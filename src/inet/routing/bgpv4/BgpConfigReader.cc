//
// Copyright (C) 2010 Helene Lageber
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#include "inet/routing/bgpv4/BgpConfigReader.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>

#include "inet/common/ModuleAccess.h"
#include "inet/routing/bgpv4/BgpSession.h"

namespace inet {

namespace bgp {

static bool isIpv6Unicast(const BgpAddressFamily& family)
{
    return family.afi == AFI_IPV6 && family.safi == SAFI_UNICAST;
}

static char toLowerCase(char ch)
{
    return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
}

static std::string toLowerCaseString(std::string value)
{
    for (auto& ch : value)
        ch = toLowerCase(ch);
    return value;
}

static void normalizeAddressFamilyToken(std::string& token)
{
    token = toLowerCaseString(token);
    std::replace(token.begin(), token.end(), '/', '-');
    std::replace(token.begin(), token.end(), '.', '-');
}

static Ipv6Address parseIpv6Prefix(const cXMLElement& networkConfig, const char *address, int& prefixLength)
{
    Ipv6Address prefix;
    if (prefix.tryParseAddrWithPrefix(address, prefixLength))
        return prefix;

    const char *prefixLengthAttr = networkConfig.getAttribute("prefixLength");
    if (!prefixLengthAttr || !*prefixLengthAttr)
        throw cRuntimeError("BGP Error: IPv6 Network '%s' must include '/prefixLength' or a 'prefixLength' attribute at %s",
                address, networkConfig.getSourceLocation());

    prefixLength = atoi(prefixLengthAttr);
    if (prefixLength < 0 || prefixLength > 128)
        throw cRuntimeError("BGP Error: invalid IPv6 prefix length %d at %s", prefixLength, networkConfig.getSourceLocation());

    prefix.set(address);
    return prefix;
}

static Ipv6Address parseIpv6NextHop(const cXMLElement& networkConfig)
{
    const char *nextHop = networkConfig.getAttribute("nextHop");
    if (nextHop && *nextHop)
        return Ipv6Address(nextHop);
    return Ipv6Address::UNSPECIFIED_ADDRESS;
}

BgpConfigReader::BgpConfigReader(cModule *bgpModule, IInterfaceTable *ift) :
    bgpModule(bgpModule), ift(ift)
{
}

void BgpConfigReader::loadConfigFromXML(cXMLElement *bgpConfig, BgpRouter *bgpRouter)
{
    this->bgpRouter = bgpRouter;

    if (strcmp(bgpConfig->getTagName(), "BGPConfig"))
        throw cRuntimeError("Cannot read BGP configuration, unaccepted '%s' node at %s", bgpConfig->getTagName(), bgpConfig->getSourceLocation());

    // load bgp timer parameters informations
    cXMLElement *paramNode = bgpConfig->getElementByPath("TimerParams");
    if (paramNode == nullptr)
        throw cRuntimeError("BGP Error: No configuration for BGP timer parameters");
    cXMLElementList timerConfig = paramNode->getChildren();
    simtime_t delayTab[NB_TIMERS];
    loadTimerConfig(timerConfig, delayTab);

    // find my AS
    cXMLElementList ASList = bgpConfig->getElementsByTagName("AS");
    int routerPosition;
    AsId myAsId = findMyAS(ASList, routerPosition);
    if (myAsId == 0)
        throw cRuntimeError("BGP Error:  No AS configuration for Router ID: %s", bgpRouter->getRouterId().str().c_str());

    bgpRouter->setAsId(myAsId);

    // load AS information
    char ASXPath[32];
    snprintf(ASXPath, sizeof(ASXPath), "AS[@id='%d']", myAsId);
    cXMLElement *ASNode = bgpConfig->getElementByPath(ASXPath);
    if (ASNode == nullptr)
        throw cRuntimeError("BGP Error:  No configuration for AS ID: %d", myAsId);
    cXMLElementList ASConfig = ASNode->getChildren();

    // load EGP Session informations
    cXMLElementList sessionList = bgpConfig->getElementsByTagName("Session");
    simtime_t saveStartDelay = delayTab[3];
    loadEbgpSessionConfig(ASConfig, sessionList, delayTab);
    delayTab[3] = saveStartDelay;

    // get all BGP speakers in my AS
    auto routerInSameASList = findInternalPeers(ASConfig);

    // create an IGP Session with each BGP speaker in my AS
    if (routerInSameASList.size()) {
        unsigned int routerPeerPosition = 1;
        delayTab[3] += sessionList.size() * 2;
        for (auto it = routerInSameASList.begin(); it != routerInSameASList.end(); it++, routerPeerPosition++) {
            SessionId newSessionID = bgpRouter->createIbgpSession(*it /*peer address*/);
            delayTab[3] += calculateStartDelay(routerInSameASList.size(), routerPosition, routerPeerPosition);
            bgpRouter->setTimer(newSessionID, delayTab);
            bgpRouter->setSocketListen(newSessionID);
        }
    }

    // should be called after all (E-BGP/I-BGP) sessions are created
    loadASConfig(ASConfig);
}

void BgpConfigReader::loadTimerConfig(cXMLElementList& timerConfig, simtime_t *delayTab)
{
    for (auto& elem : timerConfig) {
        std::string nodeName = (elem)->getTagName();
        if (nodeName == "connectRetryTime") {
            delayTab[0] = (double)atoi((elem)->getNodeValue());
        }
        else if (nodeName == "holdTime") {
            delayTab[1] = (double)atoi((elem)->getNodeValue());
        }
        else if (nodeName == "keepAliveTime") {
            delayTab[2] = (double)atoi((elem)->getNodeValue());
        }
        else if (nodeName == "startDelay") {
            delayTab[3] = (double)atoi((elem)->getNodeValue());
        }
    }
}

AsId BgpConfigReader::findMyAS(cXMLElementList& asList, int& outRouterPosition)
{
    // find my own Ipv4 address in the configuration file and return the AS id under which it is configured
    // and also the 1 based position of the entry inside the AS config element
    for (auto& elem : asList) {
        cXMLElementList routerList = (elem)->getChildrenByTagName("Router");
        outRouterPosition = 1;
        for (auto& routerList_routerListIt : routerList) {
            Ipv4Address routerAddr = Ipv4Address((routerList_routerListIt)->getAttribute("interAddr"));
            for (int i = 0; i < ift->getNumInterfaces(); i++) {
                if (ift->getInterface(i)->getProtocolData<Ipv4InterfaceData>()->getIPAddress() == routerAddr)
                    return atoi((routerList_routerListIt)->getParentNode()->getAttribute("id"));
            }
            outRouterPosition++;
        }
    }

    return 0;
}

void BgpConfigReader::loadEbgpSessionConfig(cXMLElementList& ASConfig, cXMLElementList& sessionList, simtime_t *delayTab)
{
    simtime_t saveStartDelay = delayTab[3];
    for (auto sessionListIt = sessionList.begin(); sessionListIt != sessionList.end(); sessionListIt++, delayTab[3] = saveStartDelay) {
        auto numRouters = (*sessionListIt)->getChildren();
        if (numRouters.size() != 2)
            throw cRuntimeError("BGP Error: Number of routers is invalid for session ID : %s", (*sessionListIt)->getAttribute("id"));

        Ipv4Address routerAddr1 = Ipv4Address((*sessionListIt)->getFirstChild()->getAttribute("exterAddr"));
        Ipv4Address routerAddr2 = Ipv4Address((*sessionListIt)->getLastChild()->getAttribute("exterAddr"));
        if (isInInterfaceTable(ift, routerAddr1) == -1 && isInInterfaceTable(ift, routerAddr2) == -1)
            continue;

        Ipv4Address peerAddr;
        Ipv4Address myAddr;
        if (isInInterfaceTable(ift, routerAddr1) != -1) {
            peerAddr = routerAddr2;
            myAddr = routerAddr1;
            delayTab[3] += atoi((*sessionListIt)->getAttribute("id"));
        }
        else {
            peerAddr = routerAddr1;
            myAddr = routerAddr2;
            delayTab[3] += atoi((*sessionListIt)->getAttribute("id")) + bgpModule->par("ExternalPeerStartDelayOffset").doubleValue();
        }

        if (peerAddr.isUnspecified())
            throw cRuntimeError("BGP Error: No valid external address for session ID : %s", (*sessionListIt)->getAttribute("id"));

        SessionInfo externalInfo;

        externalInfo.myAddr = myAddr;
        externalInfo.checkConnection = bgpModule->par("connectedCheck").boolValue();
        externalInfo.ebgpMultihop = bgpModule->par("ebgpMultihop").intValue();
        if (externalInfo.ebgpMultihop < 1)
            throw cRuntimeError("BGP Error: ebgpMultihop parameter must be >= 1");
        else if (externalInfo.ebgpMultihop > 1) // if E-BGP multi-hop is enabled, then turn off checkConnection
            externalInfo.checkConnection = false;

        for (auto& elem : ASConfig) {
            if (std::string(elem->getTagName()) == "Router") {
                if (isInInterfaceTable(ift, Ipv4Address(elem->getAttribute("interAddr"))) != -1) {
                    for (auto& entry : elem->getChildren()) {
                        if (std::string(entry->getTagName()) == "Neighbor") {
                            const char *peer = entry->getAttribute("address");
                            if (peer && *peer && peerAddr.equals(Ipv4Address(peer))) {
                                externalInfo.checkConnection = getBoolAttrOrPar(*entry, "connectedCheck");
                                externalInfo.ebgpMultihop = getIntAttrOrPar(*entry, "ebgpMultihop");
                                if (externalInfo.ebgpMultihop > 1) // if E-BGP multi-hop is enabled, then turn off checkConnection
                                    externalInfo.checkConnection = false;
                            }
                        }
                    }
                }
            }
        }

        SessionId newSessionID = bgpRouter->createEbgpSession(peerAddr.str().c_str(), externalInfo);
        bgpRouter->setTimer(newSessionID, delayTab);
        bgpRouter->setSocketListen(newSessionID);
    }
}

std::vector<const char *> BgpConfigReader::findInternalPeers(cXMLElementList& ASConfig)
{
    std::vector<const char *> routerInSameASList;
    for (auto& elem : ASConfig) {
        std::string nodeName = elem->getTagName();
        if (nodeName == "Router") {
            Ipv4Address internalAddr = Ipv4Address(elem->getAttribute("interAddr"));
            if (isInInterfaceTable(ift, internalAddr) == -1)
                routerInSameASList.push_back(elem->getAttribute("interAddr"));
            else
                bgpRouter->setInternalAddress(internalAddr);
        }
    }
    return routerInSameASList;
}

void BgpConfigReader::loadASConfig(cXMLElementList& ASConfig)
{
    // set the default values
    bgpRouter->setDefaultConfig();

    for (auto& elem : ASConfig) {
        std::string nodeName = elem->getTagName();
        if (nodeName == "Router") {
            Ipv4Address internalAddr = Ipv4Address(elem->getAttribute("interAddr"));
            if (isInInterfaceTable(ift, internalAddr) != -1) {
                bgpRouter->setRedistributeInternal(getBoolAttrOrPar(*elem, "redistributeInternal"));
                bgpRouter->setRedistributeOspf(getStrAttrOrPar(*elem, "redistributeOspf"));
                bgpRouter->setRedistributeRip(getBoolAttrOrPar(*elem, "redistributeRip"));
                for (auto family : getAddressFamilyAttr(*elem)) {
                    if (!isIpv6Unicast(family))
                        throw cRuntimeError("BGP Error: only ipv6-unicast is supported as MP-BGP router address family at %s", elem->getSourceLocation());
                    bgpRouter->addAddressFamily(family);
                }

                for (auto& entry : elem->getChildren()) {
                    std::string nodeName = entry->getTagName();
                    if (nodeName == "Network") {
                        const char *address = entry->getAttribute("address");
                        if (!address || !*address)
                            throw cRuntimeError("BGP Error: attribute 'address' is mandatory in 'Network'");

                        auto families = getAddressFamilyAttr(*entry);
                        if (families.empty())
                            bgpRouter->addToAdvertiseList(Ipv4Address(address));
                        else {
                            for (auto family : families) {
                                if (family.afi == AFI_IPV4 && family.safi == SAFI_UNICAST)
                                    bgpRouter->addToAdvertiseList(Ipv4Address(address));
                                else if (isIpv6Unicast(family)) {
                                    int prefixLength = -1;
                                    Ipv6Address prefix = parseIpv6Prefix(*entry, address, prefixLength);
                                    Ipv6Address nextHop = parseIpv6NextHop(*entry);
                                    bgpRouter->addAddressFamily(family);
                                    bgpRouter->addToAdvertiseIpv6List(prefix, prefixLength, nextHop);
                                }
                                else
                                    throw cRuntimeError("BGP Error: unsupported Network address family at %s", entry->getSourceLocation());
                            }
                        }
                    }
                    else if (nodeName == "Neighbor") {
                        const char *peer = entry->getAttribute("address");
                        if (peer && *peer) {
                            bool nextHopSelf = getBoolAttrOrPar(*entry, "nextHopSelf");
                            bgpRouter->setNextHopSelf(Ipv4Address(peer), nextHopSelf);

                            int localPreference = getIntAttrOrPar(*entry, "localPreference");
                            bgpRouter->setLocalPreference(Ipv4Address(peer), localPreference);

                            auto families = getAddressFamilyAttr(*entry);
                            for (auto family : families) {
                                if (!isIpv6Unicast(family))
                                    throw cRuntimeError("BGP Error: only ipv6-unicast is supported as MP-BGP neighbor address family at %s", entry->getSourceLocation());
                            }
                            if (!families.empty())
                                bgpRouter->setPeerAddressFamilies(Ipv4Address(peer), families);
                        }
                        else
                            throw cRuntimeError("BGP Error: attribute 'address' is mandatory in 'Neighbor'");
                    }
                    else
                        throw cRuntimeError("BGP Error: attribute '%s' is invalid in 'Router'", nodeName.c_str());
                }
            }
        }
        else if (nodeName == "DenyRoute" || nodeName == "DenyRouteIN" || nodeName == "DenyRouteOUT") {
            BgpRoutingTableEntry *entry = new BgpRoutingTableEntry(); // FIXME Who will delete this entry?
            entry->setDestination(Ipv4Address((elem)->getAttribute("Address")));
            entry->setNetmask(Ipv4Address((elem)->getAttribute("Netmask")));
            bgpRouter->addToPrefixList(nodeName, entry);
        }
        else if (nodeName == "DenyAS" || nodeName == "DenyASIN" || nodeName == "DenyASOUT") {
            AsId ASCur = atoi((elem)->getNodeValue());
            bgpRouter->addToAsList(nodeName, ASCur);
        }
        else
            throw cRuntimeError("BGP Error: unknown element named '%s' for AS %u", nodeName.c_str(), bgpRouter->getAsId());
    }

    bgpRouter->applyAddressFamilyDefaults();
}

int BgpConfigReader::isInInterfaceTable(IInterfaceTable *ifTable, Ipv4Address addr)
{
    for (int i = 0; i < ifTable->getNumInterfaces(); i++) {
        if (ifTable->getInterface(i)->getProtocolData<Ipv4InterfaceData>()->getIPAddress() == addr) {
            return i;
        }
    }
    return -1;
}

int BgpConfigReader::isInInterfaceTable(IInterfaceTable *ifTable, std::string ifName)
{
    for (int i = 0; i < ifTable->getNumInterfaces(); i++) {
        if (std::string(ifTable->getInterface(i)->getInterfaceName()) == ifName) {
            return i;
        }
    }
    return -1;
}

unsigned int BgpConfigReader::calculateStartDelay(int rtListSize, unsigned char rtPosition, unsigned char rtPeerPosition)
{
    unsigned int startDelay = 0;
    if (rtPeerPosition == 1) {
        if (rtPosition == 1) {
            startDelay = 1;
        }
        else {
            startDelay = (rtPosition - 1) * 2;
        }
        return startDelay;
    }

    if (rtPosition < rtPeerPosition) {
        startDelay = 2;
    }
    else if (rtPosition > rtPeerPosition) {
        startDelay = (rtListSize - 1) * 2 - 2 * (rtPeerPosition - 2);
    }
    else {
        startDelay = (rtListSize - 1) * 2 + 1;
    }
    return startDelay;
}

std::vector<BgpAddressFamily> BgpConfigReader::getAddressFamilyAttr(const cXMLElement& ifConfig) const
{
    std::vector<BgpAddressFamily> families;
    const char *addressFamilies = ifConfig.getAttribute("addressFamilies");
    if (addressFamilies && *addressFamilies) {
        for (auto token : cStringTokenizer(addressFamilies, " ,;").asVector())
            families.push_back(parseAddressFamilyToken(token, ifConfig));
    }

    const char *afi = ifConfig.getAttribute("afi");
    const char *safi = ifConfig.getAttribute("safi");
    if ((afi && *afi) || (safi && *safi))
        families.push_back(parseAddressFamily(afi, safi, ifConfig));

    return families;
}

BgpAddressFamily BgpConfigReader::parseAddressFamily(const char *afi, const char *safi, const cXMLElement& ifConfig) const
{
    if (!afi || !*afi)
        throw cRuntimeError("BGP Error: attribute 'afi' is mandatory when 'safi' is present at %s", ifConfig.getSourceLocation());

    BgpAddressFamily family;
    family.afi = parseAfi(afi, ifConfig);
    family.safi = SAFI_UNICAST;
    if (safi && *safi)
        family.safi = parseSafi(safi, ifConfig);
    return family;
}

BgpAddressFamily BgpConfigReader::parseAddressFamilyToken(std::string token, const cXMLElement& ifConfig) const
{
    normalizeAddressFamilyToken(token);

    BgpAddressFamily family;
    auto separator = token.find('-');
    if (separator == std::string::npos) {
        family.afi = parseAfi(token, ifConfig);
        family.safi = SAFI_UNICAST;
    }
    else {
        family.afi = parseAfi(token.substr(0, separator), ifConfig);
        family.safi = parseSafi(token.substr(separator + 1), ifConfig);
    }
    return family;
}

uint16_t BgpConfigReader::parseAfi(std::string afi, const cXMLElement& ifConfig) const
{
    afi = toLowerCaseString(afi);
    if (afi == "ipv4" || afi == "ip")
        return AFI_IPV4;
    if (afi == "ipv6")
        return AFI_IPV6;
    char *end = nullptr;
    long value = strtol(afi.c_str(), &end, 10);
    if (*end == '\0' && value >= 0 && value <= UINT16_MAX)
        return static_cast<uint16_t>(value);
    throw cRuntimeError("BGP Error: unknown AFI '%s' at %s", afi.c_str(), ifConfig.getSourceLocation());
}

uint8_t BgpConfigReader::parseSafi(std::string safi, const cXMLElement& ifConfig) const
{
    safi = toLowerCaseString(safi);
    if (safi == "unicast")
        return SAFI_UNICAST;
    if (safi == "multicast")
        return SAFI_MULTICAST;
    char *end = nullptr;
    long value = strtol(safi.c_str(), &end, 10);
    if (*end == '\0' && value >= 0 && value <= UINT8_MAX)
        return static_cast<uint8_t>(value);
    throw cRuntimeError("BGP Error: unknown SAFI '%s' at %s", safi.c_str(), ifConfig.getSourceLocation());
}

bool BgpConfigReader::getBoolAttrOrPar(const cXMLElement& ifConfig, const char *name) const
{
    const char *attrStr = ifConfig.getAttribute(name);
    if (attrStr && *attrStr) {
        if (strcmp(attrStr, "true") == 0 || strcmp(attrStr, "1") == 0)
            return true;
        if (strcmp(attrStr, "false") == 0 || strcmp(attrStr, "0") == 0)
            return false;
        throw cRuntimeError("Invalid boolean attribute %s = '%s' at %s", name, attrStr, ifConfig.getSourceLocation());
    }
    return bgpModule->par(name);
}

int BgpConfigReader::getIntAttrOrPar(const cXMLElement& ifConfig, const char *name) const
{
    const char *attrStr = ifConfig.getAttribute(name);
    if (attrStr && *attrStr)
        return atoi(attrStr);
    return bgpModule->par(name);
}

const char *BgpConfigReader::getStrAttrOrPar(const cXMLElement& ifConfig, const char *name) const
{
    const char *attrStr = ifConfig.getAttribute(name);
    if (attrStr && *attrStr)
        return attrStr;
    return bgpModule->par(name);
}

} // namespace bgp

} // namespace inet
