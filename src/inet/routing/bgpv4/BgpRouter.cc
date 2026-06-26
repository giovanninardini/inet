//
// Copyright (C) 2010 Helene Lageber
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#include "inet/routing/bgpv4/BgpRouter.h"

#include <algorithm>
#include <set>

#include "inet/common/ModuleAccess.h"
#include "inet/networklayer/ipv6/Ipv6InterfaceData.h"
#include "inet/routing/bgpv4/BgpSession.h"

namespace inet {
namespace bgp {

// Simulation-local registry used only for lifecycle cleanup. When a BGP module
// crashes, INET may tear down TCP and interfaces before the remote BGP peers get
// a socket failure indication, so peers are notified directly to apply the same
// implicit route withdrawal that a failed BGP session would cause.
static std::vector<BgpRouter *> bgpRouters;

static bool containsAddressFamily(const std::vector<BgpAddressFamily>& families, const BgpAddressFamily& family)
{
    return std::find(families.begin(), families.end(), family) != families.end();
}

static void appendAddressFamily(std::vector<BgpAddressFamily>& families, const BgpAddressFamily& family)
{
    if (!containsAddressFamily(families, family))
        families.push_back(family);
}

static BgpAddressFamily makeAddressFamily(uint16_t afi, uint8_t safi)
{
    BgpAddressFamily family;
    family.afi = afi;
    family.safi = safi;
    return family;
}

static std::string addressFamilyToString(const BgpAddressFamily& family)
{
    std::string afi;
    if (family.afi == AFI_IPV4)
        afi = "ipv4";
    else if (family.afi == AFI_IPV6)
        afi = "ipv6";
    else
        afi = std::to_string(family.afi);

    std::string safi;
    if (family.safi == SAFI_UNICAST)
        safi = "unicast";
    else if (family.safi == SAFI_MULTICAST)
        safi = "multicast";
    else
        safi = std::to_string(family.safi);

    return afi + "-" + safi;
}

static Ipv6Address getGlobalIpv6Address(NetworkInterface *interfaceEntry)
{
    const auto *ipv6Data = interfaceEntry->getProtocolData<Ipv6InterfaceData>();
    Ipv6Address address = ipv6Data->getGlblAddress();
    if (address.isUnspecified())
        throw cRuntimeError("BGP cannot select an IPv6 next hop on interface %s", interfaceEntry->getInterfaceFullPath().c_str());
    return address;
}

static Ipv6Address findGlobalIpv6Address(NetworkInterface *interfaceEntry)
{
    const auto *ipv6Data = interfaceEntry->getProtocolData<Ipv6InterfaceData>();
    return ipv6Data->getGlblAddress();
}

static std::vector<BgpAddressFamily> getMultiprotocolCapabilities(const BgpOpenMessage& msg)
{
    std::vector<BgpAddressFamily> families;
    for (size_t i = 0; i < msg.getOptionalParameterArraySize(); i++) {
        auto parameter = msg.getOptionalParameter(i);
        if (parameter->getParameterType() != BGP_OPTIONAL_PARAMETER_CAPABILITIES)
            continue;

        auto capabilities = dynamic_cast<const BgpOptionalParameterCapabilities *>(parameter);
        if (capabilities == nullptr)
            continue;

        for (size_t j = 0; j < capabilities->getCapabilityArraySize(); j++) {
            auto capability = capabilities->getCapability(j);
            if (capability->getCapabilityCode() != BGP_CAPABILITY_MULTIPROTOCOL)
                continue;

            auto multiprotocol = dynamic_cast<const BgpCapabilityMultiprotocol *>(capability);
            if (multiprotocol == nullptr)
                continue;

            auto family = makeAddressFamily(multiprotocol->getAfi(), multiprotocol->getSafi());
            appendAddressFamily(families, family);
        }
    }
    return families;
}

static bool ipv4PrefixesEqual(const Ipv4Address& prefix1, const Ipv4Address& netmask1, const Ipv4Address& prefix2, const Ipv4Address& netmask2)
{
    return netmask1 == netmask2 && Ipv4Address::maskedAddrAreEqual(prefix1, prefix2, netmask1);
}

static BgpRoutingTableEntry *cloneRoute(const BgpRoutingTableEntry *route)
{
    auto copy = new BgpRoutingTableEntry();
    copy->setDestination(route->getDestination());
    copy->setNetmask(route->getNetmask());
    copy->setGateway(route->getGateway());
    copy->setInterface(route->getInterface());
    copy->setMetric(route->getMetric());
    copy->setAdminDist(route->getAdminDist());
    copy->setPathType(route->getPathType());
    copy->setLocalPreference(route->getLocalPreference());
    copy->setIBgpLearned(route->isIBgpLearned());
    copy->setLearnedSessionId(route->getLearnedSessionId());
    for (unsigned int i = 0; i < route->getASCount(); i++)
        copy->addAS(route->getAS(i));
    return copy;
}

static BgpIpv6RoutingTableEntry *cloneRoute(const BgpIpv6RoutingTableEntry *route)
{
    auto copy = new BgpIpv6RoutingTableEntry(route->getDestination(), route->getPrefixLength());
    copy->setNextHop(route->getNextHop());
    copy->setInterface(route->getInterface());
    copy->setMetric(route->getMetric());
    copy->setAdminDist(route->getAdminDist());
    copy->setPathType(route->getPathType());
    copy->setLocalPreference(route->getLocalPreference());
    copy->setIBgpLearned(route->isIBgpLearned());
    copy->setLearnedSessionId(route->getLearnedSessionId());
    for (unsigned int i = 0; i < route->getASCount(); i++)
        copy->addAS(route->getAS(i));
    return copy;
}

template<typename Route>
static bool routeIsBetter(const Route *candidate, const Route *current)
{
    if (candidate->getLocalPreference() > current->getLocalPreference())
        return true;

    if (candidate->getLocalPreference() < current->getLocalPreference())
        return false;

    if (candidate->getASCount() < current->getASCount())
        return true;

    if (candidate->getASCount() > current->getASCount())
        return false;

    return candidate->getPathType() < current->getPathType();
}

static bool sameAsPath(const BgpRoutingTableEntry *route1, const BgpRoutingTableEntry *route2)
{
    if (route1->getASCount() != route2->getASCount())
        return false;

    for (unsigned int i = 0; i < route1->getASCount(); i++) {
        if (route1->getAS(i) != route2->getAS(i))
            return false;
    }
    return true;
}

static bool sameAsPath(const BgpIpv6RoutingTableEntry *route1, const BgpIpv6RoutingTableEntry *route2)
{
    if (route1->getASCount() != route2->getASCount())
        return false;

    for (unsigned int i = 0; i < route1->getASCount(); i++) {
        if (route1->getAS(i) != route2->getAS(i))
            return false;
    }
    return true;
}

static bool sameRouteAttributes(const BgpRoutingTableEntry *route1, const BgpRoutingTableEntry *route2)
{
    return route1->getLearnedSessionId() == route2->getLearnedSessionId() &&
           route1->getGateway() == route2->getGateway() &&
           route1->getPathType() == route2->getPathType() &&
           route1->getLocalPreference() == route2->getLocalPreference() &&
           route1->isIBgpLearned() == route2->isIBgpLearned() &&
           sameAsPath(route1, route2);
}

static bool sameRouteAttributes(const BgpIpv6RoutingTableEntry *route1, const BgpIpv6RoutingTableEntry *route2)
{
    return route1->getLearnedSessionId() == route2->getLearnedSessionId() &&
           route1->getNextHop() == route2->getNextHop() &&
           route1->getPathType() == route2->getPathType() &&
           route1->getLocalPreference() == route2->getLocalPreference() &&
           route1->isIBgpLearned() == route2->isIBgpLearned() &&
           sameAsPath(route1, route2);
}

BgpRouter::BgpRouter(cSimpleModule *bgpModule, IInterfaceTable *ift, IIpv4RoutingTable *rt, Ipv6RoutingTable *rt6)
{
    this->bgpModule = bgpModule;
    this->ift = ift;
    this->rt = rt;
    this->rt6 = rt6;

    ospfModule = findModuleFromPar<ospfv2::Ospfv2>(bgpModule->par("ospfRoutingModule"), bgpModule);
    bgpRouters.push_back(this);
}

BgpRouter::~BgpRouter(void)
{
    auto routerIt = std::find(bgpRouters.begin(), bgpRouters.end(), this);
    if (routerIt != bgpRouters.end())
        bgpRouters.erase(routerIt);

    if (!aborting)
        removeInstalledIpv6Routes();

    for (auto& elem : ipv6WithdrawRoutes)
        bgpModule->cancelAndDelete(elem.first);
    ipv6WithdrawRoutes.clear();

    for (auto& elem : _BGPSessions)
        delete (elem).second;

    // During crash teardown, other protocol modules may already be unwinding
    // route state; graceful shutdown and normal destruction still delete these.
    if (!aborting) {
        std::set<BgpIpv6RoutingTableEntry *> deletedIpv6Routes;
        for (auto route : bgpIpv6RoutingTable) {
            if (deletedIpv6Routes.insert(route).second)
                delete route;
        }
    }

    for (auto route : adjRibIn)
        delete route;

    for (auto route : adjRibInIpv6)
        delete route;

    for (auto& elem : _prefixListINOUT)
        delete elem;

    for (auto& elem : _prefixIpv6ListINOUT)
        delete elem;
}

void BgpRouter::printSessionSummary()
{
    EV_DEBUG << "summary of BGP sessions: \n";
    for (auto& entry : _BGPSessions) {
        BgpSession *session = entry.second;
        BgpSessionType type = session->getType();
        if (type == IGP) {
            EV_DEBUG << "  IGP session to internal peer '" << session->getPeerAddr().str(false)
                     << "' starts at " << session->getStartEventTime() << "s \n";
        }
        else if (type == EGP) {
            EV_DEBUG << "  EGP session to external peer '" << session->getPeerAddr().str(false)
                     << "' starts at " << session->getStartEventTime() << "s \n";
        }
        else {
            EV_DEBUG << "  Unknown session to peer '" << session->getPeerAddr().str(false)
                     << "' starts at " << session->getStartEventTime() << "s \n";
        }
    }
}

void BgpRouter::addWatches()
{
    WATCH(myAsId);
    WATCH(_BGPSessions);
    WATCH(bgpRoutingTable);
    WATCH(bgpIpv6RoutingTable);
    WATCH(adjRibIn);
    WATCH(adjRibInIpv6);
    _socketMap.addWatch();
}

void BgpRouter::recordStatistics()
{
    unsigned int statTab[BgpSession::NB_STATS] = {
        0, 0, 0, 0, 0, 0
    };

    for (auto& elem : _BGPSessions)
        (elem).second->getStatistics(statTab);

    bgpModule->recordScalar("OPENMsgSent", statTab[0]);
    bgpModule->recordScalar("OPENMsgRecv", statTab[1]);
    bgpModule->recordScalar("KeepAliveMsgSent", statTab[2]);
    bgpModule->recordScalar("KeepAliveMsgRcv", statTab[3]);
    bgpModule->recordScalar("UpdateMsgSent", statTab[4]);
    bgpModule->recordScalar("UpdateMsgRcv", statTab[5]);
}

// A node is "lifecycle-capable" if it contains a NodeStatus ("status") submodule,
// i.e. it can be shut down, restarted or crashed at runtime. Only on such nodes does
// the FSM re-arm a connection after a loss (see BgpFsm.cc): a restarted node must
// reconnect, whereas a plain BGP router keeps its historical behavior of not
// auto-reconnecting. Enabling auto-reconnect unconditionally would also re-open a
// listening socket on an already-bound port, crashing non-lifecycle scenarios.
bool BgpRouter::isLifecycleNode() const
{
    return !shuttingDown && getContainingNode(bgpModule)->getSubmodule("status") != nullptr;
}

void BgpRouter::closeSessions(bool abort)
{
    shuttingDown = true;
    aborting = abort;

    for (auto& elem : _BGPSessions) {
        TcpSocket *socket = elem.second->getSocket();
        if (socket) {
            _socketMap.removeSocket(socket);
            if (abort)
                socket->abort();
            else
                socket->close();
        }
        TcpSocket *socketListen = elem.second->getSocketListen();
        if (socketListen) {
            _socketMap.removeSocket(socketListen);
            if (abort)
                socketListen->abort();
            else
                socketListen->close();
        }
    }
}

void BgpRouter::notifyPeersOfLocalSessionFailure()
{
    if (!containsAddressFamily(addressFamilies, makeAddressFamily(AFI_IPV6, SAFI_UNICAST)))
        return;

    std::set<Ipv4Address> localAddresses;
    for (auto address : localBgpAddresses)
        localAddresses.insert(address);

    EV_INFO << "Notifying BGP peers about local session failure for "
            << localAddresses.size() << " local IPv4 addresses\n";

    // Lifecycle stop/crash may tear down TCP before the remote BGP module gets
    // a socket failure indication. Notify peers in the same simulation so they
    // perform the normal implicit-withdrawal cleanup for this session.
    for (auto router : bgpRouters) {
        if (router == this)
            continue;

        for (const auto& session : router->_BGPSessions) {
            if (localAddresses.find(session.second->getPeerAddr()) != localAddresses.end()) {
                EV_INFO << "Notifying peer router to remove BGP routes learned from session "
                        << session.first << " to " << session.second->getPeerAddr().str(false) << "\n";
                router->removeRoutesLearnedFromSession(session.first);
            }
        }
    }
}

void BgpRouter::removeBgpRoutes(bool abort)
{
    shuttingDown = true;
    aborting = abort;

    std::set<BgpRoutingTableEntry *> installedIpv4Routes;
    for (int i = rt->getNumRoutes() - 1; i >= 0; i--) {
        Ipv4Route *route = rt->getRoute(i);
        if (route->getSourceType() == IRoute::BGP) {
            EV_INFO << "Removing BGP route " << route->str() << endl;
            if (auto bgpRoute = dynamic_cast<BgpRoutingTableEntry *>(route)) {
                if (!aborting)
                    sendWithdrawNlri(bgpRoute, bgpRoute->getLearnedSessionId(), bgpRoute->getLearnedSessionId() != 0);
                installedIpv4Routes.insert(bgpRoute);
            }
            rt->deleteRoute(route);
        }
    }

    // During crash teardown, other protocol modules may already be unwinding
    // route state. Installed routes are removed above; uninstalled Loc-RIB
    // entries are deleted only for graceful shutdown and normal destruction.
    if (!aborting) {
        std::set<BgpRoutingTableEntry *> deletedIpv4Routes;
        for (auto route : bgpRoutingTable) {
            if (installedIpv4Routes.find(route) == installedIpv4Routes.end() &&
                deletedIpv4Routes.insert(route).second)
            {
                delete route;
            }
        }
    }
    bgpRoutingTable.clear();

    for (auto route : adjRibIn)
        delete route;
    adjRibIn.clear();

    for (auto& elem : ipv6WithdrawRoutes)
        bgpModule->cancelAndDelete(elem.first);
    ipv6WithdrawRoutes.clear();

    if (!aborting) {
        for (auto route : bgpIpv6RoutingTable)
            sendMpUnreachNlri(route, route->getLearnedSessionId(), route->getLearnedSessionId() != 0);
    }

    if (!aborting)
        removeInstalledIpv6Routes();

    // During crash teardown, other protocol modules may already be unwinding
    // route state; graceful shutdown and normal destruction still delete these.
    if (!aborting) {
        std::set<BgpIpv6RoutingTableEntry *> deletedIpv6Routes;
        for (auto route : bgpIpv6RoutingTable) {
            if (deletedIpv6Routes.insert(route).second)
                delete route;
        }
    }
    bgpIpv6RoutingTable.clear();

    for (auto route : adjRibInIpv6)
        delete route;
    adjRibInIpv6.clear();
}

SessionId BgpRouter::createIbgpSession(const char *peerAddr)
{
    SessionInfo info;
    info.sessionType = IGP;
    info.ASValue = myAsId;
    info.routerID = rt->getRouterId();
    info.peerAddr.set(peerAddr);
    info.sessionID = info.peerAddr.getInt() + info.routerID.getInt();

    numIgpSessions++;
    if (std::find(localBgpAddresses.begin(), localBgpAddresses.end(), internalAddress) == localBgpAddresses.end())
        localBgpAddresses.push_back(internalAddress);

    SessionId newSessionId;
    newSessionId = info.sessionID;

    BgpSession *newSession = new BgpSession(*this);
    newSession->setInfo(info);

    _BGPSessions[newSessionId] = newSession;

    return newSessionId;
}

SessionId BgpRouter::createEbgpSession(const char *peerAddr, SessionInfo& externalInfo)
{
    SessionInfo info;

    // set external info
    info.myAddr = externalInfo.myAddr;
    info.checkConnection = externalInfo.checkConnection;
    info.ebgpMultihop = externalInfo.ebgpMultihop;

    info.sessionType = EGP;
    info.ASValue = myAsId;
    info.routerID = rt->getRouterId();
    info.peerAddr.set(peerAddr);
    info.linkIntf = rt->getInterfaceForDestAddr(info.peerAddr);
    if (!info.linkIntf) {
        if (info.checkConnection)
            throw cRuntimeError("BGP Error: External BGP neighbor at address %s is not directly connected to BGP router %s", peerAddr, bgpModule->getOwner()->getFullName());
        else
            info.linkIntf = rt->getInterfaceForDestAddr(info.myAddr);
    }
    ASSERT(info.linkIntf);
    info.sessionID = info.peerAddr.getInt() + info.linkIntf->getProtocolData<Ipv4InterfaceData>()->getIPAddress().getInt();
    numEgpSessions++;
    if (std::find(localBgpAddresses.begin(), localBgpAddresses.end(), info.myAddr) == localBgpAddresses.end())
        localBgpAddresses.push_back(info.myAddr);

    SessionId newSessionId;
    newSessionId = info.sessionID;

    BgpSession *newSession = new BgpSession(*this);
    newSession->setInfo(info);

    _BGPSessions[newSessionId] = newSession;

    return newSessionId;
}

void BgpRouter::setTimer(SessionId id, simtime_t *delayTab)
{
    _BGPSessions[id]->setTimers(delayTab);
}

void BgpRouter::setSocketListen(SessionId id)
{
    TcpSocket *socketListen = new TcpSocket();
    _BGPSessions[id]->setSocketListen(socketListen);
}

void BgpRouter::setDefaultConfig()
{
    // per router params
    bool redistributeInternal = bgpModule->par("redistributeInternal").boolValue();
    std::string redistributeOspf = bgpModule->par("redistributeOspf").stdstringValue();
    bool redistributeRip = bgpModule->par("redistributeRip").boolValue();
    setRedistributeInternal(redistributeInternal);
    setRedistributeOspf(redistributeOspf);
    setRedistributeRip(redistributeRip);

    // per session params
    bool nextHopSelf = bgpModule->par("nextHopSelf").boolValue();
    int localPreference = bgpModule->par("localPreference").intValue();
    for (auto& session : _BGPSessions) {
        session.second->setNextHopSelf(nextHopSelf);
        session.second->setLocalPreference(localPreference);
    }
}

void BgpRouter::addToAdvertiseList(Ipv4Address address)
{
    bool routeFound = false;
    const Ipv4Route *rtEntry = nullptr;
    for (int i = 0; i < rt->getNumRoutes(); i++) {
        rtEntry = rt->getRoute(i);
        if (rtEntry->getDestination() == address) {
            routeFound = true;
            break;
        }
    }
    if (!routeFound)
        throw cRuntimeError("Network address '%s' is not found in the routing table of %s", address.str(false).c_str(), bgpModule->getOwner()->getFullName());

    auto position = std::find_if(advertiseList.begin(), advertiseList.end(),
            [&] (const Ipv4Address m) -> bool { return m == address; });
    if (position != advertiseList.end())
        throw cRuntimeError("Network address '%s' is already added to the advertised list of %s", address.str(false).c_str(), bgpModule->getOwner()->getFullName());
    advertiseList.push_back(address);

    BgpRoutingTableEntry *BGPEntry = new BgpRoutingTableEntry(rtEntry);
    BGPEntry->addAS(myAsId);
    BGPEntry->setPathType(IGP);
    BGPEntry->setLocalPreference(bgpModule->par("localPreference").intValue());
    bgpRoutingTable.push_back(BGPEntry);
}

void BgpRouter::addToAdvertiseIpv6List(const Ipv6Address& address, int prefixLength, const Ipv6Address& nextHop, simtime_t withdrawTime)
{
    for (auto route : bgpIpv6RoutingTable) {
        if (route->getDestination() == address && route->getPrefixLength() == prefixLength)
            throw cRuntimeError("IPv6 network address '%s/%d' is already added to the advertised list of %s",
                    address.str().c_str(), prefixLength, bgpModule->getOwner()->getFullName());
    }

    auto entry = new BgpIpv6RoutingTableEntry(address, prefixLength);
    entry->setNextHop(nextHop);
    entry->addAS(myAsId);
    entry->setPathType(IGP);
    entry->setLocalPreference(bgpModule->par("localPreference").intValue());
    bgpIpv6RoutingTable.push_back(entry);
    advertiseIpv6List.push_back(address);

    if (withdrawTime >= SIMTIME_ZERO) {
        auto timer = new cMessage("MP-BGP IPv6 withdraw", MP_BGP_IPV6_WITHDRAW_KIND);
        // Local configured route withdrawal is router-scoped. The timer does
        // not pretend to belong to an arbitrary BGP session; the map below
        // carries the route that must be withdrawn when the timer fires.
        ipv6WithdrawRoutes[timer] = entry;
        bgpModule->scheduleAt(withdrawTime, timer);
    }
}

void BgpRouter::addAddressFamily(const BgpAddressFamily& family)
{
    appendAddressFamily(addressFamilies, family);
}

void BgpRouter::setPeerAddressFamilies(Ipv4Address peer, const std::vector<BgpAddressFamily>& families)
{
    bool found = false;
    for (auto& session : _BGPSessions) {
        if (session.second->getPeerAddr() == peer) {
            found = true;
            session.second->setLocalAddressFamilies(families, true);
            break;
        }
    }
    if (!found)
        throw cRuntimeError("Neighbor address '%s' cannot be found in BGP router %s", peer.str(false).c_str(), bgpModule->getOwner()->getFullName());
}

void BgpRouter::applyAddressFamilyDefaults()
{
    for (auto& session : _BGPSessions) {
        if (session.second->hasExplicitLocalAddressFamilies()) {
            for (auto family : session.second->getLocalAddressFamilies()) {
                if (!containsAddressFamily(addressFamilies, family))
                    throw cRuntimeError("BGP address family '%s' for neighbor %s is not configured locally on router %s",
                            addressFamilyToString(family).c_str(),
                            session.second->getPeerAddr().str(false).c_str(),
                            bgpModule->getOwner()->getFullName());
            }
        }
        else
            session.second->setLocalAddressFamilies(addressFamilies, false);
    }
}

void BgpRouter::addToPrefixList(std::string nodeName, BgpRoutingTableEntry *entry)
{
    if (nodeName == "DenyRouteIN") {
        _prefixListIN.push_back(entry);
        _prefixListINOUT.push_back(entry);
    }
    else if (nodeName == "DenyRouteOUT") {
        _prefixListOUT.push_back(entry);
        _prefixListINOUT.push_back(entry);
    }
    else {
        _prefixListIN.push_back(entry);
        _prefixListOUT.push_back(entry);
        _prefixListINOUT.push_back(entry);
    }
}

void BgpRouter::addToIpv6PrefixList(std::string nodeName, BgpIpv6RoutingTableEntry *entry)
{
    if (nodeName == "DenyRouteIN") {
        _prefixIpv6ListIN.push_back(entry);
        _prefixIpv6ListINOUT.push_back(entry);
    }
    else if (nodeName == "DenyRouteOUT") {
        _prefixIpv6ListOUT.push_back(entry);
        _prefixIpv6ListINOUT.push_back(entry);
    }
    else {
        _prefixIpv6ListIN.push_back(entry);
        _prefixIpv6ListOUT.push_back(entry);
        _prefixIpv6ListINOUT.push_back(entry);
    }
}

void BgpRouter::addToAsList(std::string nodeName, AsId id)
{
    if (nodeName == "DenyASIN") {
        _ASListIN.push_back(id);
    }
    else if (nodeName == "DenyASOUT") {
        _ASListOUT.push_back(id);
    }
    else {
        _ASListIN.push_back(id);
        _ASListOUT.push_back(id);
    }
}

void BgpRouter::setNextHopSelf(Ipv4Address peer, bool nextHopSelf)
{
    bool found = false;
    for (auto& session : _BGPSessions) {
        if (session.second->getPeerAddr() == peer) {
            found = true;
            session.second->setNextHopSelf(nextHopSelf);
            break;
        }
    }
    if (!found)
        throw cRuntimeError("Neighbor address '%s' cannot be found in BGP router %s", peer.str(false).c_str(), bgpModule->getOwner()->getFullName());
}

void BgpRouter::setLocalPreference(Ipv4Address peer, int localPref)
{
    bool found = false;
    for (auto& session : _BGPSessions) {
        if (session.second->getPeerAddr() == peer) {
            found = true;
            session.second->setLocalPreference(localPref);
            break;
        }
    }
    if (!found)
        throw cRuntimeError("Neighbor address '%s' cannot be found in BGP router %s", peer.str(false).c_str(), bgpModule->getOwner()->getFullName());
}

void BgpRouter::setRedistributeOspf(std::string str)
{
    if (str == "") {
        redistributeOspf = false;
        return;
    }

    redistributeOspf = true;
    std::vector<std::string> tokens = cStringTokenizer(str.c_str()).asVector();

    for (auto& Ospfv2RouteType : tokens) {
        std::transform(Ospfv2RouteType.begin(), Ospfv2RouteType.end(), Ospfv2RouteType.begin(), ::tolower);
        if (Ospfv2RouteType == "o")
            redistributeOspfType.intraArea = true;
        else if (Ospfv2RouteType == "ia")
            redistributeOspfType.interArea = true;
        else if (Ospfv2RouteType == "e1")
            redistributeOspfType.externalType1 = true;
        else if (Ospfv2RouteType == "e2")
            redistributeOspfType.externalType2 = true;
        else
            throw cRuntimeError("Unknown OSPF redistribute type '%s' in BGP router %s", Ospfv2RouteType.c_str(), bgpModule->getOwner()->getFullName());
    }
}

void BgpRouter::processMessageFromTCP(cMessage *msg)
{
    TcpSocket *socket = check_and_cast_nullable<TcpSocket *>(_socketMap.findSocketFor(msg));
    if (!socket) {
        socket = new TcpSocket(msg);
        socket->setOutputGate(bgpModule->gate("socketOut"));
        Ipv4Address peerAddr = socket->getRemoteAddress().toIpv4();
        SessionId i = findIdFromPeerAddr(_BGPSessions, peerAddr);
        if (i == static_cast<SessionId>(-1)) {
            socket->close();
            _socketMap.removeSocket(socket);
            delete socket;
            socket = nullptr;
            delete msg;
            return;
        }
        socket->setCallback(this);
        socket->setUserData((void *)(uintptr_t)i);

        _socketMap.addSocket(socket);
        _BGPSessions[i]->getSocket()->abort();
        _socketMap.removeSocket(_BGPSessions[i]->getSocket());
        _BGPSessions[i]->setSocket(socket);
    }

    socket->processMessage(msg);
}

void BgpRouter::listenConnectionFromPeer(SessionId sessionID)
{
    if (_BGPSessions[sessionID]->getSocketListen()->getState() == TcpSocket::CLOSED) {
        // session StartDelayTime error, it's anormal that listenSocket is closed.
        _socketMap.removeSocket(_BGPSessions[sessionID]->getSocketListen());
        _BGPSessions[sessionID]->getSocketListen()->abort();
        _BGPSessions[sessionID]->getSocketListen()->renewSocket();
    }

    if (_BGPSessions[sessionID]->getSocketListen()->getState() != TcpSocket::LISTENING) {
        _BGPSessions[sessionID]->getSocketListen()->setOutputGate(bgpModule->gate("socketOut"));
        if (_BGPSessions[sessionID]->getType() == EGP) {
            NetworkInterface *intf = _BGPSessions[sessionID]->getLinkIntf();
            ASSERT(intf);
            Ipv4Address localAddr = intf->getProtocolData<Ipv4InterfaceData>()->getIPAddress();
            _BGPSessions[sessionID]->getSocketListen()->bind(localAddr, TCP_PORT);
        }
        else
            _BGPSessions[sessionID]->getSocketListen()->bind(TCP_PORT);
        _BGPSessions[sessionID]->getSocketListen()->listen();
        _socketMap.addSocket(_BGPSessions[sessionID]->getSocketListen());

        EV_DEBUG << "Start listening to incoming TCP connections on "
                 << _BGPSessions[sessionID]->getSocketListen()->getLocalAddress()
                 << ":" << (int)TCP_PORT
                 << " for " << BgpSession::getTypeString(_BGPSessions[sessionID]->getType()) << " session"
                 << " to peer " << _BGPSessions[sessionID]->getPeerAddr() << std::endl;
    }
}

void BgpRouter::openTCPConnectionToPeer(SessionId sessionID)
{
    EV_DEBUG << "Opening a TCP connection to "
             << _BGPSessions[sessionID]->getPeerAddr()
             << ":" << (int)TCP_PORT << std::endl;

    TcpSocket *socket = _BGPSessions[sessionID]->getSocket();
    if (socket->getState() != TcpSocket::NOT_BOUND) {
        _socketMap.removeSocket(socket);
        socket->abort();
        socket->renewSocket();
    }
    socket->setCallback(this);
    socket->setUserData((void *)(uintptr_t)sessionID);
    socket->setOutputGate(bgpModule->gate("socketOut"));
    if (_BGPSessions[sessionID]->getType() == EGP) {
        NetworkInterface *intfEntry = _BGPSessions[sessionID]->getLinkIntf();
        if (intfEntry == nullptr)
            throw cRuntimeError("No configuration interface for external peer address: %s", _BGPSessions[sessionID]->getPeerAddr().str().c_str());
        socket->bind(intfEntry->getProtocolData<Ipv4InterfaceData>()->getIPAddress(), 0);

        int ebgpMH = _BGPSessions[sessionID]->getEbgpMultihop();
        if (ebgpMH > 1)
            socket->setTimeToLive(ebgpMH);
        else if (ebgpMH == 1)
            socket->setTimeToLive(1);
        else
            throw cRuntimeError("ebgpMultihop should be >=1");
    }
    else if (_BGPSessions[sessionID]->getType() == IGP) {
        NetworkInterface *intfEntry = _BGPSessions[sessionID]->getLinkIntf();
        if (!intfEntry)
            intfEntry = rt->getInterfaceForDestAddr(_BGPSessions[sessionID]->getPeerAddr());
        if (intfEntry == nullptr)
            throw cRuntimeError("No configuration interface for internal peer address: %s", _BGPSessions[sessionID]->getPeerAddr().str().c_str());
        _BGPSessions[sessionID]->setlinkIntf(intfEntry);
        if (internalAddress == Ipv4Address::UNSPECIFIED_ADDRESS)
            throw cRuntimeError("Internal address is not specified for router %s", bgpModule->getOwner()->getFullName());
        socket->bind(internalAddress, 0);
    }
    _socketMap.addSocket(socket);

    socket->connect(_BGPSessions[sessionID]->getPeerAddr(), TCP_PORT);
}

void BgpRouter::socketEstablished(TcpSocket *socket)
{
    int connId = socket->getSocketId();
    _currSessionId = findIdFromSocketConnId(_BGPSessions, connId);
    if (_currSessionId == static_cast<SessionId>(-1)) {
        throw cRuntimeError("socket id=%d is not established", connId);
    }

    // if it's an IGP Session, TCPConnectionConfirmed only if all EGP Sessions established
    if (_BGPSessions[_currSessionId]->getType() == IGP &&
        this->findNextSession(EGP) != static_cast<SessionId>(-1))
    {
        _BGPSessions[_currSessionId]->getFSM()->TcpConnectionFails();
    }
    else {
        _BGPSessions[_currSessionId]->getFSM()->TcpConnectionConfirmed();
        _BGPSessions[_currSessionId]->getSocketListen()->abort();
    }

    if (_BGPSessions[_currSessionId]->getSocketListen()->getSocketId() != connId &&
        _BGPSessions[_currSessionId]->getType() == EGP &&
        this->findNextSession(EGP) != static_cast<SessionId>(-1))
    {
        _BGPSessions[_currSessionId]->getSocketListen()->abort();
    }
}

void BgpRouter::socketFailure(TcpSocket *socket, int code)
{
    int connId = socket->getSocketId();
    _currSessionId = findIdFromSocketConnId(_BGPSessions, connId);
    if (_currSessionId != static_cast<SessionId>(-1)) {
        _BGPSessions[_currSessionId]->getFSM()->TcpConnectionFails();
    }
}

void BgpRouter::socketPeerClosed(TcpSocket *socket)
{
    socket->close();
    int connId = socket->getSocketId();
    _currSessionId = findIdFromSocketConnId(_BGPSessions, connId);
    if (_currSessionId != static_cast<SessionId>(-1))
        _BGPSessions[_currSessionId]->getFSM()->TcpConnectionFails();
}

void BgpRouter::socketDataArrived(TcpSocket *socket)
{
    auto queue = socket->getReadBuffer();
    while (queue->has<BgpHeader>()) {
        auto header = queue->pop<BgpHeader>();
        processChunks(*header.get());
    }
}

void BgpRouter::socketDataArrived(TcpSocket *socket, Packet *packet, bool urgent)
{
    _currSessionId = findIdFromSocketConnId(_BGPSessions, socket->getSocketId());
    if (_currSessionId != static_cast<SessionId>(-1))
        BufferingCallback::socketDataArrived(socket, packet, urgent);
    else
        delete packet;
}

void BgpRouter::processChunks(const BgpHeader& ptrHdr)
{
    switch (ptrHdr.getType()) {
        case BGP_OPEN:
            processMessage(*check_and_cast<const BgpOpenMessage *>(&ptrHdr));
            break;

        case BGP_KEEPALIVE:
            processMessage(*check_and_cast<const BgpKeepAliveMessage *>(&ptrHdr));
            break;

        case BGP_UPDATE:
            processMessage(*check_and_cast<const BgpUpdateMessage *>(&ptrHdr));
            break;

        default:
            throw cRuntimeError("Invalid BGP message type %d", ptrHdr.getType());
    }
}

void BgpRouter::processMessage(const BgpOpenMessage& msg)
{
    BgpSession *session = _BGPSessions[_currSessionId];
    EV_INFO << "Processing BGP OPEN message from "
            << session->getPeerAddr().str(false)
            << " with contents: \n";
    printOpenMessage(msg);

    auto peerAddressFamilies = getMultiprotocolCapabilities(msg);
    session->setPeerAddressFamilies(peerAddressFamilies);
    for (auto family : session->getNegotiatedAddressFamilies())
        EV_INFO << "Negotiated MP-BGP address family " << addressFamilyToString(family)
                << " with peer " << session->getPeerAddr().str(false) << "\n";

    session->getFSM()->OpenMsgEvent();
}

void BgpRouter::processMessage(const BgpKeepAliveMessage& msg)
{
    BgpSession *session = _BGPSessions[_currSessionId];
    EV_INFO << "Processing BGP Keep Alive message from "
            << session->getPeerAddr().str(false)
            << " with contents: \n";
    printKeepAliveMessage(msg);
    session->getFSM()->KeepAliveMsgEvent();
}

void BgpRouter::processMessage(const BgpUpdateMessage& msg)
{
    BgpSession *session = _BGPSessions[_currSessionId];
    EV_INFO << "Processing BGP Update message from "
            << session->getPeerAddr().str(false)
            << " with contents: \n";
    printUpdateMessage(msg);
    session->getFSM()->UpdateMsgEvent();

    for (size_t i = 0; i < msg.getPathAttributesArraySize(); i++) {
        switch (msg.getPathAttributes(i)->getTypeCode()) {
            case BgpUpdateAttributeTypeCode::MP_REACH_NLRI: {
                auto& mpReach = *check_and_cast<const BgpUpdatePathAttributesMpReachNlri *>(msg.getPathAttributes(i));
                processMpReachNlri(msg, mpReach, _currSessionId);
                break;
            }
            case BgpUpdateAttributeTypeCode::MP_UNREACH_NLRI: {
                auto& mpUnreach = *check_and_cast<const BgpUpdatePathAttributesMpUnreachNlri *>(msg.getPathAttributes(i));
                processMpUnreachNlri(mpUnreach, _currSessionId);
                break;
            }
            default:
                break;
        }
    }

    for (size_t i = 0; i < msg.getWithdrawnRoutesArraySize(); i++) {
        const BgpUpdateWithdrawnRoutes& withdrawn = msg.getWithdrawnRoutes(i);
        Ipv4Address netmask = Ipv4Address::makeNetmask(withdrawn.length);
        auto removedRoute = removeAdjRibInIpv4Route(withdrawn.prefix, netmask, _currSessionId);
        bool removed = removedRoute != nullptr;
        delete removedRoute;
        if (!removed) {
            EV_INFO << "Ignoring withdrawal for unknown IPv4 route "
                    << withdrawn.prefix << "/" << (int)withdrawn.length << "\n";
            continue;
        }

        EV_INFO << "Removed BGP IPv4 candidate from Adj-RIB-In after withdrawal: "
                << withdrawn.prefix << "/" << (int)withdrawn.length << "\n";

        BgpRoutingTableEntry *selectedRoute = nullptr;
        BgpProcessResult result = recomputeIpv4Route(withdrawn.prefix, netmask, _currSessionId, true, selectedRoute);
        if (result == RESULT0)
            continue;

        if (selectedRoute && selectedRoute->getLearnedSessionId() != 0)
            updateSendProcess(result, selectedRoute->getLearnedSessionId(), selectedRoute);
        else {
            auto withdrawnEntry = new BgpRoutingTableEntry();
            withdrawnEntry->setDestination(withdrawn.prefix);
            withdrawnEntry->setNetmask(netmask);
            sendWithdrawNlri(withdrawnEntry, _currSessionId, true);
            delete withdrawnEntry;
        }
    }

    if (msg.getNLRIArraySize() == 0)
        return;

    BgpRoutingTableEntry *entry = new BgpRoutingTableEntry();
    entry->setLocalPreference(bgpModule->par("localPreference").intValue());
    entry->setDestination(msg.getNLRI(0).prefix);

    Ipv4Address netMask(Ipv4Address::ALLONES_ADDRESS);
    netMask = Ipv4Address::makeNetmask(msg.getNLRI(0).length);
    entry->setNetmask(netMask);

    for (size_t i = 0; i < msg.getPathAttributesArraySize(); i++) {
        if (msg.getPathAttributes(i)->getTypeCode() == BgpUpdateAttributeTypeCode::AS_PATH) {
            auto& asPath = *check_and_cast<const BgpUpdatePathAttributesAsPath *>(msg.getPathAttributes(i));
            for (size_t k = 0; k < asPath.getValueArraySize(); k++) {
                const BgpAsPathSegment& asPathVal = asPath.getValue(k);
                for (size_t n = 0; n < asPathVal.getAsValueArraySize(); n++) {
                    entry->addAS(asPathVal.getAsValue(n));
                }
            }
        }
    }

    BgpProcessResult decisionProcessResult = asLoopDetection(entry, myAsId);

    if (decisionProcessResult == ASLOOP_NO_DETECTED) {
        // RFC 4271, 9.1.  Decision Process
        decisionProcessResult = decisionProcess(msg, entry, _currSessionId);
        // RFC 4271, 9.2.  Update-Send Process
        if (decisionProcessResult != 0)
            updateSendProcess(decisionProcessResult, _currSessionId, entry);
    }
    else
        delete entry;
}

BgpProcessResult BgpRouter::asLoopDetection(BgpRoutingTableEntry *entry, AsId myAS)
{
    for (unsigned int i = 1; i < entry->getASCount(); i++) {
        if (myAS == entry->getAS(i))
            return ASLOOP_DETECTED;
    }
    return ASLOOP_NO_DETECTED;
}

BgpProcessResult BgpRouter::asLoopDetection(BgpIpv6RoutingTableEntry *entry, AsId myAS)
{
    for (unsigned int i = 1; i < entry->getASCount(); i++) {
        if (myAS == entry->getAS(i))
            return ASLOOP_DETECTED;
    }
    return ASLOOP_NO_DETECTED;
}

bool BgpRouter::isInIpv6Table(const std::vector<BgpIpv6RoutingTableEntry *>& rtTable, const BgpIpv6RoutingTableEntry *entry) const
{
    return findIpv6TableIndex(rtTable, entry) != (unsigned long)-1;
}

unsigned long BgpRouter::findIpv6TableIndex(const std::vector<BgpIpv6RoutingTableEntry *>& rtTable, const BgpIpv6RoutingTableEntry *entry) const
{
    for (unsigned long index = 0; index < rtTable.size(); index++) {
        auto route = rtTable[index];
        if (route->getDestination() == entry->getDestination() &&
            route->getPrefixLength() == entry->getPrefixLength())
        {
            return index;
        }
    }
    return -1;
}

BgpRoutingTableEntry *BgpRouter::findIpv4Route(const Ipv4Address& prefix, const Ipv4Address& netmask, SessionId learnedSessionId) const
{
    for (auto route : bgpRoutingTable) {
        if (route->getLearnedSessionId() == learnedSessionId &&
            ipv4PrefixesEqual(prefix, netmask, route->getDestination(), route->getNetmask()))
        {
            return route;
        }
    }
    return nullptr;
}

BgpRoutingTableEntry *BgpRouter::findAdjRibInIpv4Route(const Ipv4Address& prefix, const Ipv4Address& netmask, SessionId learnedSessionId) const
{
    for (auto route : adjRibIn) {
        if (route->getLearnedSessionId() == learnedSessionId &&
            ipv4PrefixesEqual(prefix, netmask, route->getDestination(), route->getNetmask()))
        {
            return route;
        }
    }
    return nullptr;
}

BgpRoutingTableEntry *BgpRouter::removeAdjRibInIpv4Route(const Ipv4Address& prefix, const Ipv4Address& netmask, SessionId learnedSessionId)
{
    for (auto routeIt = adjRibIn.begin(); routeIt != adjRibIn.end(); routeIt++) {
        auto route = *routeIt;
        if (route->getLearnedSessionId() == learnedSessionId &&
            ipv4PrefixesEqual(prefix, netmask, route->getDestination(), route->getNetmask()))
        {
            adjRibIn.erase(routeIt);
            return route;
        }
    }
    return nullptr;
}

BgpIpv6RoutingTableEntry *BgpRouter::findAdjRibInIpv6Route(const Ipv6Address& prefix, int prefixLength, SessionId learnedSessionId) const
{
    for (auto route : adjRibInIpv6) {
        if (route->getDestination() == prefix &&
            route->getPrefixLength() == prefixLength &&
            route->getLearnedSessionId() == learnedSessionId)
        {
            return route;
        }
    }
    return nullptr;
}

BgpIpv6RoutingTableEntry *BgpRouter::removeAdjRibInIpv6Route(const Ipv6Address& prefix, int prefixLength, SessionId learnedSessionId)
{
    for (auto routeIt = adjRibInIpv6.begin(); routeIt != adjRibInIpv6.end(); routeIt++) {
        auto route = *routeIt;
        if (route->getDestination() == prefix &&
            route->getPrefixLength() == prefixLength &&
            route->getLearnedSessionId() == learnedSessionId)
        {
            adjRibInIpv6.erase(routeIt);
            return route;
        }
    }
    return nullptr;
}

BgpProcessResult BgpRouter::recomputeIpv4Route(const Ipv4Address& prefix, const Ipv4Address& netmask, SessionId sourceSessionIndex, bool fromPeer, BgpRoutingTableEntry *&selectedRoute)
{
    (void)sourceSessionIndex;
    (void)fromPeer;

    // Re-run the RFC 4271 best-path choice for one IPv4 prefix after a
    // withdrawal or session loss. Adj-RIB-In contains peer candidates, while
    // bgpRoutingTable contains the selected Loc-RIB route and local Network
    // routes; only the selected route is installed into the IPv4 routing table.
    selectedRoute = nullptr;
    BgpRoutingTableEntry *oldSelectedRoute = nullptr;
    BgpRoutingTableEntry *bestRoute = nullptr;

    for (auto route : bgpRoutingTable) {
        if (!ipv4PrefixesEqual(prefix, netmask, route->getDestination(), route->getNetmask()))
            continue;

        if (route->getLearnedSessionId() == 0) {
            if (!bestRoute || routeIsBetter(route, bestRoute))
                bestRoute = route;
        }
        else
            oldSelectedRoute = route;
    }

    for (auto route : adjRibIn) {
        if (ipv4PrefixesEqual(prefix, netmask, route->getDestination(), route->getNetmask()) &&
            (!bestRoute || routeIsBetter(route, bestRoute)))
        {
            bestRoute = route;
        }
    }

    if (oldSelectedRoute && bestRoute && sameRouteAttributes(oldSelectedRoute, bestRoute)) {
        selectedRoute = oldSelectedRoute;
        return RESULT0;
    }

    if (oldSelectedRoute) {
        auto routeIt = std::find(bgpRoutingTable.begin(), bgpRoutingTable.end(), oldSelectedRoute);
        ASSERT(routeIt != bgpRoutingTable.end());
        bgpRoutingTable.erase(routeIt);
        if (oldSelectedRoute->getRoutingTable())
            rt->deleteRoute(oldSelectedRoute);
        else
            delete oldSelectedRoute;
    }

    if (!bestRoute) {
        EV_INFO << "Adj-RIB-In recomputation found no IPv4 route for "
                << prefix << "/" << netmask.getNetmaskLength() << "\n";
        return oldSelectedRoute ? ROUTE_DESTINATION_CHANGED : RESULT0;
    }

    if (bestRoute->getLearnedSessionId() == 0) {
        selectedRoute = bestRoute;
        return oldSelectedRoute ? ROUTE_DESTINATION_CHANGED : RESULT0;
    }

    selectedRoute = cloneRoute(bestRoute);
    selectedRoute->setInterface(_BGPSessions[selectedRoute->getLearnedSessionId()]->getLinkIntf());
    bgpRoutingTable.push_back(selectedRoute);

    if (isReachable(selectedRoute->getGateway()))
        rt->addRoute(selectedRoute);
    else
        EV_INFO << "Keeping selected BGP IPv4 route " << selectedRoute->str()
                << " in BGP state because its next hop is not reachable\n";

    EV_INFO << "Adj-RIB-In selected BGP IPv4 route " << selectedRoute->str() << "\n";
    return oldSelectedRoute ? ROUTE_DESTINATION_CHANGED : NEW_ROUTE_ADDED;
}

BgpProcessResult BgpRouter::recomputeIpv6Route(const Ipv6Address& prefix, int prefixLength, SessionId sourceSessionIndex, bool fromPeer, BgpIpv6RoutingTableEntry *&selectedRoute)
{
    (void)sourceSessionIndex;
    (void)fromPeer;

    // Same decision model as IPv4, applied to RFC 4760 IPv6-unicast NLRI:
    // choose the best candidate from Adj-RIB-In plus local Network routes, then
    // replace the selected Loc-RIB/Ipv6RoutingTable route only if the best path
    // actually changed.
    selectedRoute = nullptr;
    BgpIpv6RoutingTableEntry *oldSelectedRoute = nullptr;
    BgpIpv6RoutingTableEntry *bestRoute = nullptr;

    for (auto route : bgpIpv6RoutingTable) {
        if (route->getDestination() != prefix || route->getPrefixLength() != prefixLength)
            continue;

        if (route->getLearnedSessionId() == 0) {
            if (!bestRoute || routeIsBetter(route, bestRoute))
                bestRoute = route;
        }
        else
            oldSelectedRoute = route;
    }

    for (auto route : adjRibInIpv6) {
        if (route->getDestination() == prefix &&
            route->getPrefixLength() == prefixLength &&
            (!bestRoute || routeIsBetter(route, bestRoute)))
        {
            bestRoute = route;
        }
    }

    if (oldSelectedRoute && bestRoute && sameRouteAttributes(oldSelectedRoute, bestRoute)) {
        selectedRoute = oldSelectedRoute;
        return RESULT0;
    }

    if (oldSelectedRoute) {
        auto routeIt = std::find(bgpIpv6RoutingTable.begin(), bgpIpv6RoutingTable.end(), oldSelectedRoute);
        ASSERT(routeIt != bgpIpv6RoutingTable.end());
        removeInstalledIpv6Route(oldSelectedRoute);
        bgpIpv6RoutingTable.erase(routeIt);
        delete oldSelectedRoute;
    }

    if (!bestRoute) {
        EV_INFO << "Adj-RIB-In recomputation found no MP-BGP IPv6 route for "
                << prefix << "/" << prefixLength << "\n";
        return oldSelectedRoute ? ROUTE_DESTINATION_CHANGED : RESULT0;
    }

    if (bestRoute->getLearnedSessionId() == 0) {
        selectedRoute = bestRoute;
        return oldSelectedRoute ? ROUTE_DESTINATION_CHANGED : RESULT0;
    }

    selectedRoute = cloneRoute(bestRoute);
    bgpIpv6RoutingTable.push_back(selectedRoute);
    installIpv6Route(selectedRoute, selectedRoute->getLearnedSessionId());

    if (rt6)
        rt6->purgeDestCache();

    EV_INFO << "Adj-RIB-In selected MP-BGP IPv6 route " << selectedRoute->str() << "\n";
    return oldSelectedRoute ? ROUTE_DESTINATION_CHANGED : NEW_ROUTE_ADDED;
}

BgpProcessResult BgpRouter::decisionProcess(const BgpUpdateMessage& msg, BgpIpv6RoutingTableEntry *entry, SessionId sessionIndex)
{
    (void)msg;

    // MP_REACH_NLRI has already been normalized into an IPv6 BGP route entry.
    // First apply the existing inbound filters, then store the candidate in
    // Adj-RIB-In and run the decision process for this prefix.
    if (isInIpv6PrefixList(_prefixIpv6ListIN, entry) != (unsigned long)-1 || isInASList(_ASListIN, entry)) {
        delete entry;
        return RESULT0;
    }

    BgpSessionType type = _BGPSessions[sessionIndex]->getType();
    if (type == IGP)
        entry->setIBgpLearned(true);

    entry->setLearnedSessionId(sessionIndex);

    // One peer can advertise at most one active path for the same prefix here;
    // replace that peer's old Adj-RIB-In candidate before recomputing Loc-RIB.
    auto oldRoute = removeAdjRibInIpv6Route(entry->getDestination(), entry->getPrefixLength(), sessionIndex);
    delete oldRoute;

    adjRibInIpv6.push_back(entry);
    EV_INFO << "Stored MP-BGP IPv6 candidate in Adj-RIB-In: " << entry->str()
            << " from peer " << _BGPSessions[sessionIndex]->getPeerAddr().str(false) << "\n";

    BgpIpv6RoutingTableEntry *selectedRoute = nullptr;
    return recomputeIpv6Route(entry->getDestination(), entry->getPrefixLength(), sessionIndex, true, selectedRoute);
}

void BgpRouter::processMpReachNlri(const BgpUpdateMessage& msg, const BgpUpdatePathAttributesMpReachNlri& mpReach, SessionId sessionIndex)
{
    BgpAddressFamily family;
    family.afi = mpReach.getAfi();
    family.safi = mpReach.getSafi();

    if (family.afi != AFI_IPV6 || family.safi != SAFI_UNICAST) {
        EV_WARN << "Ignoring unsupported MP_REACH_NLRI address family "
                << addressFamilyToString(family) << "\n";
        return;
    }

    if (!_BGPSessions[sessionIndex]->hasNegotiatedAddressFamily(family)) {
        EV_WARN << "Ignoring unnegotiated MP_REACH_NLRI address family "
                << addressFamilyToString(family)
                << " from peer " << _BGPSessions[sessionIndex]->getPeerAddr().str(false) << "\n";
        return;
    }

    for (size_t routeIndex = 0; routeIndex < mpReach.getNlriArraySize(); routeIndex++) {
        const BgpMpNlri& nlri = mpReach.getNlri(routeIndex);
        auto entry = new BgpIpv6RoutingTableEntry(nlri.ipv6Prefix, nlri.length);
        entry->setNextHop(mpReach.getNextHopIpv6Address());
        entry->setLocalPreference(bgpModule->par("localPreference").intValue());

        for (size_t i = 0; i < msg.getPathAttributesArraySize(); i++) {
            switch (msg.getPathAttributes(i)->getTypeCode()) {
                case BgpUpdateAttributeTypeCode::ORIGIN: {
                    auto origin = check_and_cast<const BgpUpdatePathAttributesOrigin *>(msg.getPathAttributes(i));
                    entry->setPathType(origin->getValue());
                    break;
                }
                case BgpUpdateAttributeTypeCode::AS_PATH: {
                    auto& asPath = *check_and_cast<const BgpUpdatePathAttributesAsPath *>(msg.getPathAttributes(i));
                    for (size_t k = 0; k < asPath.getValueArraySize(); k++) {
                        const BgpAsPathSegment& asPathVal = asPath.getValue(k);
                        for (size_t n = 0; n < asPathVal.getAsValueArraySize(); n++)
                            entry->addAS(asPathVal.getAsValue(n));
                    }
                    break;
                }
                case BgpUpdateAttributeTypeCode::LOCAL_PREF: {
                    auto localPref = check_and_cast<const BgpUpdatePathAttributesLocalPref *>(msg.getPathAttributes(i));
                    entry->setLocalPreference(localPref->getValue());
                    break;
                }
                default:
                    break;
            }
        }

        BgpProcessResult decisionProcessResult = asLoopDetection(entry, myAsId);
        if (decisionProcessResult == ASLOOP_NO_DETECTED) {
            decisionProcessResult = decisionProcess(msg, entry, sessionIndex);
            if (decisionProcessResult != RESULT0) {
                BgpIpv6RoutingTableEntry *selectedRoute = nullptr;
                for (auto route : bgpIpv6RoutingTable) {
                    if (route->getDestination() == nlri.ipv6Prefix &&
                        route->getPrefixLength() == nlri.length &&
                        route->getLearnedSessionId() != 0)
                    {
                        selectedRoute = route;
                        break;
                    }
                }
                if (selectedRoute)
                    updateSendProcess(decisionProcessResult, selectedRoute->getLearnedSessionId(), selectedRoute);
            }
        }
        else
            delete entry;
    }
}

BgpIpv6RoutingTableEntry *BgpRouter::findIpv6Route(const Ipv6Address& prefix, int prefixLength, SessionId learnedSessionId) const
{
    for (auto route : bgpIpv6RoutingTable) {
        if (route->getDestination() == prefix &&
            route->getPrefixLength() == prefixLength &&
            route->getLearnedSessionId() == learnedSessionId)
        {
            return route;
        }
    }
    return nullptr;
}

void BgpRouter::installIpv6Route(BgpIpv6RoutingTableEntry *entry, SessionId sessionIndex)
{
    if (entry->getRoutingTable())
        return;

    if (!rt6) {
        EV_INFO << "Keeping MP-BGP IPv6 route " << entry->getDestination() << "/"
                << entry->getPrefixLength()
                << " in BGP state because no IPv6 routing table is configured\n";
        return;
    }

    entry->setInterface(_BGPSessions[sessionIndex]->getLinkIntf());
    if (_BGPSessions[sessionIndex]->getType() == IGP)
        entry->setAdminDist(Ipv6Route::dBGPInternal);
    else
        entry->setAdminDist(Ipv6Route::dBGPExternal);

    rt6->addRoutingProtocolRoute(entry);
    EV_INFO << "Installed MP-BGP IPv6 route " << entry->str() << "\n";
}

void BgpRouter::removeInstalledIpv6Route(BgpIpv6RoutingTableEntry *entry)
{
    Ipv6RoutingTable *routingTable = entry->getRoutingTable();
    if (!routingTable)
        return;

    routingTable->removeRoute(entry);
    routingTable->purgeDestCache();
    EV_INFO << "Removed MP-BGP IPv6 route from IPv6 routing table: "
            << entry->getDestination() << "/" << entry->getPrefixLength() << "\n";
}

void BgpRouter::removeInstalledIpv6Routes()
{
    for (auto route : bgpIpv6RoutingTable)
        removeInstalledIpv6Route(route);
}

void BgpRouter::removeRoutesLearnedFromSession(SessionId sessionId)
{
    // A failed session implicitly withdraws every route learned from that peer.
    // Remove those candidates from Adj-RIB-In, remember the affected prefixes,
    // then recompute each prefix once. If a backup candidate is present it is
    // promoted; otherwise a withdrawal is propagated to the remaining peers.
    struct Ipv4Prefix {
        Ipv4Address prefix;
        Ipv4Address netmask;
    };
    struct Ipv6Prefix {
        Ipv6Address prefix;
        int prefixLength = 0;
    };

    std::vector<Ipv4Prefix> affectedIpv4Prefixes;
    std::vector<Ipv6Prefix> affectedIpv6Prefixes;

    for (auto routeIt = adjRibIn.begin(); routeIt != adjRibIn.end(); ) {
        BgpRoutingTableEntry *entry = *routeIt;
        if (entry->getLearnedSessionId() == sessionId) {
            EV_INFO << "Removing BGP IPv4 candidate learned from failed session "
                    << sessionId << ": " << entry->getDestination()
                    << "/" << entry->getNetmask().getNetmaskLength() << "\n";
            affectedIpv4Prefixes.push_back({entry->getDestination(), entry->getNetmask()});
            routeIt = adjRibIn.erase(routeIt);
            delete entry;
        }
        else
            routeIt++;
    }

    for (auto routeIt = adjRibInIpv6.begin(); routeIt != adjRibInIpv6.end(); ) {
        BgpIpv6RoutingTableEntry *entry = *routeIt;
        if (entry->getLearnedSessionId() == sessionId) {
            EV_INFO << "Removing MP-BGP IPv6 candidate learned from failed session "
                    << sessionId << ": " << entry->getDestination()
                    << "/" << entry->getPrefixLength() << "\n";
            affectedIpv6Prefixes.push_back({entry->getDestination(), entry->getPrefixLength()});
            routeIt = adjRibInIpv6.erase(routeIt);
            delete entry;
        }
        else
            routeIt++;
    }

    for (const auto& prefix : affectedIpv4Prefixes) {
        BgpRoutingTableEntry *selectedRoute = nullptr;
        BgpProcessResult result = recomputeIpv4Route(prefix.prefix, prefix.netmask, sessionId, true, selectedRoute);
        if (result == RESULT0)
            continue;

        if (selectedRoute && selectedRoute->getLearnedSessionId() != 0)
            updateSendProcess(result, selectedRoute->getLearnedSessionId(), selectedRoute);
        else {
            auto withdrawnEntry = new BgpRoutingTableEntry();
            withdrawnEntry->setDestination(prefix.prefix);
            withdrawnEntry->setNetmask(prefix.netmask);
            sendWithdrawNlri(withdrawnEntry, sessionId, true);
            delete withdrawnEntry;
        }
    }

    for (const auto& prefix : affectedIpv6Prefixes) {
        BgpIpv6RoutingTableEntry *selectedRoute = nullptr;
        BgpProcessResult result = recomputeIpv6Route(prefix.prefix, prefix.prefixLength, sessionId, true, selectedRoute);
        if (result == RESULT0)
            continue;

        if (selectedRoute && selectedRoute->getLearnedSessionId() != 0)
            updateSendProcess(result, selectedRoute->getLearnedSessionId(), selectedRoute);
        else {
            auto withdrawnEntry = new BgpIpv6RoutingTableEntry(prefix.prefix, prefix.prefixLength);
            sendMpUnreachNlri(withdrawnEntry, sessionId, true);
            delete withdrawnEntry;
        }
    }
}

void BgpRouter::sendWithdrawNlri(BgpRoutingTableEntry *entry, SessionId sourceSessionIndex, bool fromPeer)
{
    for (auto& elem : _BGPSessions) {
        BgpSession *targetSession = elem.second;
        if (!targetSession->isEstablished())
            continue;

        if (fromPeer && elem.first == sourceSessionIndex)
            continue;

        if (fromPeer && entry->isIBgpLearned() && targetSession->getType() == IGP) {
            EV_INFO << "BGP Split Horizon: prevent withdrawal propagation of network "
                    << entry->getDestination() << "\\" << entry->getNetmask();
            continue;
        }

        BgpUpdateWithdrawnRoutes withdrawnRoute;
        withdrawnRoute.length = entry->getNetmask().getNetmaskLength();
        withdrawnRoute.prefix = entry->getDestination().doAnd(entry->getNetmask());
        targetSession->sendWithdrawMessage(withdrawnRoute);
    }
}

void BgpRouter::withdrawIpv4Route(BgpRoutingTableEntry *entry, SessionId sourceSessionIndex, bool fromPeer)
{
    auto routeIt = std::find(bgpRoutingTable.begin(), bgpRoutingTable.end(), entry);
    if (routeIt == bgpRoutingTable.end())
        return;

    EV_INFO << "Withdrawing BGP IPv4 route " << entry->getDestination()
            << "/" << entry->getNetmask().getNetmaskLength() << "\n";

    sendWithdrawNlri(entry, sourceSessionIndex, fromPeer);
    bgpRoutingTable.erase(routeIt);
    if (entry->getRoutingTable())
        rt->deleteRoute(entry);
    else
        delete entry;
}

void BgpRouter::sendMpUnreachNlri(BgpIpv6RoutingTableEntry *entry, SessionId sourceSessionIndex, bool fromPeer)
{
    BgpAddressFamily ipv6Unicast = makeAddressFamily(AFI_IPV6, SAFI_UNICAST);
    for (auto& elem : _BGPSessions) {
        BgpSession *targetSession = elem.second;
        if (!targetSession->isEstablished())
            continue;

        if (fromPeer && elem.first == sourceSessionIndex)
            continue;

        if (!targetSession->hasNegotiatedAddressFamily(ipv6Unicast))
            continue;

        if (fromPeer && entry->isIBgpLearned() && targetSession->getType() == IGP) {
            EV_INFO << "BGP Split Horizon: prevent withdrawal propagation of IPv6 network "
                    << entry->getDestination() << "/" << entry->getPrefixLength();
            continue;
        }

        std::vector<BgpUpdatePathAttributes *> content;
        auto mpUnreach = new BgpUpdatePathAttributesMpUnreachNlri();
        content.push_back(mpUnreach);
        mpUnreach->setAfi(AFI_IPV6);
        mpUnreach->setSafi(SAFI_UNICAST);

        BgpMpNlri nlri;
        nlri.length = entry->getPrefixLength();
        nlri.ipv6Prefix = entry->getDestination();
        mpUnreach->setWithdrawnRoutesArraySize(1);
        mpUnreach->setWithdrawnRoutes(0, nlri);
        mpUnreach->setLength(2 + 1 + 1 + (entry->getPrefixLength() + 7) / 8);

        targetSession->sendUpdateMessage(content);
    }
}

void BgpRouter::withdrawIpv6Route(BgpIpv6RoutingTableEntry *entry, SessionId sourceSessionIndex, bool fromPeer)
{
    auto routeIt = std::find(bgpIpv6RoutingTable.begin(), bgpIpv6RoutingTable.end(), entry);
    if (routeIt == bgpIpv6RoutingTable.end())
        return;

    EV_INFO << "Withdrawing MP-BGP IPv6 route " << entry->getDestination()
            << "/" << entry->getPrefixLength() << "\n";

    sendMpUnreachNlri(entry, sourceSessionIndex, fromPeer);
    removeInstalledIpv6Route(entry);
    bgpIpv6RoutingTable.erase(routeIt);
    delete entry;
}

void BgpRouter::processMpUnreachNlri(const BgpUpdatePathAttributesMpUnreachNlri& mpUnreach, SessionId sessionIndex)
{
    BgpAddressFamily family;
    family.afi = mpUnreach.getAfi();
    family.safi = mpUnreach.getSafi();

    if (family.afi != AFI_IPV6 || family.safi != SAFI_UNICAST) {
        EV_WARN << "Ignoring unsupported MP_UNREACH_NLRI address family "
                << addressFamilyToString(family) << "\n";
        return;
    }

    if (!_BGPSessions[sessionIndex]->hasNegotiatedAddressFamily(family)) {
        EV_WARN << "Ignoring unnegotiated MP_UNREACH_NLRI address family "
                << addressFamilyToString(family)
                << " from peer " << _BGPSessions[sessionIndex]->getPeerAddr().str(false) << "\n";
        return;
    }

    for (size_t i = 0; i < mpUnreach.getWithdrawnRoutesArraySize(); i++) {
        const BgpMpNlri& withdrawn = mpUnreach.getWithdrawnRoutes(i);
        auto removedRoute = removeAdjRibInIpv6Route(withdrawn.ipv6Prefix, withdrawn.length, sessionIndex);
        if (!removedRoute) {
            EV_INFO << "Ignoring MP_UNREACH_NLRI for unknown IPv6 route "
                    << withdrawn.ipv6Prefix << "/" << (int)withdrawn.length << "\n";
            continue;
        }
        delete removedRoute;

        EV_INFO << "Removed MP-BGP IPv6 candidate from Adj-RIB-In after MP_UNREACH_NLRI: "
                << withdrawn.ipv6Prefix << "/" << (int)withdrawn.length << "\n";

        // A withdrawal affects only this peer's candidate. Recompute the
        // prefix from the remaining Adj-RIB-In entries so a backup path is
        // advertised only when the selected route actually changes.
        BgpIpv6RoutingTableEntry *selectedRoute = nullptr;
        BgpProcessResult result = recomputeIpv6Route(withdrawn.ipv6Prefix, withdrawn.length, sessionIndex, true, selectedRoute);
        if (result == RESULT0)
            continue;

        if (selectedRoute && selectedRoute->getLearnedSessionId() != 0)
            updateSendProcess(result, selectedRoute->getLearnedSessionId(), selectedRoute);
        else {
            auto withdrawnEntry = new BgpIpv6RoutingTableEntry(withdrawn.ipv6Prefix, withdrawn.length);
            sendMpUnreachNlri(withdrawnEntry, sessionIndex, true);
            delete withdrawnEntry;
        }
    }
}

void BgpRouter::processIpv6WithdrawTimer(cMessage *timer)
{
    // Timer ownership is kept separate from route ownership: the message key
    // identifies the local IPv6 route, and withdrawIpv6Route() removes the
    // route from BGP state, the IPv6 routing table, and negotiated peers.
    auto timerIt = ipv6WithdrawRoutes.find(timer);
    if (timerIt == ipv6WithdrawRoutes.end())
        throw cRuntimeError("Unknown MP-BGP IPv6 withdraw timer");

    BgpIpv6RoutingTableEntry *entry = timerIt->second;
    ipv6WithdrawRoutes.erase(timerIt);
    withdrawIpv6Route(entry, 0, false);
}

/* add entry to routing table, or delete entry */
BgpProcessResult BgpRouter::decisionProcess(const BgpUpdateMessage& msg, BgpRoutingTableEntry *entry, SessionId sessionIndex)
{
    // Don't add the route if it exists in PrefixListINTable or in ASListINTable
    if (isInTable(_prefixListIN, entry) != (unsigned long)-1 || isInASList(_ASListIN, entry)) {
        delete entry;
        return RESULT0;
    }

    /*If the AS_PATH attribute of a BGP route contains an AS loop, the BGP
       route should be excluded from the decision process. */
#if 0
    entry->setPathType(msg.getPathAttributeList(0).getOrigin().getValue());
    entry->setGateway(msg.getPathAttributeList(0).getNextHop().getValue());
    if (msg.getPathAttributeList(0).getLocalPrefArraySize() != 0)
        entry->setLocalPreference(msg.getPathAttributeList(0).getLocalPref(0).getValue());
#else
    for (size_t i = 0; i < msg.getPathAttributesArraySize(); i++) {
        switch (msg.getPathAttributes(i)->getTypeCode()) {
            case BgpUpdateAttributeTypeCode::ORIGIN: {
                auto attr = check_and_cast<const BgpUpdatePathAttributesOrigin *>(msg.getPathAttributes(i));
                entry->setPathType(attr->getValue());
                break;
            }
            case BgpUpdateAttributeTypeCode::NEXT_HOP: {
                auto attr = check_and_cast<const BgpUpdatePathAttributesNextHop *>(msg.getPathAttributes(i));
                entry->setGateway(attr->getValue());
                break;
            }
            case BgpUpdateAttributeTypeCode::LOCAL_PREF: {
                auto attr = check_and_cast<const BgpUpdatePathAttributesLocalPref *>(msg.getPathAttributes(i));
                entry->setLocalPreference(attr->getValue());
                break;
            }
            default:
                break;
        }
    }
#endif

    BgpSessionType type = _BGPSessions[sessionIndex]->getType();
    if (type == IGP) {
        entry->setAdminDist(Ipv4Route::dBGPInternal);
        entry->setIBgpLearned(true);
    }
    else if (type == EGP)
        entry->setAdminDist(Ipv4Route::dBGPExternal);
    else
        entry->setAdminDist(Ipv4Route::dUnknown);
    entry->setLearnedSessionId(sessionIndex);

    // Keep a peer-owned copy in Adj-RIB-In for future reselection. The original
    // entry continues through the legacy IPv4 decision/install path below so
    // existing RFC 4271 behavior and fingerprints remain unchanged.
    auto oldAdjRoute = removeAdjRibInIpv4Route(entry->getDestination(), entry->getNetmask(), sessionIndex);
    delete oldAdjRoute;
    adjRibIn.push_back(cloneRoute(entry));

    // if the route already exists in BGP routing table, tieBreakingProcess();
    // (RFC 4271: 9.1.2.2 Breaking Ties)
    unsigned long BGPindex = isInTable(bgpRoutingTable, entry);
    if (BGPindex != (unsigned long)-1) {
        if (tieBreakingProcess(bgpRoutingTable[BGPindex], entry)) {
            delete entry;
            return RESULT0;
        }
        else {
            entry->setInterface(_BGPSessions[sessionIndex]->getLinkIntf());
            bgpRoutingTable.push_back(entry);
            rt->addRoute(entry);
            return ROUTE_DESTINATION_CHANGED;
        }
    }

    int indexIP = isInRoutingTable(rt, entry->getDestination());
    // if the route already exists in the IPv4 routing table
    if (indexIP != -1) {
        // and it was not added by BGP before
        if (rt->getRoute(indexIP)->getSourceType() != IRoute::BGP) {
            // and the Update msg is coming from IGP session
            if (_BGPSessions[sessionIndex]->getType() == IGP) {
                Ipv4Route *oldEntry = rt->getRoute(indexIP);
                BgpRoutingTableEntry *BGPEntry = new BgpRoutingTableEntry(oldEntry);
                BGPEntry->addAS(myAsId);
                BGPEntry->setPathType(IGP);
                BGPEntry->setAdminDist(Ipv4Route::dBGPInternal);
                BGPEntry->setIBgpLearned(true);
                BGPEntry->setLocalPreference(entry->getLocalPreference());
                BGPEntry->setLearnedSessionId(sessionIndex);
                rt->addRoute(BGPEntry);
                // Note: No need to delete the existing route. Let the administrative distance decides.
//                rt->deleteRoute(oldEntry);
            }
            else {
                delete entry;
                return RESULT0;
            }
        }
    }
    else {
        // and the Update msg is coming from IGP session
        if (_BGPSessions[sessionIndex]->getType() == IGP) {
            // if the next hop is reachable
            if (isReachable(entry->getGateway())) {
                entry->setInterface(_BGPSessions[sessionIndex]->getLinkIntf());
                rt->addRoute(entry);
            }
        }
    }

    entry->setInterface(_BGPSessions[sessionIndex]->getLinkIntf());
    bgpRoutingTable.push_back(entry);

    if (_BGPSessions[sessionIndex]->getType() == EGP) {
        if (isReachable(entry->getGateway()))
            rt->addRoute(entry);

        // if redistributeInternal is true, then insert the new external route into the OSPF (if exists).
        // The OSPF module then floods AS-External LSA into the AS and lets other routers know
        // about the new external route.
        if (ospfExist(rt) && redistributeInternal) {
            NetworkInterface *ie = entry->getInterface();
            if (!ie)
                throw cRuntimeError("Model error: interface entry is nullptr");
            ospfv2::Ipv4AddressRange OSPFnetAddr;
            OSPFnetAddr.address = entry->getDestination();
            OSPFnetAddr.mask = entry->getNetmask();
            if (!ospfModule)
                throw cRuntimeError("Cannot find the OSPF module on router %s", bgpModule->getFullName());
            ospfModule->insertExternalRoute(ie->getInterfaceId(), OSPFnetAddr);
        }
    }
    return NEW_ROUTE_ADDED; // FIXME model error: When returns NEW_ROUTE_ADDED then entry stored in bgpRoutingTable, but sometimes not stored in rt
}

bool BgpRouter::tieBreakingProcess(BgpRoutingTableEntry *oldEntry, BgpRoutingTableEntry *entry)
{
    if (entry->getLocalPreference() > oldEntry->getLocalPreference()) {
        deleteBGPRoutingEntry(oldEntry);
        return false;
    }

    /* Remove from consideration all routes that are not tied for
         having the smallest number of AS numbers present in their
         AS_PATH attributes.*/
    if (entry->getASCount() < oldEntry->getASCount()) {
        deleteBGPRoutingEntry(oldEntry);
        return false;
    }

    /* Remove from consideration all routes that are not tied for
         having the lowest Origin number in their Origin attribute.*/
    if (entry->getPathType() < oldEntry->getPathType()) {
        deleteBGPRoutingEntry(oldEntry);
        return false;
    }

    return true;
}

bool BgpRouter::tieBreakingProcess(BgpIpv6RoutingTableEntry *oldEntry, BgpIpv6RoutingTableEntry *entry)
{
    if (entry->getLocalPreference() > oldEntry->getLocalPreference())
        return false;

    if (entry->getASCount() < oldEntry->getASCount())
        return false;

    if (entry->getPathType() < oldEntry->getPathType())
        return false;

    return true;
}

void BgpRouter::updateSendProcess(BgpProcessResult type, SessionId sessionIndex, BgpRoutingTableEntry *entry)
{
    // Don't send the update Message if the route exists in listOUTTable
    // SESSION = EGP : send an update message to all BGP Peer (EGP && IGP)
    // if it is not the currentSession and if the session is already established
    // SESSION = IGP : send an update message to External BGP Peer (EGP) only
    // if it is not the currentSession and if the session is already established
    for (auto& elem : _BGPSessions) {
        if (isInTable(_prefixListOUT, entry) != (unsigned long)-1 || isInASList(_ASListOUT, entry) ||
            ((elem).first == sessionIndex && type != NEW_SESSION_ESTABLISHED) ||
            (type == NEW_SESSION_ESTABLISHED && (elem).first != sessionIndex) ||
            !(elem).second->isEstablished())
        {
            continue;
        }

        // if the next hop is not reachable
        if (!isReachable(entry->getGateway()))
            continue;

        BgpSessionType sType = _BGPSessions[sessionIndex]->getType();

        // BGP split horizon: skip if this prefix is learned over I-BGP and we are
        // advertising it to another internal peer.
        if (entry->isIBgpLearned() && sType == IGP && elem.second->getType() == IGP) {
            EV_INFO << "BGP Split Horizon: prevent advertisement of network "
                    << entry->getDestination() << "\\" << entry->getNetmask();
            continue;
        }

        if ((sType == IGP && (elem).second->getType() == EGP) ||
            sType == EGP ||
            type == ROUTE_DESTINATION_CHANGED ||
            type == NEW_SESSION_ESTABLISHED)
        {
            BgpUpdateNlri NLRI;
            std::vector<BgpUpdatePathAttributes *> content;

            unsigned int nbAS = entry->getASCount();
            auto asPath = new BgpUpdatePathAttributesAsPath();
            content.push_back(asPath);
            asPath->setValueArraySize(1);
            asPath->getValueForUpdate(0).setType(AS_SEQUENCE);
            asPath->getValueForUpdate(0).setLength(0);
            if ((elem).second->getType() == EGP) {
                // RFC 4271 : set My AS in first position if it is not already
                if (entry->getAS(0) != myAsId) {
                    asPath->getValueForUpdate(0).setAsValueArraySize(nbAS + 1);
                    asPath->getValueForUpdate(0).setLength(nbAS + 1);
                    asPath->getValueForUpdate(0).setAsValue(0, myAsId);
                    for (unsigned int j = 1; j < nbAS + 1; j++)
                        asPath->getValueForUpdate(0).setAsValue(j, entry->getAS(j - 1));
                }
                else {
                    asPath->getValueForUpdate(0).setAsValueArraySize(nbAS);
                    asPath->getValueForUpdate(0).setLength(nbAS);
                    for (unsigned int j = 0; j < nbAS; j++)
                        asPath->getValueForUpdate(0).setAsValue(j, entry->getAS(j));
                }
            }
            // no AS number is added when the route is being advertised between internal peers
            else if ((elem).second->getType() == IGP) {
                asPath->getValueForUpdate(0).setAsValueArraySize(nbAS);
                asPath->getValueForUpdate(0).setLength(nbAS);
                for (unsigned int j = 0; j < nbAS; j++)
                    asPath->getValueForUpdate(0).setAsValue(j, entry->getAS(j));

                auto localPref = new BgpUpdatePathAttributesLocalPref();
                content.push_back(localPref);
                localPref->setLength(4);
                localPref->setValue(_BGPSessions[sessionIndex]->getLocalPreference());
            }
            asPath->setLength(2 + 2 * asPath->getValue(0).getAsValueArraySize());

            auto nextHopAttr = new BgpUpdatePathAttributesNextHop;
            content.push_back(nextHopAttr);
            if (sType == EGP || _BGPSessions[sessionIndex]->getNextHopSelf()) {
                NetworkInterface *iftEntry = (elem).second->getLinkIntf();
                nextHopAttr->setValue(iftEntry->getProtocolData<Ipv4InterfaceData>()->getIPAddress());
            }
            else
                nextHopAttr->setValue(entry->getGateway());

            auto originAttr = new BgpUpdatePathAttributesOrigin;
            content.push_back(originAttr);
            originAttr->setValue((BgpSessionType)entry->getPathType());

            Ipv4Address netMask = entry->getNetmask();
            NLRI.prefix = entry->getDestination().doAnd(netMask);
            NLRI.length = (unsigned char)netMask.getNetmaskLength();

            (elem).second->sendUpdateMessage(content, NLRI);
        }
    }
}

void BgpRouter::updateSendProcess(BgpProcessResult type, SessionId sessionIndex, BgpIpv6RoutingTableEntry *entry)
{
    BgpAddressFamily ipv6Unicast = makeAddressFamily(AFI_IPV6, SAFI_UNICAST);
    for (auto& elem : _BGPSessions) {
        BgpSession *targetSession = elem.second;
        bool isSourceSession = elem.first == sessionIndex;
        bool isStartupAdvertisement = type == NEW_SESSION_ESTABLISHED;
        bool isOtherStartupSession = isStartupAdvertisement && !isSourceSession;

        if ((isSourceSession && !isStartupAdvertisement) ||
            isOtherStartupSession ||
            !targetSession->isEstablished() ||
            isInIpv6PrefixList(_prefixIpv6ListOUT, entry) != (unsigned long)-1 ||
            isInASList(_ASListOUT, entry))
            continue;

        if (!targetSession->hasNegotiatedAddressFamily(ipv6Unicast)) {
            EV_INFO << "Not advertising IPv6 route " << entry->getDestination() << "/"
                    << entry->getPrefixLength() << " to peer "
                    << targetSession->getPeerAddr().str(false)
                    << " because IPv6-unicast was not negotiated\n";
            continue;
        }

        BgpSessionType sourceSessionType = _BGPSessions[sessionIndex]->getType();
        if (entry->isIBgpLearned() && sourceSessionType == IGP && targetSession->getType() == IGP) {
            EV_INFO << "BGP Split Horizon: prevent advertisement of IPv6 network "
                    << entry->getDestination() << "/" << entry->getPrefixLength();
            continue;
        }

        std::vector<BgpUpdatePathAttributes *> content;

        auto originAttr = new BgpUpdatePathAttributesOrigin;
        content.push_back(originAttr);
        originAttr->setValue((BgpSessionType)entry->getPathType());

        unsigned int nbAS = entry->getASCount();
        auto asPath = new BgpUpdatePathAttributesAsPath();
        content.push_back(asPath);
        asPath->setValueArraySize(1);
        asPath->getValueForUpdate(0).setType(AS_SEQUENCE);
        asPath->getValueForUpdate(0).setLength(0);

        if (targetSession->getType() == EGP) {
            bool prependMyAs = nbAS == 0 || entry->getAS(0) != myAsId;
            asPath->getValueForUpdate(0).setAsValueArraySize(nbAS + (prependMyAs ? 1 : 0));
            asPath->getValueForUpdate(0).setLength(nbAS + (prependMyAs ? 1 : 0));
            unsigned int outputIndex = 0;
            if (prependMyAs) {
                asPath->getValueForUpdate(0).setAsValue(outputIndex, myAsId);
                outputIndex++;
            }
            for (unsigned int j = 0; j < nbAS; j++, outputIndex++)
                asPath->getValueForUpdate(0).setAsValue(outputIndex, entry->getAS(j));
        }
        else if (targetSession->getType() == IGP) {
            asPath->getValueForUpdate(0).setAsValueArraySize(nbAS);
            asPath->getValueForUpdate(0).setLength(nbAS);
            for (unsigned int j = 0; j < nbAS; j++)
                asPath->getValueForUpdate(0).setAsValue(j, entry->getAS(j));

            auto localPref = new BgpUpdatePathAttributesLocalPref();
            content.push_back(localPref);
            localPref->setLength(4);
            localPref->setValue(_BGPSessions[sessionIndex]->getLocalPreference());
        }
        asPath->setLength(2 + 2 * asPath->getValue(0).getAsValueArraySize());

        auto mpReach = new BgpUpdatePathAttributesMpReachNlri();
        content.push_back(mpReach);
        mpReach->setAfi(AFI_IPV6);
        mpReach->setSafi(SAFI_UNICAST);
        mpReach->setNextHopNetworkAddressLength(16);
        if (sourceSessionType == EGP || targetSession->getNextHopSelf()) {
            Ipv6Address nextHop = findGlobalIpv6Address(targetSession->getLinkIntf());
            if (nextHop.isUnspecified() && entry->getLearnedSessionId() == 0 && !entry->getNextHop().isUnspecified())
                nextHop = entry->getNextHop();
            if (nextHop.isUnspecified())
                nextHop = getGlobalIpv6Address(targetSession->getLinkIntf());
            mpReach->setNextHopIpv6Address(nextHop);
        }
        else
            mpReach->setNextHopIpv6Address(entry->getNextHop());
        mpReach->setNumberOfSnpas(0);

        BgpMpNlri nlri;
        nlri.length = entry->getPrefixLength();
        nlri.ipv6Prefix = entry->getDestination();
        mpReach->setNlriArraySize(1);
        mpReach->setNlri(0, nlri);
        mpReach->setLength(2 + 1 + 1 + 16 + 1 + 1 + (entry->getPrefixLength() + 7) / 8);

        targetSession->sendUpdateMessage(content);
    }
}

/*
 *  Delete BGP Routing entry, if the route deleted correctly return true, false else.
 *  Side effects when returns true:
 *      bgpRoutingTable changed, iterators on bgpRoutingTable will be invalid.
 */
bool BgpRouter::deleteBGPRoutingEntry(BgpRoutingTableEntry *entry)
{
    for (auto it = bgpRoutingTable.begin();
         it != bgpRoutingTable.end(); it++)
    {
        if (((*it)->getDestination().getInt() & (*it)->getNetmask().getInt()) ==
            (entry->getDestination().getInt() & entry->getNetmask().getInt()))
        {
            bgpRoutingTable.erase(it);
            rt->deleteRoute(entry);
            return true;
        }
    }
    return false;
}

/*return index of the Ipv4 table if the route is found, -1 else*/
int BgpRouter::isInRoutingTable(IIpv4RoutingTable *rtTable, Ipv4Address addr)
{
    for (int i = 0; i < rtTable->getNumRoutes(); i++) {
        const Ipv4Route *entry = rtTable->getRoute(i);
        if (Ipv4Address::maskedAddrAreEqual(addr, entry->getDestination(), entry->getNetmask())) {
            if (isDefaultRoute(entry) && addr.getInt() != 0)
                continue;
            else
                return i;
        }
    }
    return -1;
}

SessionId BgpRouter::findIdFromSocketConnId(std::map<SessionId, BgpSession *> sessions, int connId)
{
    for (auto& session : sessions) {
        TcpSocket *socket = (session).second->getSocket();
        if (socket->getSocketId() == connId) {
            return (session).first;
        }
    }
    return -1;
}

/*return index of the table if the route is found, -1 else*/
unsigned long BgpRouter::isInTable(std::vector<BgpRoutingTableEntry *> rtTable, BgpRoutingTableEntry *entry)
{
    for (unsigned long i = 0; i < rtTable.size(); i++) {
        BgpRoutingTableEntry *entryCur = rtTable[i];
        if ((entry->getDestination().getInt() & entry->getNetmask().getInt()) ==
            (entryCur->getDestination().getInt() & entryCur->getNetmask().getInt()))
        {
            return i;
        }
    }
    return -1;
}

unsigned long BgpRouter::isInIpv6PrefixList(const std::vector<BgpIpv6RoutingTableEntry *>& rtTable, const BgpIpv6RoutingTableEntry *entry) const
{
    for (unsigned long i = 0; i < rtTable.size(); i++) {
        BgpIpv6RoutingTableEntry *entryCur = rtTable[i];
        if (entry->getDestination().matches(entryCur->getDestination(), entryCur->getPrefixLength()))
            return i;
    }
    return -1;
}

/*return true if the AS is found, false else*/
bool BgpRouter::isInASList(std::vector<AsId> ASList, BgpRoutingTableEntry *entry)
{
    for (auto& elem : ASList) {
        for (unsigned int i = 0; i < entry->getASCount(); i++) {
            if ((elem) == entry->getAS(i)) {
                return true;
            }
        }
    }
    return false;
}

bool BgpRouter::isInASList(std::vector<AsId> ASList, BgpIpv6RoutingTableEntry *entry)
{
    for (auto& elem : ASList) {
        for (unsigned int i = 0; i < entry->getASCount(); i++) {
            if (elem == entry->getAS(i))
                return true;
        }
    }
    return false;
}

/*return true if OSPF exists, false else*/
bool BgpRouter::ospfExist(IIpv4RoutingTable *rtTable)
{
    for (int i = 0; i < rtTable->getNumRoutes(); i++) {
        if (rtTable->getRoute(i)->getSourceType() == IRoute::OSPF) {
            return true;
        }
    }
    return false;
}

/*return sessionID if the session is found, -1 else*/
SessionId BgpRouter::findNextSession(BgpSessionType type, bool startSession)
{
    SessionId sessionID = -1;
    for (auto& elem : _BGPSessions) {
        if ((elem).second->getType() == type && !(elem).second->isEstablished()) {
            sessionID = (elem).first;
            break;
        }
    }
    if (startSession == true && type == IGP && sessionID != static_cast<SessionId>(-1)) {
        // note: if the internal peer is not directly-connected to us, then we should know how to reach it.
        // this is done with the help of an intra-AS routing protocol (RIP, OSPF, EIGRP).
        NetworkInterface *linkIntf = rt->getInterfaceForDestAddr(_BGPSessions[sessionID]->getPeerAddr());
        if (linkIntf == nullptr)
            throw cRuntimeError("No configuration interface for peer address: %s", _BGPSessions[sessionID]->getPeerAddr().str().c_str());

        _BGPSessions[sessionID]->setlinkIntf(linkIntf);
        _BGPSessions[sessionID]->startConnection();
    }
    return sessionID;
}

SessionId BgpRouter::findIdFromPeerAddr(std::map<SessionId, BgpSession *> sessions, Ipv4Address peerAddr)
{
    for (auto& session : sessions) {
        if ((session).second->getPeerAddr().equals(peerAddr))
            return (session).first;
    }
    return -1;
}

void BgpRouter::printOpenMessage(const BgpOpenMessage& openMsg)
{
    EV_INFO << "  My AS: " << openMsg.getMyAS() << "\n";
    EV_INFO << "  Hold time: " << openMsg.getHoldTime() << "s \n";
    EV_INFO << "  BGP Id: " << openMsg.getBGPIdentifier() << "\n";
    if (openMsg.getOptionalParameterArraySize() == 0)
        EV_INFO << "  Optional parameters: empty \n";
    for (size_t i = 0; i < openMsg.getOptionalParameterArraySize(); i++) {
        auto optParam = openMsg.getOptionalParameter(i);
        ASSERT(optParam != nullptr);
        EV_INFO << "  Optional parameter " << i + 1 << ": \n";
        EV_INFO << "    Parameter type: " << optParam->getParameterType() << "\n";
        EV_INFO << "    Parameter length: " << optParam->getParameterValueLength() << "\n";
        if (optParam->getParameterType() == BGP_OPTIONAL_PARAMETER_CAPABILITIES) {
            auto capabilities = dynamic_cast<const BgpOptionalParameterCapabilities *>(optParam);
            if (capabilities != nullptr) {
                for (size_t j = 0; j < capabilities->getCapabilityArraySize(); j++) {
                    auto capability = capabilities->getCapability(j);
                    EV_INFO << "    Capability " << j + 1 << ": code " << (int)capability->getCapabilityCode()
                            << " length " << (int)capability->getCapabilityLength();
                    if (capability->getCapabilityCode() == BGP_CAPABILITY_MULTIPROTOCOL) {
                        auto multiprotocol = dynamic_cast<const BgpCapabilityMultiprotocol *>(capability);
                        if (multiprotocol != nullptr) {
                            auto family = makeAddressFamily(multiprotocol->getAfi(), multiprotocol->getSafi());
                            EV_INFO << " " << addressFamilyToString(family);
                        }
                    }
                    EV_INFO << "\n";
                }
            }
        }
    }
}

void BgpRouter::printUpdateMessage(const BgpUpdateMessage& updateMsg)
{
    if (updateMsg.getWithdrawnRoutesArraySize() == 0)
        EV_INFO << "  Withdrawn routes: empty \n";
    for (size_t i = 0; i < updateMsg.getWithdrawnRoutesArraySize(); i++) {
        const BgpUpdateWithdrawnRoutes& withdrwan = updateMsg.getWithdrawnRoutes(i);
        EV_INFO << "  Withdrawn route " << i + 1 << ": \n";
        EV_INFO << "    length: " << (int)withdrwan.length << "\n";
        EV_INFO << "    prefix: " << withdrwan.prefix << "\n";
    }
    if (updateMsg.getPathAttributesArraySize() == 0)
        EV_INFO << "  Path attribute: empty \n";
    for (size_t i = 0; i < updateMsg.getPathAttributesArraySize(); i++) {
        EV_INFO << "  Path attribute " << i + 1 << ": [len:" << updateMsg.getPathAttributes(i)->getLength() << "]\n";
        switch (updateMsg.getPathAttributes(i)->getTypeCode()) {
            case BgpUpdateAttributeTypeCode::ORIGIN: {
                auto& attr = *check_and_cast<const BgpUpdatePathAttributesOrigin *>(updateMsg.getPathAttributes(i));
                EV_INFO << "    ORIGIN: " << BgpSession::getTypeString(attr.getValue()) << "\n";
                break;
            }
            case BgpUpdateAttributeTypeCode::AS_PATH: {
                auto& asPath = *check_and_cast<const BgpUpdatePathAttributesAsPath *>(updateMsg.getPathAttributes(i));
                EV_INFO << "    AS_PATH:";
                for (size_t k = 0; k < asPath.getValueArraySize(); k++) {
                    const BgpAsPathSegment& asPathVal = asPath.getValue(k);
                    for (size_t n = 0; n < asPathVal.getAsValueArraySize(); n++) {
                        EV_INFO << " " << asPathVal.getAsValue(n);
                    }
                }
                EV_INFO << "\n";
                break;
            }
            case BgpUpdateAttributeTypeCode::NEXT_HOP: {
                auto& attr = *check_and_cast<const BgpUpdatePathAttributesNextHop *>(updateMsg.getPathAttributes(i));
                EV_INFO << "    NEXT_HOP: " << attr.getValue().str(false) << "\n";
                break;
            }
            case BgpUpdateAttributeTypeCode::LOCAL_PREF: {
                auto& attr = *check_and_cast<const BgpUpdatePathAttributesLocalPref *>(updateMsg.getPathAttributes(i));
                EV_INFO << "    LOCAL_PREF: " << attr.getValue() << "\n";
                break;
            }
            case BgpUpdateAttributeTypeCode::ATOMIC_AGGREGATE: {
                auto& attr = *check_and_cast<const BgpUpdatePathAttributesAtomicAggregate *>(updateMsg.getPathAttributes(i));
                (void)attr;
                EV_INFO << "    ATOMIC_AGGREGATE" << "\n";
                break;
            }
            case BgpUpdateAttributeTypeCode::AGGREGATOR: {
                auto& attr = *check_and_cast<const BgpUpdatePathAttributesAggregator *>(updateMsg.getPathAttributes(i));
                EV_INFO << "    AGGREGATOR: " << attr.getAsNumber() << ", " << attr.getBgpSpeaker() << "\n";
                break;
            }
            case BgpUpdateAttributeTypeCode::MULTI_EXIT_DISC: {
                auto& attr = *check_and_cast<const BgpUpdatePathAttributesMultiExitDisc *>(updateMsg.getPathAttributes(i));
                EV_INFO << "    MULTI_EXIT_DISC: " << attr.getValue() << "\n";
                break;
            }
            case BgpUpdateAttributeTypeCode::MP_REACH_NLRI: {
                auto& attr = *check_and_cast<const BgpUpdatePathAttributesMpReachNlri *>(updateMsg.getPathAttributes(i));
                EV_INFO << "    MP_REACH_NLRI: AFI " << attr.getAfi() << " SAFI " << attr.getSafi()
                        << " next hop " << attr.getNextHopIpv6Address()
                        << " NLRI count " << attr.getNlriArraySize() << "\n";
                for (size_t routeIndex = 0; routeIndex < attr.getNlriArraySize(); routeIndex++) {
                    const BgpMpNlri& nlri = attr.getNlri(routeIndex);
                    if (attr.getAfi() == AFI_IPV6)
                        EV_INFO << "      NLRI: " << nlri.ipv6Prefix << "/" << (int)nlri.length << "\n";
                    else
                        EV_INFO << "      NLRI: " << nlri.ipv4Prefix << "/" << (int)nlri.length << "\n";
                }
                break;
            }
            case BgpUpdateAttributeTypeCode::MP_UNREACH_NLRI: {
                auto& attr = *check_and_cast<const BgpUpdatePathAttributesMpUnreachNlri *>(updateMsg.getPathAttributes(i));
                EV_INFO << "    MP_UNREACH_NLRI: AFI " << attr.getAfi() << " SAFI " << attr.getSafi()
                        << " withdrawn count " << attr.getWithdrawnRoutesArraySize() << "\n";
                for (size_t routeIndex = 0; routeIndex < attr.getWithdrawnRoutesArraySize(); routeIndex++) {
                    const BgpMpNlri& nlri = attr.getWithdrawnRoutes(routeIndex);
                    if (attr.getAfi() == AFI_IPV6)
                        EV_INFO << "      Withdrawn NLRI: " << nlri.ipv6Prefix << "/" << (int)nlri.length << "\n";
                    else
                        EV_INFO << "      Withdrawn NLRI: " << nlri.ipv4Prefix << "/" << (int)nlri.length << "\n";
                }
                break;
            }
        }
    }

    if (updateMsg.getNLRIArraySize() > 0) {
        auto NLRI_Base = updateMsg.getNLRI(0);
        EV_INFO << "  Network Layer Reachability Information (NLRI): \n";
        EV_INFO << "    NLRI length: " << (int)NLRI_Base.length << "\n";
        EV_INFO << "    NLRI prefix: " << NLRI_Base.prefix << "\n";
    }
}

//void printNotificationMessage(const BgpNotificationMessage& notificationMsg)
//{
//
//}

void BgpRouter::printKeepAliveMessage(const BgpKeepAliveMessage& keepAliveMsg)
{
    // TODO add code once implemented
}

bool BgpRouter::isRouteExcluded(const Ipv4Route& rtEntry)
{
    // all host-specific routes are excluded
    if (rtEntry.getNetmask() == Ipv4Address::ALLONES_ADDRESS)
        return true;

    // all static routes are excluded
    if (rtEntry.getSourceType() == IRoute::MANUAL)
        return true;

    // all BGP routes are excluded
    if (rtEntry.getSourceType() == IRoute::BGP)
        return true;

    // all RIP routes are excluded when redistributeRip is false
    if (rtEntry.getSourceType() == IRoute::RIP) {
        if (!redistributeRip)
            return true;
        else
            return false;
    }

    if (rtEntry.getSourceType() == IRoute::OSPF) {
        // all OSPF routes are excluded when redistributeOspf is false
        if (!redistributeOspf)
            return true;

        auto entry = static_cast<const ospfv2::Ospfv2RoutingTableEntry *>(&rtEntry);
        ASSERT(entry);

        if (entry->getPathType() == ospfv2::Ospfv2RoutingTableEntry::INTRAAREA) {
            if (redistributeOspfType.intraArea)
                return false;
            else
                return true;
        }

        if (entry->getPathType() == ospfv2::Ospfv2RoutingTableEntry::INTERAREA) {
            if (redistributeOspfType.interArea)
                return false;
            else
                return true;
        }

        int externalType = checkExternalRoute(&rtEntry);

        if (externalType == 1) {
            if (redistributeOspfType.externalType1)
                return false;
            else
                return true;
        }

        if (externalType == 2) {
            if (redistributeOspfType.externalType2)
                return false;
            else
                return true;
        }

        // exclude all other OSPF route types
        return true;
    }

    if (rtEntry.getSourceType() == IRoute::IFACENETMASK) {
        if (rtEntry.getInterface()->isLoopback())
            return true;
        else if (!redistributeRip && !redistributeOspf)
            return true;
        else
            return isExternalAddress(rtEntry);
    }

    // exclude all other routes
    return true;
}

bool BgpRouter::isExternalAddress(const Ipv4Route& rtEntry)
{
    for (auto& session : _BGPSessions) {
        if (session.second->getType() == EGP) {
            NetworkInterface *exIntf = rt->getInterfaceForDestAddr(session.second->getPeerAddr());
            if (exIntf == rtEntry.getInterface())
                return true;
        }
    }

    return false;
}

bool BgpRouter::isDefaultRoute(const Ipv4Route *entry) const
{
    if (entry->getDestination().getInt() == 0 && entry->getNetmask().getInt() == 0)
        return true;
    return false;
}

bool BgpRouter::isReachable(const Ipv4Address addr) const
{
    if (addr.isUnspecified())
        return true;

    for (int i = 0; i < rt->getNumRoutes(); i++) {
        Ipv4Route *route = rt->getRoute(i);
        if (!isDefaultRoute(route) && route->getSourceType() != IRoute::BGP) {
            if (addr.doAnd(route->getNetmask()) == route->getDestination().doAnd(route->getNetmask()))
                return true;
        }
    }

    return false;
}

} // namespace bgp

} // namespace inet
