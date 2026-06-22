//
// Copyright (C) 2010 Helene Lageber
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#ifndef __INET_BGPROUTINGTABLEENTRY_H
#define __INET_BGPROUTINGTABLEENTRY_H

#include "inet/networklayer/ipv4/Ipv4RoutingTable.h"
#include "inet/networklayer/ipv6/Ipv6Route.h"
#include "inet/networklayer/ipv6/Ipv6RoutingTable.h"
#include "inet/routing/bgpv4/BgpCommon.h"

namespace inet {

namespace bgp {

class INET_API BgpRoutingTableEntry : public Ipv4Route
{
  private:
    enum { DEFAULT_COST = 1} ;
    typedef unsigned char RoutingPathType;
    // destinationID is RoutingEntry::host
    // addressMask is RoutingEntry::netmask
    RoutingPathType _pathType = INCOMPLETE;
    std::vector<AsId> _ASList;
    int localPreference = 0;
    bool IBGP_learned = false;

  public:
    BgpRoutingTableEntry(void);
    BgpRoutingTableEntry(const Ipv4Route *entry);
    virtual ~BgpRoutingTableEntry(void) {}

    void setPathType(RoutingPathType type) { _pathType = type; }
    RoutingPathType getPathType(void) const { return _pathType; }
    static const std::string getPathTypeString(RoutingPathType type);
    void addAS(AsId newAS) { _ASList.push_back(newAS); }
    unsigned int getASCount(void) const { return _ASList.size(); }
    AsId getAS(unsigned int index) const { return _ASList[index]; }
    int getLocalPreference(void) const { return localPreference; }
    void setLocalPreference(int l) { localPreference = l; }
    bool isIBgpLearned(void) { return IBGP_learned; }
    void setIBgpLearned(bool i) { IBGP_learned = i; }
    virtual std::string str() const;
};

class INET_API BgpIpv6RoutingTableEntry : public Ipv6Route
{
  private:
    enum { DEFAULT_COST = 1 };
    typedef unsigned char RoutingPathType;
    RoutingPathType pathType = INCOMPLETE;
    std::vector<AsId> ASList;
    int localPreference = 0;
    bool iBgpLearned = false;
    SessionId learnedSessionId = 0;

  public:
    BgpIpv6RoutingTableEntry();
    BgpIpv6RoutingTableEntry(const Ipv6Address& destination, int prefixLength);
    virtual ~BgpIpv6RoutingTableEntry() {}

    const Ipv6Address& getDestination() const { return getDestPrefix(); }
    void setDestination(const Ipv6Address& destination) { Ipv6Route::setDestination(destination); }
    void setPathType(RoutingPathType type) { pathType = type; }
    RoutingPathType getPathType() const { return pathType; }
    void addAS(AsId newAS) { ASList.push_back(newAS); }
    unsigned int getASCount() const { return ASList.size(); }
    AsId getAS(unsigned int index) const { return ASList[index]; }
    int getLocalPreference() const { return localPreference; }
    void setLocalPreference(int localPreference) { this->localPreference = localPreference; }
    bool isIBgpLearned() const { return iBgpLearned; }
    void setIBgpLearned(bool iBgpLearned) { this->iBgpLearned = iBgpLearned; }
    SessionId getLearnedSessionId() const { return learnedSessionId; }
    void setLearnedSessionId(SessionId sessionId) { learnedSessionId = sessionId; }
    virtual std::string str() const override;
};

inline BgpRoutingTableEntry::BgpRoutingTableEntry(void)
{
    setNetmask(Ipv4Address::ALLONES_ADDRESS);
    setMetric(DEFAULT_COST);
    setSourceType(IRoute::BGP);
}

inline BgpRoutingTableEntry::BgpRoutingTableEntry(const Ipv4Route *entry)
{
    setDestination(entry->getDestination());
    setNetmask(entry->getNetmask());
    setGateway(entry->getGateway());
    setInterface(entry->getInterface());
    setMetric(DEFAULT_COST);
    setSourceType(IRoute::BGP);
    setAdminDist(dBGPExternal);
}

inline const std::string BgpRoutingTableEntry::getPathTypeString(RoutingPathType type)
{
    if (type == IGP)
        return "IGP";
    else if (type == EGP)
        return "EGP";
    else if (type == INCOMPLETE)
        return "INCOMPLETE";

    return "Unknown";
}

inline std::ostream& operator<<(std::ostream& out, BgpRoutingTableEntry& entry)
{
    if (entry.getDestination().isUnspecified())
        out << "0.0.0.0";
    else
        out << entry.getDestination();
    out << "/";
    if (entry.getNetmask().isUnspecified())
        out << "0";
    else
        out << entry.getNetmask().getNetmaskLength();
    out << " nextHop: " << entry.getGateway().str(false)
        << " cost: " << entry.getMetric()
        << " if: " << entry.getInterfaceName()
        << " origin: " << BgpRoutingTableEntry::getPathTypeString(entry.getPathType());
    if (entry.isIBgpLearned())
        out << " localPref: " << entry.getLocalPreference();
    out << " ASlist: ";
    for (unsigned int i = 0; i < entry.getASCount(); i++)
        out << entry.getAS(i) << ' ';

    return out;
}

inline std::string BgpRoutingTableEntry::str() const
{
    std::stringstream out;
    out << getSourceTypeAbbreviation();
    out << " ";
    if (getDestination().isUnspecified())
        out << "0.0.0.0";
    else
        out << getDestination();
    out << "/";
    if (getNetmask().isUnspecified())
        out << "0";
    else
        out << getNetmask().getNetmaskLength();
    out << " gw:";
    if (getGateway().isUnspecified())
        out << "*  ";
    else
        out << getGateway() << "  ";
    if (getRoutingTable() && getRoutingTable()->isAdminDistEnabled())
        out << "AD:" << getAdminDist() << "  ";
    out << "metric:" << getMetric() << "  ";
    out << "if:";
    if (!getInterface())
        out << "*";
    else
        out << getInterfaceName();

    out << " origin: " << BgpRoutingTableEntry::getPathTypeString(_pathType);
    if (IBGP_learned)
        out << " localPref: " << getLocalPreference();
    out << " ASlist: ";
    for (auto& element : _ASList)
        out << element << ' ';

    return out.str();
}

inline BgpIpv6RoutingTableEntry::BgpIpv6RoutingTableEntry() :
    Ipv6Route(Ipv6Address(), 128, IRoute::BGP)
{
    setMetric(DEFAULT_COST);
    setAdminDist(Ipv6Route::dBGPExternal);
}

inline BgpIpv6RoutingTableEntry::BgpIpv6RoutingTableEntry(const Ipv6Address& destination, int prefixLength) :
    Ipv6Route(destination, prefixLength, IRoute::BGP)
{
    setMetric(DEFAULT_COST);
    setAdminDist(Ipv6Route::dBGPExternal);
}

inline std::ostream& operator<<(std::ostream& out, BgpIpv6RoutingTableEntry& entry)
{
    out << entry.getDestination() << "/" << entry.getPrefixLength()
        << " nextHop: " << entry.getNextHop()
        << " cost: " << entry.getMetric()
        << " origin: " << BgpRoutingTableEntry::getPathTypeString(entry.getPathType());
    if (entry.isIBgpLearned())
        out << " localPref: " << entry.getLocalPreference();
    out << " ASlist: ";
    for (unsigned int i = 0; i < entry.getASCount(); i++)
        out << entry.getAS(i) << ' ';
    return out;
}

inline std::string BgpIpv6RoutingTableEntry::str() const
{
    std::stringstream out;
    out << getSourceTypeAbbreviation() << " ";
    out << getDestination() << "/" << getPrefixLength();
    out << " gw:";
    if (getNextHop().isUnspecified())
        out << "*  ";
    else
        out << getNextHop() << "  ";
    if (getRoutingTable() && getRoutingTable()->isAdminDistEnabled())
        out << "AD:" << getAdminDist() << "  ";
    out << "metric:" << getMetric() << "  ";
    out << "origin: " << BgpRoutingTableEntry::getPathTypeString(pathType);
    if (iBgpLearned)
        out << " localPref: " << localPreference;
    out << " ASlist: ";
    for (auto& element : ASList)
        out << element << ' ';
    return out.str();
}

} // namespace bgp

} // namespace inet

#endif
