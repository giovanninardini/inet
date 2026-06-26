//
// Copyright (C) 2010 Helene Lageber
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#ifndef __INET_BGPROUTER_H
#define __INET_BGPROUTER_H

#include "inet/common/socket/SocketMap.h"
#include "inet/networklayer/contract/ipv4/Ipv4Address.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/routing/bgpv4/BgpCommon.h"
#include "inet/routing/bgpv4/BgpRoutingTableEntry.h"
#include "inet/routing/bgpv4/bgpmessage/BgpHeader_m.h"
#include "inet/routing/bgpv4/bgpmessage/BgpUpdate.h"
#include "inet/routing/ospfv2/Ospfv2.h"
#include "inet/transportlayer/contract/tcp/TcpSocket.h"

namespace inet {

namespace bgp {

class BgpSession;

class INET_API BgpRouter : public TcpSocket::BufferingCallback
{
  private:
    IInterfaceTable *ift = nullptr;
    IIpv4RoutingTable *rt = nullptr;
    Ipv6RoutingTable *rt6 = nullptr;
    cSimpleModule *bgpModule = nullptr;
    ospfv2::Ospfv2 *ospfModule = nullptr;
    AsId myAsId = 0;
    bool redistributeInternal = false;
    bool redistributeRip = false;
    bool redistributeOspf = false;
    bool shuttingDown = false;
    bool aborting = false;
    struct redistributeOspfType_t {
        bool interArea;
        bool intraArea;
        bool externalType1;
        bool externalType2;
    };
    redistributeOspfType_t redistributeOspfType = {};
    SocketMap _socketMap;
    SessionId _currSessionId = 0;
    std::map<SessionId, BgpSession *> _BGPSessions;
    // Configured local BGP IPv4 endpoint addresses; kept separately so
    // lifecycle crash cleanup can still identify peers after interfaces go down.
    std::vector<Ipv4Address> localBgpAddresses;
    uint32_t numEgpSessions = 0;
    uint32_t numIgpSessions = 0;
    Ipv4Address internalAddress = Ipv4Address::UNSPECIFIED_ADDRESS;

    typedef std::vector<BgpRoutingTableEntry *> RoutingTableEntryVector;
    typedef std::vector<BgpIpv6RoutingTableEntry *> Ipv6RoutingTableEntryVector;
    RoutingTableEntryVector bgpRoutingTable; // The Loc-RIB selected BGP IPv4 routing table
    Ipv6RoutingTableEntryVector bgpIpv6RoutingTable; // The Loc-RIB selected MP-BGP IPv6 routing table
    RoutingTableEntryVector adjRibIn; // Peer-learned IPv4 route candidates, keyed by session and prefix
    Ipv6RoutingTableEntryVector adjRibInIpv6; // Peer-learned IPv6 route candidates, keyed by session and prefix
    // Router-level timers for optional local IPv6 Network withdrawTime.
    // Unlike session FSM timers, these are not associated with a peer session.
    std::map<cMessage *, BgpIpv6RoutingTableEntry *> ipv6WithdrawRoutes;
    std::vector<Ipv4Address> advertiseList;
    std::vector<Ipv6Address> advertiseIpv6List;
    std::vector<BgpAddressFamily> addressFamilies;
    RoutingTableEntryVector _prefixListIN;
    RoutingTableEntryVector _prefixListOUT;
    RoutingTableEntryVector _prefixListINOUT; // store union of pointers in _prefixListIN and _prefixListOUT
    Ipv6RoutingTableEntryVector _prefixIpv6ListIN;
    Ipv6RoutingTableEntryVector _prefixIpv6ListOUT;
    Ipv6RoutingTableEntryVector _prefixIpv6ListINOUT; // store union of pointers in _prefixIpv6ListIN and _prefixIpv6ListOUT
    std::vector<AsId> _ASListIN;
    std::vector<AsId> _ASListOUT;

  public:
    enum { TCP_PORT = 179 };
    BgpRouter(cSimpleModule *bgpModule, IInterfaceTable *ift, IIpv4RoutingTable *rt, Ipv6RoutingTable *rt6 = nullptr);
    virtual ~BgpRouter();

    RouterId getRouterId() { return rt->getRouterId(); }
    void setAsId(AsId myAsId) { this->myAsId = myAsId; }
    AsId getAsId() { return myAsId; }
    int getNumBgpSessions() { return _BGPSessions.size(); }
    int getNumEgpSessions() { return numEgpSessions; }
    int getNumIgpSessions() { return numIgpSessions; }
    void setDefaultConfig();
    Ipv4Address getInternalAddress() { return internalAddress; }
    void setInternalAddress(Ipv4Address x) { internalAddress = x; }
    bool getRedistributeInternal() { return redistributeInternal; }
    void setRedistributeInternal(bool x) { this->redistributeInternal = x; }
    bool getRedistributeRip() { return redistributeRip; }
    void setRedistributeRip(bool x) { this->redistributeRip = x; }
    bool getRedistributeOspf() { return redistributeOspf; }
    void setRedistributeOspf(std::string x);
    void printSessionSummary();
    void addWatches();
    void recordStatistics();
    void closeSessions(bool abort);
    void notifyPeersOfLocalSessionFailure();
    void removeBgpRoutes(bool abort);
    void removeInstalledIpv6Routes();
    void removeRoutesLearnedFromSession(SessionId sessionId);
    void processIpv6WithdrawTimer(cMessage *timer);

    SessionId createEbgpSession(const char *peerAddr, SessionInfo& externalInfo);
    SessionId createIbgpSession(const char *peerAddr);
    void setTimer(SessionId id, simtime_t *delayTab);
    void setSocketListen(SessionId id);
    void addToAdvertiseList(Ipv4Address address);
    void addToAdvertiseIpv6List(const Ipv6Address& address, int prefixLength, const Ipv6Address& nextHop, simtime_t withdrawTime = -1);
    void addAddressFamily(const BgpAddressFamily& family);
    void setPeerAddressFamilies(Ipv4Address peer, const std::vector<BgpAddressFamily>& families);
    void applyAddressFamilyDefaults();
    void addToPrefixList(std::string nodeName, BgpRoutingTableEntry *entry);
    void addToIpv6PrefixList(std::string nodeName, BgpIpv6RoutingTableEntry *entry);
    void addToAsList(std::string nodeName, AsId id);
    void setNextHopSelf(Ipv4Address peer, bool nextHopSelf);
    void setLocalPreference(Ipv4Address peer, int localPref);
    bool isExternalAddress(const Ipv4Route& rtEntry);
    void processMessageFromTCP(cMessage *msg);

    void printOpenMessage(const BgpOpenMessage& msg);
    void printUpdateMessage(const BgpUpdateMessage& msg);
//    void printNotificationMessage(const BgpNotificationMessage& msg);
    void printKeepAliveMessage(const BgpKeepAliveMessage& msg);

  protected:
    /** @name TcpSocket::ICallback callback methods */
    //@{
    virtual void socketDataArrived(TcpSocket *socket) override;
    virtual void socketDataArrived(TcpSocket *socket, Packet *packet, bool urgent) override;
    virtual void socketAvailable(TcpSocket *socket, TcpAvailableInfo *availableInfo) override { socket->accept(availableInfo->getNewSocketId()); } // TODO
    virtual void socketEstablished(TcpSocket *socket) override;
    virtual void socketPeerClosed(TcpSocket *socket) override;
    virtual void socketClosed(TcpSocket *socket) override {}
    virtual void socketFailure(TcpSocket *socket, int code) override;
    virtual void socketStatusArrived(TcpSocket *socket, TcpStatusInfo *status) override {}
    virtual void socketDeleted(TcpSocket *socket) override {}
    //@}

    friend class BgpSession;
    // functions used by the BgpSession class
    void getScheduleAt(simtime_t t, cMessage *msg) { bgpModule->scheduleAt(t, msg); }
    void getCancelAndDelete(cMessage *msg) { bgpModule->cancelAndDelete(msg); }
    cMessage *getCancelEvent(cMessage *msg) { return bgpModule->cancelEvent(msg); }
    IIpv4RoutingTable *getIPRoutingTable() { return rt; }
    std::vector<BgpRoutingTableEntry *> getBGPRoutingTable() { return bgpRoutingTable; }
    std::vector<BgpIpv6RoutingTableEntry *> getBGPIpv6RoutingTable() { return bgpIpv6RoutingTable; }

    bool isLifecycleNode() const;

    /**
     * \brief active listenSocket for a given session (used by fsm)
     */
    void listenConnectionFromPeer(SessionId sessionID);
    /**
     * \brief active TcpConnection for a given session (used by fsm)
     */
    void openTCPConnectionToPeer(SessionId sessionID);
    /**
     * \brief RFC 4271, 9.2 : Update-Send Process / Sent or not new UPDATE messages to its peers
     */
    void updateSendProcess(BgpProcessResult decisionProcessResult, SessionId sessionIndex, BgpRoutingTableEntry *entry);
    void updateSendProcess(BgpProcessResult decisionProcessResult, SessionId sessionIndex, BgpIpv6RoutingTableEntry *entry);
    /**
     * \brief find the next SessionId compared to his type and start this session if boolean is true
     */
    SessionId findNextSession(BgpSessionType type, bool startSession = false);

  private:

    void processChunks(const BgpHeader& ptrHdr);
    void processMessage(const BgpOpenMessage& msg);
    void processMessage(const BgpKeepAliveMessage& msg);
    void processMessage(const BgpUpdateMessage& msg);

    bool deleteBGPRoutingEntry(BgpRoutingTableEntry *entry);

    /**
     * \brief RFC 4271: 9.1. : Decision Process used when an UPDATE message is received
     *  As matches, routes are sent or not to UpdateSentProcess
     *  The result can be ROUTE_DESTINATION_CHANGED, NEW_ROUTE_ADDED or 0 if no routingTable modification
     */
    BgpProcessResult decisionProcess(const BgpUpdateMessage& msg, BgpRoutingTableEntry *entry, SessionId sessionIndex);

    /**
     * \brief RFC 4271: 9.1.2.2 Breaking Ties used when BGP speaker may have several routes
     *  to the same destination that have the same degree of preference.
     *
     * \return bool, true if this process changed the route, false else
     */
    bool tieBreakingProcess(BgpRoutingTableEntry *oldEntry, BgpRoutingTableEntry *entry);
    bool tieBreakingProcess(BgpIpv6RoutingTableEntry *oldEntry, BgpIpv6RoutingTableEntry *entry);

    void withdrawIpv4Route(BgpRoutingTableEntry *entry, SessionId sourceSessionIndex, bool fromPeer);
    void sendWithdrawNlri(BgpRoutingTableEntry *entry, SessionId sourceSessionIndex, bool fromPeer);
    BgpRoutingTableEntry *findIpv4Route(const Ipv4Address& prefix, const Ipv4Address& netmask, SessionId learnedSessionId) const;
    BgpRoutingTableEntry *findAdjRibInIpv4Route(const Ipv4Address& prefix, const Ipv4Address& netmask, SessionId learnedSessionId) const;
    BgpRoutingTableEntry *removeAdjRibInIpv4Route(const Ipv4Address& prefix, const Ipv4Address& netmask, SessionId learnedSessionId);
    BgpProcessResult recomputeIpv4Route(const Ipv4Address& prefix, const Ipv4Address& netmask, SessionId sourceSessionIndex, bool fromPeer, BgpRoutingTableEntry *&selectedRoute);

    bool isInASList(std::vector<AsId> ASList, BgpRoutingTableEntry *entry);
    bool isInASList(std::vector<AsId> ASList, BgpIpv6RoutingTableEntry *entry);
    unsigned long isInTable(std::vector<BgpRoutingTableEntry *> rtTable, BgpRoutingTableEntry *entry);
    unsigned long isInIpv6PrefixList(const std::vector<BgpIpv6RoutingTableEntry *>& rtTable, const BgpIpv6RoutingTableEntry *entry) const;

    bool ospfExist(IIpv4RoutingTable *rtTable);
    // check if the route is in OSPF external Ipv4RoutingTable
    int checkExternalRoute(const Ipv4Route *ospfRoute) { return ospfModule->checkExternalRoute(ospfRoute->getDestination()); }
    BgpProcessResult asLoopDetection(BgpRoutingTableEntry *entry, AsId myAS);
    BgpProcessResult asLoopDetection(BgpIpv6RoutingTableEntry *entry, AsId myAS);

    /**
     * \brief Decision process for RFC 4760 MP-BGP IPv6 routes.
     *  This follows the RFC 4271 route selection model, while MP_REACH_NLRI
     *  provides the IPv6 NLRI and next hop. The receive path normalizes UPDATE
     *  attributes into the IPv6 BGP route entry before this method stores and
     *  installs it.
     *
     * \return NEW_ROUTE_ADDED or 0 if no routingTable modification
     */
    BgpProcessResult decisionProcess(const BgpUpdateMessage& msg, BgpIpv6RoutingTableEntry *entry, SessionId sessionIndex);
    bool isInIpv6Table(const std::vector<BgpIpv6RoutingTableEntry *>& rtTable, const BgpIpv6RoutingTableEntry *entry) const;
    unsigned long findIpv6TableIndex(const std::vector<BgpIpv6RoutingTableEntry *>& rtTable, const BgpIpv6RoutingTableEntry *entry) const;
    void processMpReachNlri(const BgpUpdateMessage& msg, const BgpUpdatePathAttributesMpReachNlri& mpReach, SessionId sessionIndex);
    void processMpUnreachNlri(const BgpUpdatePathAttributesMpUnreachNlri& mpUnreach, SessionId sessionIndex);
    void installIpv6Route(BgpIpv6RoutingTableEntry *entry, SessionId sessionIndex);
    void removeInstalledIpv6Route(BgpIpv6RoutingTableEntry *entry);
    void withdrawIpv6Route(BgpIpv6RoutingTableEntry *entry, SessionId sourceSessionIndex, bool fromPeer);
    void sendMpUnreachNlri(BgpIpv6RoutingTableEntry *entry, SessionId sourceSessionIndex, bool fromPeer);
    BgpIpv6RoutingTableEntry *findIpv6Route(const Ipv6Address& prefix, int prefixLength, SessionId learnedSessionId) const;
    BgpIpv6RoutingTableEntry *findAdjRibInIpv6Route(const Ipv6Address& prefix, int prefixLength, SessionId learnedSessionId) const;
    BgpIpv6RoutingTableEntry *removeAdjRibInIpv6Route(const Ipv6Address& prefix, int prefixLength, SessionId learnedSessionId);
    BgpProcessResult recomputeIpv6Route(const Ipv6Address& prefix, int prefixLength, SessionId sourceSessionIndex, bool fromPeer, BgpIpv6RoutingTableEntry *&selectedRoute);

    int isInRoutingTable(IIpv4RoutingTable *rtTable, Ipv4Address addr);
    SessionId findIdFromPeerAddr(std::map<SessionId, BgpSession *> sessions, Ipv4Address peerAddr);
    SessionId findIdFromSocketConnId(std::map<SessionId, BgpSession *> sessions, int connId);
    bool isRouteExcluded(const Ipv4Route& rtEntry);
    bool isDefaultRoute(const Ipv4Route *entry) const;
    bool isReachable(const Ipv4Address addr) const;
};

} // namespace bgp

} // namespace inet

#endif
