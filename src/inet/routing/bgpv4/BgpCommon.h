//
// Copyright (C) 2010 Helene Lageber
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#ifndef __INET_BGPCOMMON_H
#define __INET_BGPCOMMON_H

#include <vector>

#include "inet/networklayer/common/NetworkInterface.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/routing/bgpv4/BgpCommon_m.h"
#include "inet/transportlayer/contract/tcp/TcpSocket.h"

namespace inet {
namespace bgp {

typedef Ipv4Address RouterId;
typedef Ipv4Address NextHop;
typedef unsigned short AsId;
typedef unsigned long SessionId;

struct BgpAddressFamily
{
    uint16_t afi = 0;
    uint8_t safi = 0;

    bool operator==(const BgpAddressFamily& other) const { return afi == other.afi && safi == other.safi; }
    bool operator<(const BgpAddressFamily& other) const { return afi < other.afi || (afi == other.afi && safi < other.safi); }
};

struct SessionInfo
{
    SessionId sessionID = 0;
    BgpSessionType sessionType = INCOMPLETE;
    AsId ASValue = 0;
    Ipv4Address routerID;
    Ipv4Address peerAddr;
    Ipv4Address myAddr;
    bool nextHopSelf = false;
    int localPreference = 0;
    bool checkConnection = false;
    int ebgpMultihop = 0;
    NetworkInterface *linkIntf = nullptr;
    TcpSocket *socket = nullptr;
    TcpSocket *socketListen = nullptr;
    bool sessionEstablished = false;
};

} // namespace bgp
} // namespace inet

#endif
