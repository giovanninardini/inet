//
// Copyright (C) 2010 Helene Lageber
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//

#include "inet/routing/bgpv4/bgpmessage/BgpUpdate.h"

namespace inet {
namespace bgp {

unsigned short computePathAttributeBytes(const BgpUpdatePathAttributes& pathAttr)
{
    unsigned short contentBytes = pathAttr.getExtendedLengthBit() ? 4 : 3;
    switch (pathAttr.getTypeCode()) {
        case BgpUpdateAttributeTypeCode::ORIGIN: {
            auto& attr = *check_and_cast<const BgpUpdatePathAttributesOrigin *>(&pathAttr);
            ASSERT(attr.getLength() == 1);
            contentBytes += 1;
            return contentBytes;
        }
        case BgpUpdateAttributeTypeCode::AS_PATH: {
            auto& attr = *check_and_cast<const BgpUpdatePathAttributesAsPath *>(&pathAttr);
    #ifndef NDEBUG
            {
                unsigned short s = 0;
                for (size_t j = 0; j < attr.getValueArraySize(); j++) {
                    ASSERT(attr.getValue(j).getLength() == attr.getValue(j).getAsValueArraySize());
                    s += 2 + 2 * attr.getValue(j).getAsValueArraySize();
                }
                ASSERT(s == attr.getLength());
            }
    #endif
            contentBytes += attr.getLength(); // type (1) + length (1) + value
            return contentBytes;
        }
        case BgpUpdateAttributeTypeCode::NEXT_HOP: {
            auto& attr = *check_and_cast<const BgpUpdatePathAttributesNextHop *>(&pathAttr);
            ASSERT(attr.getLength() == 4);
            contentBytes += 4;
            return contentBytes;
        }
        case BgpUpdateAttributeTypeCode::LOCAL_PREF: {
            auto& attr = *check_and_cast<const BgpUpdatePathAttributesLocalPref *>(&pathAttr);
            ASSERT(attr.getLength() == 4);
            contentBytes += 4;
            return contentBytes;
        }
        case BgpUpdateAttributeTypeCode::ATOMIC_AGGREGATE: {
            auto& attr = *check_and_cast<const BgpUpdatePathAttributesAtomicAggregate *>(&pathAttr);
            ASSERT(attr.getLength() == 0);
            return contentBytes;
        }
        case BgpUpdateAttributeTypeCode::MP_REACH_NLRI: {
            auto& attr = *check_and_cast<const BgpUpdatePathAttributesMpReachNlri *>(&pathAttr);
            unsigned short valueBytes = 2 + 1 + 1 + attr.getNextHopNetworkAddressLength() + 1;
            for (size_t i = 0; i < attr.getNlriArraySize(); i++)
                valueBytes += 1 + (attr.getNlri(i).length + 7) / 8;
            ASSERT(attr.getLength() == valueBytes);
            contentBytes += valueBytes;
            return contentBytes;
        }
        case BgpUpdateAttributeTypeCode::MP_UNREACH_NLRI: {
            auto& attr = *check_and_cast<const BgpUpdatePathAttributesMpUnreachNlri *>(&pathAttr);
            unsigned short valueBytes = 2 + 1;
            for (size_t i = 0; i < attr.getWithdrawnRoutesArraySize(); i++)
                valueBytes += 1 + (attr.getWithdrawnRoutes(i).length + 7) / 8;
            ASSERT(attr.getLength() == valueBytes);
            contentBytes += valueBytes;
            return contentBytes;
        }
        default:
            throw cRuntimeError("Unknown BgpUpdateAttributeTypeCode: %d", (int)pathAttr.getTypeCode());
    }
}

} // namespace bgp
} // namespace inet
