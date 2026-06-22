//
// Copyright (C) 2020 OpenSim Ltd.
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//


#include "inet/routing/bgpv4/bgpmessage/BgpHeaderSerializer.h"

#include <algorithm>

#include "inet/common/packet/serializer/ChunkSerializerRegistry.h"
#include "inet/routing/bgpv4/bgpmessage/BgpHeader_m.h"
#include "inet/routing/bgpv4/bgpmessage/BgpUpdate.h"

namespace inet {
namespace bgp {

Register_Serializer(BgpHeader, BgpHeaderSerializer);
Register_Serializer(BgpKeepAliveMessage, BgpHeaderSerializer);
Register_Serializer(BgpOpenMessage, BgpHeaderSerializer);
Register_Serializer(BgpUpdateMessage, BgpHeaderSerializer);

static unsigned int getPrefixBytes(uint8_t prefixLength)
{
    return (prefixLength + 7) / 8;
}

static void writeIpv6Prefix(MemoryOutputStream& stream, const Ipv6Address& address, uint8_t prefixLength)
{
    if (prefixLength > 128)
        throw cRuntimeError("Cannot serialize BGP UPDATE Message: IPv6 prefix length must be no greater than 128.");

    const uint32_t *words = address.words();
    unsigned int remainingBits = prefixLength;
    for (int i = 0; i < 4 && remainingBits > 0; i++) {
        uint32_t word = words[i];
        uint8_t bits = std::min(remainingBits, 32U);
        stream.writeNBitsOfUint64Be(word >> (32 - bits), bits);
        remainingBits -= bits;
    }
    if (prefixLength % 8 != 0)
        stream.writeBitRepeatedly(0, 8 - (prefixLength % 8));
}

static Ipv6Address readIpv6Prefix(MemoryInputStream& stream, uint8_t prefixLength)
{
    if (prefixLength > 128)
        throw cRuntimeError("Cannot deserialize BGP UPDATE Message: IPv6 prefix length must be no greater than 128.");

    uint32_t words[4] = {};
    unsigned int remainingBits = prefixLength;
    for (int i = 0; i < 4 && remainingBits > 0; i++) {
        uint8_t bits = std::min(remainingBits, 32U);
        words[i] = stream.readNBitsToUint64Be(bits) << (32 - bits);
        remainingBits -= bits;
    }
    if (prefixLength % 8 != 0)
        stream.readBitRepeatedly(0, 8 - (prefixLength % 8));
    return Ipv6Address(words[0], words[1], words[2], words[3]);
}

static void writeMpNlri(MemoryOutputStream& stream, const BgpMpNlri& nlri, BgpAddressFamilyIdentifier afi)
{
    uint8_t length = nlri.length;
    stream.writeByte(length);
    switch (afi) {
        case AFI_IPV4:
            if (length > 32)
                throw cRuntimeError("Cannot serialize BGP UPDATE Message: IPv4 prefix length must be no greater than 32.");
            if (length > 0)
                stream.writeNBitsOfUint64Be(nlri.ipv4Prefix.getInt() >> (32 - length), length);
            if (length % 8 != 0)
                stream.writeBitRepeatedly(0, 8 - (length % 8));
            break;
        case AFI_IPV6:
            writeIpv6Prefix(stream, nlri.ipv6Prefix, length);
            break;
        default:
            throw cRuntimeError("Cannot serialize BGP UPDATE Message: unsupported MP-BGP AFI %d.", afi);
    }
}

static BgpMpNlri readMpNlri(MemoryInputStream& stream, BgpAddressFamilyIdentifier afi)
{
    BgpMpNlri nlri;
    uint8_t length = stream.readByte();
    nlri.length = length;
    switch (afi) {
        case AFI_IPV4: {
            if (length > 32)
                throw cRuntimeError("Cannot deserialize BGP UPDATE Message: IPv4 prefix length must be no greater than 32.");
            uint32_t prefix = length == 0 ? 0 : stream.readNBitsToUint64Be(length);
            nlri.ipv4Prefix = Ipv4Address(length == 0 ? 0 : prefix << (32 - length));
            if (length % 8 != 0)
                stream.readBitRepeatedly(0, 8 - (length % 8));
            break;
        }
        case AFI_IPV6:
            nlri.ipv6Prefix = readIpv6Prefix(stream, length);
            break;
        default:
            throw cRuntimeError("Cannot deserialize BGP UPDATE Message: unsupported MP-BGP AFI %d.", afi);
    }
    return nlri;
}

static unsigned int getMpNlriBytes(const BgpMpNlri& nlri)
{
    return 1 + getPrefixBytes(nlri.length);
}

static unsigned int getCapabilityBytes(const BgpCapabilityBase& capability)
{
    return 2 + capability.getCapabilityLength();
}

void BgpHeaderSerializer::serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const
{
    const auto& bgpHeader = staticPtrCast<const BgpHeader>(chunk);
    for (size_t i = 0; i < 16; ++i) {
        uint8_t marker = bgpHeader->getMarker(i);
        if (marker != 0xFF)
            throw cRuntimeError("Cannot serialize BGP Message: marker must be set to all ones.");
        stream.writeByte(marker);
    }
    uint16_t totalLength = bgpHeader->getTotalLength();
    if (totalLength < 19 || totalLength > 4096)
        throw cRuntimeError("Cannot serialize BGP Message: totalLength field must be at least 19 and no greater than 4096.");
    stream.writeUint16Be(totalLength);
    BgpType type = bgpHeader->getType();
    stream.writeByte(type);
    switch (type) {
        case BGP_OPEN: {
            if (totalLength < 29)
                throw cRuntimeError("Cannot serialize BGP OPEN Message: length field must be at least 29.");
            const auto& bgpOpenMessage = CHK(dynamicPtrCast<const BgpOpenMessage>(chunk));
            uint8_t version = bgpOpenMessage->getVersion();
            if (version != 4)
                throw cRuntimeError("Cannot serialize BGP OPEN Message: version must be set to 4.");
            stream.writeByte(version);
            stream.writeUint16Be(bgpOpenMessage->getMyAS());
            uint64_t holdTime = bgpOpenMessage->getHoldTime().inUnit(SIMTIME_S);
            if (holdTime > 0 && holdTime < 3)
                throw cRuntimeError("Cannot serialize BGP OPEN Message: Hold Time must be either 0 or at least 3.");
            stream.writeUint16Be(holdTime);
            stream.writeIpv4Address(bgpOpenMessage->getBGPIdentifier());
            unsigned short optionalParametersLength = bgpOpenMessage->getOptionalParametersLength();
            stream.writeByte(optionalParametersLength);
            unsigned short numOptionalParametersBytes = 0;
            for (size_t i = 0; i < bgpOpenMessage->getOptionalParameterArraySize(); ++i) {
                const BgpOptionalParameterBase *optionalParameter = bgpOpenMessage->getOptionalParameter(i);
                stream.writeByte(optionalParameter->getParameterType());
                unsigned short parameterValueLength = optionalParameter->getParameterValueLength();
                stream.writeByte(parameterValueLength);
                if (optionalParameter->getParameterType() == BGP_OPTIONAL_PARAMETER_CAPABILITIES) {
                    const BgpOptionalParameterCapabilities *capabilitiesParameter = check_and_cast<const BgpOptionalParameterCapabilities *>(optionalParameter);
                    unsigned short capabilitiesLength = 0;
                    for (size_t e = 0; e < capabilitiesParameter->getCapabilityArraySize(); ++e) {
                        const BgpCapabilityBase *capability = capabilitiesParameter->getCapability(e);
                        capabilitiesLength += getCapabilityBytes(*capability);
                        stream.writeByte(capability->getCapabilityCode());
                        stream.writeByte(capability->getCapabilityLength());
                        switch (capability->getCapabilityCode()) {
                            case BGP_CAPABILITY_MULTIPROTOCOL: {
                                const BgpCapabilityMultiprotocol *multiprotocol = check_and_cast<const BgpCapabilityMultiprotocol *>(capability);
                                if (multiprotocol->getCapabilityLength() != 4)
                                    throw cRuntimeError("Cannot serialize BGP OPEN Message: Multiprotocol capability length must be 4.");
                                stream.writeUint16Be(multiprotocol->getAfi());
                                stream.writeByte(multiprotocol->getReserved());
                                stream.writeByte(multiprotocol->getSafi());
                                break;
                            }
                            default: {
                                const BgpCapabilityRaw *raw = check_and_cast<const BgpCapabilityRaw *>(capability);
                                for (size_t k = 0; k < raw->getValueArraySize(); ++k)
                                    stream.writeByte(raw->getValue(k));
                                break;
                            }
                        }
                    }
                    if (capabilitiesLength != parameterValueLength)
                        throw cRuntimeError("Cannot serialize BGP OPEN Message: incorrect capabilities parameter length field.");
                }
                else {
                    const BgpOptionalParameterRaw *rawParameter = check_and_cast<const BgpOptionalParameterRaw *>(optionalParameter);
                    for (size_t e = 0; e < rawParameter->getValueArraySize(); ++e)
                        stream.writeByte(rawParameter->getValue(e));
                }
                numOptionalParametersBytes += 2 + parameterValueLength;
            }
            if (numOptionalParametersBytes != optionalParametersLength)
                throw cRuntimeError("Cannot serialize BGP OPEN Message: incorrect parameterValueLength field.");
            break;
        }
        case BGP_UPDATE: {
            if (totalLength < 23)
                throw cRuntimeError("Cannot serialize BGP UPDATE Message: length field must be at least 23.");
            const auto& bgpUpdateMessage = staticPtrCast<const BgpUpdateMessage>(chunk);
            uint16_t withDrawnRoutesLength = bgpUpdateMessage->getWithDrawnRoutesLength();
            stream.writeUint16Be(withDrawnRoutesLength);
            for (size_t i = 0; i < bgpUpdateMessage->getWithdrawnRoutesArraySize(); ++i) {
                auto& withdrawnRoutes = bgpUpdateMessage->getWithdrawnRoutes(i);
                uint16_t length = withdrawnRoutes.length;
                stream.writeByte(length);
                if (length > 0)
                    stream.writeNBitsOfUint64Be(withdrawnRoutes.prefix.getInt() >> (32 - length), length);
                if (length % 8 != 0)
                    stream.writeBitRepeatedly(0, 8 - (length % 8));
            }
            stream.writeUint16Be(bgpUpdateMessage->getTotalPathAttributeLength());
            for (size_t i = 0; i < bgpUpdateMessage->getPathAttributesArraySize(); ++i) {
                const auto& pathAttributes = bgpUpdateMessage->getPathAttributes(i);
                bool optionalBit = pathAttributes->getOptionalBit();
                stream.writeBit(optionalBit);
                bool transitiveBit = pathAttributes->getTransitiveBit();
                stream.writeBit(transitiveBit);
                bool partialBit = pathAttributes->getPartialBit();
                stream.writeBit(partialBit);
                bool extendedLengthBit = pathAttributes->getExtendedLengthBit();
                stream.writeBit(extendedLengthBit);
                if (!optionalBit && (!transitiveBit || partialBit))
                    throw cRuntimeError("Cannot serialize BGP UPDATE Message: incorrect flags.");
                if (optionalBit && !transitiveBit && partialBit)
                    throw cRuntimeError("Cannot serialize BGP UPDATE Message: incorrect flags.");
                stream.writeUint4(pathAttributes->getReserved());
                BgpUpdateAttributeTypeCode typeCode = pathAttributes->getTypeCode();
                stream.writeByte(typeCode);
                if (!extendedLengthBit)
                    stream.writeByte(pathAttributes->getLength());
                else
                    stream.writeUint16Be(pathAttributes->getLength());
                switch (typeCode) {
                    case ORIGIN: {
                        const BgpUpdatePathAttributesOrigin *origin = check_and_cast<const BgpUpdatePathAttributesOrigin *>(pathAttributes);
                        stream.writeByte(origin->getValue());
                        break;
                    }
                    case AS_PATH: {
                        const BgpUpdatePathAttributesAsPath *asPath = check_and_cast<const BgpUpdatePathAttributesAsPath *>(pathAttributes);
                        for (size_t e = 0; e < asPath->getValueArraySize(); ++e) {
                            const auto& value = asPath->getValue(e);
                            stream.writeByte(value.getType());
                            uint8_t numOfASNumbers = value.getLength();
                            if (numOfASNumbers != value.getAsValueArraySize())
                                throw cRuntimeError("Cannot serialize BGP UPDATE Message: AS Path attribute length field.");
                            stream.writeByte(numOfASNumbers);
                            for (uint8_t k = 0; k < numOfASNumbers; ++k) {
                                stream.writeUint16Be(value.getAsValue(k));
                            }
                        }
                        break;
                    }
                    case NEXT_HOP: {
                        const BgpUpdatePathAttributesNextHop *nextHop = check_and_cast<const BgpUpdatePathAttributesNextHop *>(pathAttributes);
                        stream.writeIpv4Address(nextHop->getValue());
                        break;
                    }
                    case MULTI_EXIT_DISC: {
                        const BgpUpdatePathAttributesMultiExitDisc *multiExitDisc = check_and_cast<const BgpUpdatePathAttributesMultiExitDisc *>(pathAttributes);
                        stream.writeUint32Be(multiExitDisc->getValue());
                        break;
                    }
                    case LOCAL_PREF: {
                        const BgpUpdatePathAttributesLocalPref *localPref = check_and_cast<const BgpUpdatePathAttributesLocalPref *>(pathAttributes);
                        stream.writeUint32Be(localPref->getValue());
                        break;
                    }
                    case ATOMIC_AGGREGATE: {
                        const BgpUpdatePathAttributesAtomicAggregate *atomicAggregate = check_and_cast<const BgpUpdatePathAttributesAtomicAggregate *>(pathAttributes);
                        (void)atomicAggregate; // unused
                        break;
                    }
                    case AGGREGATOR: {
                        const BgpUpdatePathAttributesAggregator *aggregator = check_and_cast<const BgpUpdatePathAttributesAggregator *>(pathAttributes);
                        stream.writeUint16Be(aggregator->getAsNumber());
                        stream.writeIpv4Address(aggregator->getBgpSpeaker());
                        break;
                    }
                    case MP_REACH_NLRI: {
                        const BgpUpdatePathAttributesMpReachNlri *mpReachNlri = check_and_cast<const BgpUpdatePathAttributesMpReachNlri *>(pathAttributes);
                        stream.writeUint16Be(mpReachNlri->getAfi());
                        stream.writeByte(mpReachNlri->getSafi());
                        uint8_t nextHopNetworkAddressLength = mpReachNlri->getNextHopNetworkAddressLength();
                        stream.writeByte(nextHopNetworkAddressLength);
                        if (mpReachNlri->getAfi() == AFI_IPV4) {
                            if (nextHopNetworkAddressLength != 4)
                                throw cRuntimeError("Cannot serialize BGP UPDATE Message: IPv4 MP_REACH_NLRI next hop length must be 4.");
                            stream.writeIpv4Address(mpReachNlri->getNextHopIpv4Address());
                        }
                        else if (mpReachNlri->getAfi() == AFI_IPV6) {
                            if (nextHopNetworkAddressLength != 16 && nextHopNetworkAddressLength != 32)
                                throw cRuntimeError("Cannot serialize BGP UPDATE Message: IPv6 MP_REACH_NLRI next hop length must be 16 or 32.");
                            stream.writeIpv6Address(mpReachNlri->getNextHopIpv6Address());
                            if (nextHopNetworkAddressLength == 32)
                                stream.writeIpv6Address(Ipv6Address::UNSPECIFIED_ADDRESS);
                        }
                        else
                            throw cRuntimeError("Cannot serialize BGP UPDATE Message: unsupported MP_REACH_NLRI AFI %d.", mpReachNlri->getAfi());
                        stream.writeByte(mpReachNlri->getNumberOfSnpas());
                        for (size_t e = 0; e < mpReachNlri->getNlriArraySize(); ++e)
                            writeMpNlri(stream, mpReachNlri->getNlri(e), mpReachNlri->getAfi());
                        break;
                    }
                    case MP_UNREACH_NLRI: {
                        const BgpUpdatePathAttributesMpUnreachNlri *mpUnreachNlri = check_and_cast<const BgpUpdatePathAttributesMpUnreachNlri *>(pathAttributes);
                        stream.writeUint16Be(mpUnreachNlri->getAfi());
                        stream.writeByte(mpUnreachNlri->getSafi());
                        for (size_t e = 0; e < mpUnreachNlri->getWithdrawnRoutesArraySize(); ++e)
                            writeMpNlri(stream, mpUnreachNlri->getWithdrawnRoutes(e), mpUnreachNlri->getAfi());
                        break;
                    }
                    default:
                        throw cRuntimeError("Cannot serialize BGP UPDATE Message: incorrect typeCode: %d.", typeCode);
                }
            }
            for (size_t i = 0; i < bgpUpdateMessage->getNLRIArraySize(); ++i) {
                auto& nlri = bgpUpdateMessage->getNLRI(i);
                uint8_t length = nlri.length;
                stream.writeByte(length);
                if (length > 0)
                    stream.writeNBitsOfUint64Be(nlri.prefix.getInt() >> (32 - length), length);
                if (length % 8 != 0)
                    stream.writeBitRepeatedly(0, 8 - (length % 8));
            }
            break;
        }
        case BGP_KEEPALIVE: {
            break;
        }
        default:
            throw cRuntimeError("Cannot serialize BGP packet: type %d not supported.", type);
    }
}

const Ptr<Chunk> BgpHeaderSerializer::deserialize(MemoryInputStream& stream) const
{
    bool incorrect = false;
    uint8_t marker[16];
    for (int i = 0; i < 16; ++i) {
        marker[i] = stream.readByte();
        if (marker[i] != 0xFF)
            incorrect = true;
    }
    uint16_t totalLength = stream.readUint16Be();
    if (totalLength < 19 || totalLength > 4096)
        incorrect = true;
    BgpType type = static_cast<BgpType>(stream.readByte());
    switch (type) {
        case BGP_OPEN: {
            auto bgpOpenMessage = makeShared<BgpOpenMessage>();
            if (incorrect)
                bgpOpenMessage->markIncorrect();
            for (size_t i = 0; i < 16; ++i) {
                bgpOpenMessage->setMarker(i, marker[i]);
            }
            if (totalLength < 29)
                bgpOpenMessage->markIncorrect();
            bgpOpenMessage->setTotalLength(totalLength);
            bgpOpenMessage->setChunkLength(B(totalLength));
            bgpOpenMessage->setType(type);
            uint8_t version = stream.readByte();
            if (version != 4)
                bgpOpenMessage->markIncorrect();
            bgpOpenMessage->setVersion(version);
            bgpOpenMessage->setMyAS(stream.readUint16Be());
            uint16_t holdTime = stream.readUint16Be();
            if (holdTime > 0 && holdTime < 3)
                bgpOpenMessage->markIncorrect();
            bgpOpenMessage->setHoldTime(SimTime(holdTime, SIMTIME_S));
            bgpOpenMessage->setBGPIdentifier(stream.readIpv4Address());
            unsigned short optionalParametersLength = stream.readByte();
            bgpOpenMessage->setOptionalParametersLength(optionalParametersLength);
            for (size_t i = 0; optionalParametersLength > 0; ++i) {
                bgpOpenMessage->setOptionalParameterArraySize(i + 1);
                uint8_t parameterType = stream.readByte();
                uint8_t parameterValueLength = stream.readByte();
                BgpOptionalParameterBase *optionalParameter = nullptr;
                optionalParametersLength -= (2 + parameterValueLength);
                if (parameterType == BGP_OPTIONAL_PARAMETER_CAPABILITIES) {
                    BgpOptionalParameterCapabilities *capabilitiesParameter = new BgpOptionalParameterCapabilities();
                    uint8_t remainingCapabilitiesLength = parameterValueLength;
                    for (size_t e = 0; remainingCapabilitiesLength > 0; ++e) {
                        capabilitiesParameter->setCapabilityArraySize(e + 1);
                        uint8_t capabilityCode = stream.readByte();
                        uint8_t capabilityLength = stream.readByte();
                        remainingCapabilitiesLength -= (2 + capabilityLength);
                        if (capabilityCode == BGP_CAPABILITY_MULTIPROTOCOL && capabilityLength == 4) {
                            BgpCapabilityMultiprotocol *multiprotocol = new BgpCapabilityMultiprotocol();
                            multiprotocol->setCapabilityCode(static_cast<BgpCapabilityCode>(capabilityCode));
                            multiprotocol->setCapabilityLength(capabilityLength);
                            multiprotocol->setAfi(static_cast<BgpAddressFamilyIdentifier>(stream.readUint16Be()));
                            multiprotocol->setReserved(stream.readByte());
                            multiprotocol->setSafi(static_cast<BgpSubsequentAddressFamilyIdentifier>(stream.readByte()));
                            capabilitiesParameter->setCapability(e, multiprotocol);
                        }
                        else {
                            BgpCapabilityRaw *rawCapability = new BgpCapabilityRaw();
                            rawCapability->setCapabilityCode(capabilityCode);
                            rawCapability->setCapabilityLength(capabilityLength);
                            for (size_t k = 0; k < capabilityLength; ++k) {
                                rawCapability->setValueArraySize(k + 1);
                                rawCapability->setValue(k, stream.readByte());
                            }
                            capabilitiesParameter->setCapability(e, rawCapability);
                        }
                    }
                    optionalParameter = capabilitiesParameter;
                }
                else {
                    BgpOptionalParameterRaw *rawParameter = new BgpOptionalParameterRaw();
                    for (size_t e = 0; e < parameterValueLength; ++e) {
                        rawParameter->setValueArraySize(e + 1);
                        rawParameter->setValue(e, stream.readByte());
                    }
                    optionalParameter = rawParameter;
                }
                optionalParameter->setParameterType(parameterType);
                optionalParameter->setParameterValueLength(parameterValueLength);
                bgpOpenMessage->setOptionalParameter(i, optionalParameter);
            }
            return bgpOpenMessage;
        }
        case BGP_UPDATE: {
            auto bgpUpdateMessage = makeShared<BgpUpdateMessage>();
            if (incorrect)
                bgpUpdateMessage->markIncorrect();
            for (size_t i = 0; i < 16; ++i) {
                bgpUpdateMessage->setMarker(i, marker[i]);
            }
            if (totalLength < 23)
                bgpUpdateMessage->markIncorrect();
            bgpUpdateMessage->setTotalLength(totalLength);
            bgpUpdateMessage->setChunkLength(B(totalLength));
            bgpUpdateMessage->setType(type);
            uint32_t withdrawnRoutesLength = stream.readUint16Be();
            uint32_t tmp_withdrawnRoutesLength = withdrawnRoutesLength;
            for (size_t i = 0; withdrawnRoutesLength > 0; ++i) {
                bgpUpdateMessage->setWithdrawnRoutesArraySize(i + 1);
                BgpUpdateWithdrawnRoutes *withdrawnRoutes = new BgpUpdateWithdrawnRoutes();
                uint8_t length = stream.readByte();
                withdrawnRoutes->length = length;
                uint32_t prefix = length == 0 ? 0 : stream.readNBitsToUint64Be(length);
                withdrawnRoutes->prefix = Ipv4Address(length == 0 ? 0 : prefix << (32 - length));
                if (length % 8 != 0) {
                    stream.readBitRepeatedly(0, 8 - (length % 8));
                    withdrawnRoutesLength -= (1 + (length / 8) + 1);
                }
                else
                    withdrawnRoutesLength -= (1 + (length / 8));
                bgpUpdateMessage->setWithdrawnRoutes(i, *withdrawnRoutes);
            }
            uint32_t totalPathAttributeLength = stream.readUint16Be();
            uint32_t tmp_totalPathAttributeLength = totalPathAttributeLength;
            bgpUpdateMessage->setTotalPathAttributeLength(totalPathAttributeLength);
            for (size_t i = 0; totalPathAttributeLength > 0; ++i) {
                bgpUpdateMessage->setPathAttributesArraySize(i + 1);
                bool optionalBit = stream.readBit();
                bool transitiveBit = stream.readBit();
                bool partialBit = stream.readBit();
                bool extendedLengthBit = stream.readBit();
                if (!stream.readBitRepeatedly(false, 4))
                    bgpUpdateMessage->markIncorrect();
                BgpUpdateAttributeTypeCode typeCode = static_cast<BgpUpdateAttributeTypeCode>(stream.readByte());
                uint16_t pathAttributeLength = 0;
                if (!extendedLengthBit) {
                    pathAttributeLength = stream.readByte();
                    totalPathAttributeLength -= (pathAttributeLength + 3);
                }
                else {
                    pathAttributeLength = stream.readUint16Be();
                    totalPathAttributeLength -= (pathAttributeLength + 4);
                }
                switch (typeCode) {
                    case ORIGIN: {
                        if (optionalBit || !transitiveBit || pathAttributeLength != 1) {
                            bgpUpdateMessage->markIncorrect();
                            return bgpUpdateMessage;
                        }
                        BgpUpdatePathAttributesOrigin *origin = new BgpUpdatePathAttributesOrigin();
                        origin->setOptionalBit(optionalBit);
                        origin->setTransitiveBit(transitiveBit);
                        origin->setPartialBit(partialBit);
                        origin->setExtendedLengthBit(extendedLengthBit);
                        origin->setReserved(0);
                        origin->setLength(pathAttributeLength);
                        origin->setTypeCode(typeCode);
                        origin->setValue(static_cast<BgpSessionType>(stream.readByte()));
                        bgpUpdateMessage->setPathAttributes(i, origin);
                        break;
                    }
                    case AS_PATH: {
                        if (optionalBit || !transitiveBit) {
                            bgpUpdateMessage->markIncorrect();
                            return bgpUpdateMessage;
                        }
                        BgpUpdatePathAttributesAsPath *asPath = new BgpUpdatePathAttributesAsPath();
                        asPath->setOptionalBit(optionalBit);
                        asPath->setTransitiveBit(transitiveBit);
                        asPath->setPartialBit(partialBit);
                        asPath->setExtendedLengthBit(extendedLengthBit);
                        asPath->setReserved(0);
                        asPath->setLength(pathAttributeLength);
                        asPath->setTypeCode(typeCode);
                        for (size_t e = 0; pathAttributeLength > 0; ++e) {
                            asPath->setValueArraySize(e + 1);
                            BgpAsPathSegment *value = new BgpAsPathSegment();
                            value->setType(static_cast<BgpPathSegmentType>(stream.readByte()));
                            uint8_t numOfASNumbers = stream.readByte();
                            value->setLength(numOfASNumbers);
                            pathAttributeLength -= (2 + numOfASNumbers * 2);
                            value->setAsValueArraySize(numOfASNumbers);
                            for (size_t k = 0; numOfASNumbers > 0; ++k) {
                                value->setAsValue(k, stream.readUint16Be());
                                --numOfASNumbers;
                            }
                            asPath->setValue(e, *value);
                        }
                        bgpUpdateMessage->setPathAttributes(i, asPath);
                        break;
                    }
                    case NEXT_HOP: {
                        if (optionalBit || !transitiveBit || pathAttributeLength != 4) {
                            bgpUpdateMessage->markIncorrect();
                            return bgpUpdateMessage;
                        }
                        BgpUpdatePathAttributesNextHop *nextHop = new BgpUpdatePathAttributesNextHop();
                        nextHop->setOptionalBit(optionalBit);
                        nextHop->setTransitiveBit(transitiveBit);
                        nextHop->setPartialBit(partialBit);
                        nextHop->setExtendedLengthBit(extendedLengthBit);
                        nextHop->setReserved(0);
                        nextHop->setLength(pathAttributeLength);
                        nextHop->setTypeCode(typeCode);
                        nextHop->setValue(stream.readIpv4Address());
                        bgpUpdateMessage->setPathAttributes(i, nextHop);
                        break;
                    }
                    case MULTI_EXIT_DISC: {
                        if (!optionalBit || transitiveBit || pathAttributeLength != 4) {
                            bgpUpdateMessage->markIncorrect();
                            return bgpUpdateMessage;
                        }
                        BgpUpdatePathAttributesMultiExitDisc *multiExitDisc = new BgpUpdatePathAttributesMultiExitDisc();
                        multiExitDisc->setOptionalBit(optionalBit);
                        multiExitDisc->setTransitiveBit(transitiveBit);
                        multiExitDisc->setPartialBit(partialBit);
                        multiExitDisc->setExtendedLengthBit(extendedLengthBit);
                        multiExitDisc->setReserved(0);
                        multiExitDisc->setLength(pathAttributeLength);
                        multiExitDisc->setTypeCode(typeCode);
                        multiExitDisc->setValue(stream.readUint32Be());
                        bgpUpdateMessage->setPathAttributes(i, multiExitDisc);
                        break;
                    }
                    case LOCAL_PREF: {
                        if (optionalBit || !transitiveBit || pathAttributeLength != 4) {
                            bgpUpdateMessage->markIncorrect();
                            return bgpUpdateMessage;
                        }
                        BgpUpdatePathAttributesLocalPref *localPref = new BgpUpdatePathAttributesLocalPref();
                        localPref->setOptionalBit(optionalBit);
                        localPref->setTransitiveBit(transitiveBit);
                        localPref->setPartialBit(partialBit);
                        localPref->setExtendedLengthBit(extendedLengthBit);
                        localPref->setReserved(0);
                        localPref->setLength(pathAttributeLength);
                        localPref->setTypeCode(typeCode);
                        localPref->setValue(stream.readUint32Be());
                        bgpUpdateMessage->setPathAttributes(i, localPref);
                        break;
                    }
                    case ATOMIC_AGGREGATE: {
                        if (optionalBit || !transitiveBit || pathAttributeLength != 0) {
                            bgpUpdateMessage->markIncorrect();
                            return bgpUpdateMessage;
                        }
                        BgpUpdatePathAttributesAtomicAggregate *atomicAggregate = new BgpUpdatePathAttributesAtomicAggregate();
                        atomicAggregate->setOptionalBit(optionalBit);
                        atomicAggregate->setTransitiveBit(transitiveBit);
                        atomicAggregate->setPartialBit(partialBit);
                        atomicAggregate->setExtendedLengthBit(extendedLengthBit);
                        atomicAggregate->setReserved(0);
                        atomicAggregate->setLength(pathAttributeLength);
                        atomicAggregate->setTypeCode(typeCode);
                        bgpUpdateMessage->setPathAttributes(i, atomicAggregate);
                        break;
                    }
                    case AGGREGATOR: {
                        if (!optionalBit || !transitiveBit || pathAttributeLength != 6) {
                            bgpUpdateMessage->markIncorrect();
                            return bgpUpdateMessage;
                        }
                        BgpUpdatePathAttributesAggregator *aggregator = new BgpUpdatePathAttributesAggregator();
                        aggregator->setOptionalBit(optionalBit);
                        aggregator->setTransitiveBit(transitiveBit);
                        aggregator->setPartialBit(partialBit);
                        aggregator->setExtendedLengthBit(extendedLengthBit);
                        aggregator->setReserved(0);
                        aggregator->setLength(pathAttributeLength);
                        aggregator->setTypeCode(typeCode);
                        aggregator->setAsNumber(stream.readUint16Be());
                        aggregator->setBgpSpeaker(stream.readIpv4Address());
                        bgpUpdateMessage->setPathAttributes(i, aggregator);
                        break;
                    }
                    case MP_REACH_NLRI: {
                        if (!optionalBit || transitiveBit || pathAttributeLength < 5) {
                            bgpUpdateMessage->markIncorrect();
                            return bgpUpdateMessage;
                        }
                        BgpUpdatePathAttributesMpReachNlri *mpReachNlri = new BgpUpdatePathAttributesMpReachNlri();
                        mpReachNlri->setOptionalBit(optionalBit);
                        mpReachNlri->setTransitiveBit(transitiveBit);
                        mpReachNlri->setPartialBit(partialBit);
                        mpReachNlri->setExtendedLengthBit(extendedLengthBit);
                        mpReachNlri->setReserved(0);
                        mpReachNlri->setLength(pathAttributeLength);
                        mpReachNlri->setTypeCode(typeCode);
                        BgpAddressFamilyIdentifier afi = static_cast<BgpAddressFamilyIdentifier>(stream.readUint16Be());
                        mpReachNlri->setAfi(afi);
                        mpReachNlri->setSafi(static_cast<BgpSubsequentAddressFamilyIdentifier>(stream.readByte()));
                        uint8_t nextHopNetworkAddressLength = stream.readByte();
                        mpReachNlri->setNextHopNetworkAddressLength(nextHopNetworkAddressLength);
                        uint16_t remainingAttributeLength = pathAttributeLength - 4;
                        if (afi == AFI_IPV4 && nextHopNetworkAddressLength == 4)
                            mpReachNlri->setNextHopIpv4Address(stream.readIpv4Address());
                        else if (afi == AFI_IPV6 && (nextHopNetworkAddressLength == 16 || nextHopNetworkAddressLength == 32)) {
                            mpReachNlri->setNextHopIpv6Address(stream.readIpv6Address());
                            if (nextHopNetworkAddressLength == 32)
                                stream.readIpv6Address();
                        }
                        else {
                            bgpUpdateMessage->markIncorrect();
                            return bgpUpdateMessage;
                        }
                        remainingAttributeLength -= nextHopNetworkAddressLength;
                        mpReachNlri->setNumberOfSnpas(stream.readByte());
                        remainingAttributeLength -= 1;
                        for (size_t e = 0; remainingAttributeLength > 0; ++e) {
                            BgpMpNlri nlri = readMpNlri(stream, afi);
                            mpReachNlri->setNlriArraySize(e + 1);
                            mpReachNlri->setNlri(e, nlri);
                            remainingAttributeLength -= getMpNlriBytes(nlri);
                        }
                        bgpUpdateMessage->setPathAttributes(i, mpReachNlri);
                        break;
                    }
                    case MP_UNREACH_NLRI: {
                        if (!optionalBit || transitiveBit || pathAttributeLength < 3) {
                            bgpUpdateMessage->markIncorrect();
                            return bgpUpdateMessage;
                        }
                        BgpUpdatePathAttributesMpUnreachNlri *mpUnreachNlri = new BgpUpdatePathAttributesMpUnreachNlri();
                        mpUnreachNlri->setOptionalBit(optionalBit);
                        mpUnreachNlri->setTransitiveBit(transitiveBit);
                        mpUnreachNlri->setPartialBit(partialBit);
                        mpUnreachNlri->setExtendedLengthBit(extendedLengthBit);
                        mpUnreachNlri->setReserved(0);
                        mpUnreachNlri->setLength(pathAttributeLength);
                        mpUnreachNlri->setTypeCode(typeCode);
                        BgpAddressFamilyIdentifier afi = static_cast<BgpAddressFamilyIdentifier>(stream.readUint16Be());
                        mpUnreachNlri->setAfi(afi);
                        mpUnreachNlri->setSafi(static_cast<BgpSubsequentAddressFamilyIdentifier>(stream.readByte()));
                        uint16_t remainingAttributeLength = pathAttributeLength - 3;
                        for (size_t e = 0; remainingAttributeLength > 0; ++e) {
                            BgpMpNlri nlri = readMpNlri(stream, afi);
                            mpUnreachNlri->setWithdrawnRoutesArraySize(e + 1);
                            mpUnreachNlri->setWithdrawnRoutes(e, nlri);
                            remainingAttributeLength -= getMpNlriBytes(nlri);
                        }
                        bgpUpdateMessage->setPathAttributes(i, mpUnreachNlri);
                        break;
                    }
                    default: {
                        BgpUpdatePathAttributes *pathAttributes = new BgpUpdatePathAttributes();
                        pathAttributes->setOptionalBit(optionalBit);
                        pathAttributes->setTransitiveBit(transitiveBit);
                        pathAttributes->setPartialBit(partialBit);
                        pathAttributes->setExtendedLengthBit(extendedLengthBit);
                        pathAttributes->setReserved(0);
                        pathAttributes->setLength(pathAttributeLength);
                        pathAttributes->setTypeCode(typeCode);
                        for (size_t e = 0; e < pathAttributeLength; ++e)
                            stream.readByte();
                        bgpUpdateMessage->markIncorrect();
                        bgpUpdateMessage->setPathAttributes(i, pathAttributes);
                    }
                }
            }
            int nlri_size = (totalLength - BGP_HEADER_OCTETS.get() - tmp_withdrawnRoutesLength - tmp_totalPathAttributeLength - 4);
            for (size_t i = 0; nlri_size > 0; ++i) {
                BgpUpdateNlri *nlri = new BgpUpdateNlri();
                bgpUpdateMessage->setNLRIArraySize(i + 1);
                uint8_t length = stream.readByte();
                nlri->length = length;
                uint32_t prefix = length == 0 ? 0 : stream.readNBitsToUint64Be(length);
                nlri->prefix = Ipv4Address(length == 0 ? 0 : prefix << (32 - length));
                if (length % 8 != 0) {
                    stream.readBitRepeatedly(0, 8 - (length % 8));
                    nlri_size -= (1 + (length / 8) + 1);
                }
                else
                    nlri_size -= (1 + (length / 8));
                bgpUpdateMessage->setNLRI(i, *nlri);
            }
            return bgpUpdateMessage;
        }
        case BGP_KEEPALIVE: {
            auto bgpKeepAliveMessage = makeShared<BgpKeepAliveMessage>();
            if (incorrect)
                bgpKeepAliveMessage->markIncorrect();
            for (size_t i = 0; i < 16; ++i) {
                bgpKeepAliveMessage->setMarker(i, marker[i]);
            }
            if (totalLength != 19)
                bgpKeepAliveMessage->markIncorrect();
            bgpKeepAliveMessage->setTotalLength(totalLength);
            bgpKeepAliveMessage->setChunkLength(B(totalLength));
            bgpKeepAliveMessage->setType(type);
            return bgpKeepAliveMessage;
        }
        default: {
            auto bgpHeader = makeShared<BgpHeader>();
            bgpHeader->setChunkLength(B(1));
            bgpHeader->markIncorrect();
            return bgpHeader;
        }
    }
}

} // namespace bgp
} // namespace inet
