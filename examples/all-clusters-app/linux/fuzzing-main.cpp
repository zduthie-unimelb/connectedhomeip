/*
 *    Copyright (c) 2022 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "AppMain.h"
#include <app/server/Server.h>
#include <transport/SessionManager.h>
#include <transport/TransportMgr.h>
#include <transport/raw/PeerAddress.h>

#include <CommissionableInit.h>

#include <chrono>
#include <iostream>
#include <vector>

#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"
#include "chip_message.pb.h"

extern "C" void __gcov_dump();

using namespace chip;
using namespace chip::DeviceLayer;

namespace {

LinuxCommissionableDataProvider gCommissionableDataProvider;

}

static std::vector<uint8_t> PacketFromProtoMessage(const chip_message::ChipMessage& message) {
    std::vector<uint8_t> packet = {};

    /* 4.4.1. Message Header Field Descriptions */

    /* 4.4.1.1. Message Length (16 bits) */
    // (IGNORE FPR NOW)

    /* 4.4.1.2. Message Flags (8 bits) */
    uint8_t messageFlags =
        (message.flag_dsiz() << 0) +
        (message.flag_s() << 2) +
        ((message.flag_version() ? 0x0 : 0x0) << 4);
    // uint8_t messageFlags = 0x4;
    packet.push_back(messageFlags);

    /* 4.4.1.3. Session ID (16 bits) */
    int32_t sessionId = message.session_id();
    packet.push_back(sessionId & 0xff00 >> 8);
    packet.push_back(sessionId & 0x00ff >> 0);

    /* 4.4.1.4. Security Flags (8 bits) */
    uint8_t securityFlags =
        (message.security_flag_session_type() << 0) +
        (message.security_flag_mx() << 5) +
        (message.security_flag_c() << 6) +
        (message.security_flag_p() << 7);
    packet.push_back(securityFlags);

    /* 4.4.1.5. Message Counter (32 bits) */
    int32_t messageCounter = message.message_counter();
    packet.push_back(messageCounter & 0xff000000 >> 24);
    packet.push_back(messageCounter & 0x00ff0000 >> 16);
    packet.push_back(messageCounter & 0x0000ff00 >> 8);
    packet.push_back(messageCounter & 0x000000ff >> 0);
    
    // /* 4.4.1.6. Source Node ID (64 bits) */
    if (message.has_source_node_id()) {
        int64_t sourceNodeId = message.source_node_id();
        packet.push_back(sourceNodeId & 0xff00000000000000 >> 56);
        packet.push_back(sourceNodeId & 0x00ff000000000000 >> 48);
        packet.push_back(sourceNodeId & 0x0000ff0000000000 >> 40);
        packet.push_back(sourceNodeId & 0x000000ff00000000 >> 32);
        packet.push_back(sourceNodeId & 0x00000000ff000000 >> 24);
        packet.push_back(sourceNodeId & 0x0000000000ff0000 >> 16);
        packet.push_back(sourceNodeId & 0x000000000000ff00 >> 8);
        packet.push_back(sourceNodeId & 0x00000000000000ff >> 0);
    }

    /* 4.4.1.7. Destination Node ID */
    // Assume 64 bit (if present)
    if (message.has_destination_node_id()) {
        if (message.has_source_node_id()) {
            int64_t destinationNodeId = message.destination_node_id();
            packet.push_back(destinationNodeId & 0xff00000000000000 >> 56);
            packet.push_back(destinationNodeId & 0x00ff000000000000 >> 48);
            packet.push_back(destinationNodeId & 0x0000ff0000000000 >> 40);
            packet.push_back(destinationNodeId & 0x000000ff00000000 >> 32);
            packet.push_back(destinationNodeId & 0x00000000ff000000 >> 24);
            packet.push_back(destinationNodeId & 0x0000000000ff0000 >> 16);
            packet.push_back(destinationNodeId & 0x000000000000ff00 >> 8);
            packet.push_back(destinationNodeId & 0x00000000000000ff >> 0);
        }
    }

    /* 4.4.1.8. Message Extensions (variable) */
    // TODO

    /* 4.4.2. Message Footer Field Descriptions */
    /* 4.4.2.1. Message Integrity Check (variable length) */

    auto messagePayload = message.payload();
    std::vector<uint8_t> payloadPacket = {};

    /* 4.4.3. Protocol Header Field Descriptions */

    /* 4.4.3.1. Exchange Flags (8 bits) */
    uint8_t protocolHeader =
        (messagePayload.flag_i() << 0) +
        (messagePayload.flag_a() << 1) +
        (messagePayload.flag_r() << 2) +
        (messagePayload.flag_sx() << 3) +
        (messagePayload.flag_v() << 4);
    payloadPacket.push_back(protocolHeader);

    /* 4.4.3.2. Protocol Opcode (8 bits) */
    // TODO - don't drop bits
    uint32_t protocolOpcode = messagePayload.protocol_opcode();
    payloadPacket.push_back(protocolOpcode & 0xff >> 0);

    /* 4.4.3.3. Exchange ID (16 bits) */
    // TODO - don't drop bits
    uint32_t exchangeId = messagePayload.protocol_opcode();
    payloadPacket.push_back(exchangeId & 0xff00 >> 8);
    payloadPacket.push_back(exchangeId & 0x00ff >> 0);

    /* 4.4.3.4. Protocol ID (16 bits) */
    payloadPacket.push_back(0);
    payloadPacket.push_back(messagePayload.protocol_id());

    /* 4.4.3.5. Protocol Vendor ID (16 bits) */
    if (messagePayload.has_vendor_id()) {
        uint32_t vendorId = messagePayload.vendor_id();
        payloadPacket.push_back(vendorId & 0xff00 >> 8);
        payloadPacket.push_back(vendorId & 0x00ff >> 0);
    }

    /* 4.4.3.6. Acknowledged Message Counter (32 bits) */
    if (messagePayload.has_acknowledged_message_counter()) {
        uint32_t acknowledgedMessageCounter = messagePayload.acknowledged_message_counter();
        payloadPacket.push_back(acknowledgedMessageCounter & 0xff000000 >> 24);
        payloadPacket.push_back(acknowledgedMessageCounter & 0x00ff0000 >> 16);
        payloadPacket.push_back(acknowledgedMessageCounter & 0x0000ff00 >> 8);
        payloadPacket.push_back(acknowledgedMessageCounter & 0x000000ff >> 0);
    }

    /* 4.4.3.7. Secured Extensions (variable) */
    if (messagePayload.has_secured_extensions()) {
        payloadPacket.insert(payloadPacket.end(), 
            messagePayload.secured_extensions().begin(),
            messagePayload.secured_extensions().end());
    }

    payloadPacket.insert(payloadPacket.end(), 
        messagePayload.application_payload().begin(),
        messagePayload.application_payload().end());

    packet.insert(packet.end(), payloadPacket.begin(), payloadPacket.end());

    return packet;
}

Transport::PeerAddress AddressFromString(const char * str)
{
    Inet::IPAddress addr;

    VerifyOrDie(Inet::IPAddress::FromString(str, addr));

    return Transport::PeerAddress::UDP(addr);
}

uint16_t kLocalSessionId = 1;
uint16_t kPeerSessionId = 2;
const NodeId kLocalNodeId = 123;
const NodeId kPeerNodeId = 123;
const FabricIndex kFabricIndex = 1;
const Transport::PeerAddress kPeerAddress = AddressFromString("fe80::1");

void CleanShutdown()
{
    Server::GetInstance().Shutdown();
    PlatformMgr().Shutdown();
    // TODO: We don't Platform::MemoryShutdown because ~CASESessionManager calls
    // Dnssd::ResolverProxy::Shutdown, which starts doing Platform::Delete.
    // Platform::MemoryShutdown();
}

DEFINE_PROTO_FUZZER(const chip_message::ChipMessage& message) {
    protobuf_mutator::protobuf::FileDescriptorProto file;

    static auto fuzzCampaignStart = std::chrono::steady_clock::now();
    static auto fuzzCampaignMinutes = [](){
        char *envString = getenv("FUZZ_CAMPAIGN_MINUTES");

        int minutes = (envString == NULL) ? 0 : atoi(envString);
        if (minutes > 0) std::cerr << "FUZZ_CAMPAIGN_MINUTES: " << minutes << std::endl;

        return minutes;
    } ();

    // Check elapsed time
    if (fuzzCampaignMinutes > 0) {
        auto current = std::chrono::steady_clock::now();
        auto elapsedMinutes = std::chrono::duration_cast<std::chrono::minutes>(current - fuzzCampaignStart).count();
        if (elapsedMinutes >= fuzzCampaignMinutes) {
            // Passed scheduled end
            std::cerr << "Stopping fuzzing after " << elapsedMinutes << " minutes" << std::endl; 
            __gcov_dump();
            exit(0);
        }
    }

    std::vector<uint8_t> packet = PacketFromProtoMessage(message);
    chip::Encoding::LogBufferAsHex("PROTOPACKET", ByteSpan(packet.data(), packet.size()));
    // std::cerr << "Packet: " << (unsigned int)packet[0] << " " << (unsigned int)packet[1] << " " << (unsigned int)packet[2] << std::endl;

    const uint8_t * aData = packet.data();
    size_t aSize = packet.size();

    static bool matterStackInitialized = false;
    if (!matterStackInitialized)
    {
        // Might be simpler to do ChipLinuxAppInit() with argc == 0, argv set to
        // just a fake executable name?
        VerifyOrDie(Platform::MemoryInit() == CHIP_NO_ERROR);
        VerifyOrDie(PlatformMgr().InitChipStack() == CHIP_NO_ERROR);

	    VerifyOrDie(chip::examples::InitCommissionableDataProvider(gCommissionableDataProvider,
                                                                   LinuxDeviceOptions::GetInstance()) == CHIP_NO_ERROR);
        SetCommissionableDataProvider(&gCommissionableDataProvider);


        // ChipLinuxAppMainLoop blocks, and we don't want that here.
        static chip::CommonCaseDeviceServerInitParams initParams;
        (void) initParams.InitializeStaticResourcesBeforeServerInit();
        VerifyOrDie(Server::GetInstance().Init(initParams) == CHIP_NO_ERROR);

        ApplicationInit();

        // We don't start the event loop task, because we don't plan to deliver
        // data on a separate thread.

        matterStackInitialized = true;

        // And add a test session
        SessionHolder testSessionHolder;
        Server::GetInstance().GetSecureSessionManager().InjectCaseSessionWithTestKey(testSessionHolder, kLocalSessionId,
            kPeerSessionId, kLocalNodeId, kPeerNodeId, kFabricIndex, kPeerAddress, CryptoContext::SessionRole::kResponder);

        // The fuzzer does not have a way to tell us when it's done, so just
        // shut down things on exit.
        atexit(CleanShutdown);
    }

    // For now, just dump the data as a UDP payload into the session manager.
    // But maybe we should try to separately extract a PeerAddress and data from
    // the incoming data?
    Transport::PeerAddress peerAddr;
    System::PacketBufferHandle buf =
        System::PacketBufferHandle::NewWithData(aData, aSize, /* aAdditionalSize = */ 0, /* aReservedSize = */ 0);
    if (buf.IsNull())
    {
        // Too big; we couldn't represent this as a packetbuffer to start with.
        // return 0;
        return;
    }

    // Ignoring the return value from OnMessageReceived, because we might be
    // passing it all sorts of garbage that will cause it to fail.
    Server::GetInstance().GetSecureSessionManager().OnMessageReceived(peerAddr, std::move(buf));

    // Now process pending events until our sentinel is reached.
    PlatformMgr().ScheduleWork([](intptr_t) { PlatformMgr().StopEventLoopTask(); });
    PlatformMgr().RunEventLoop();

    // // Emulate a bug.
    // if (message.optional_string() == "ab") {
    //     std::cerr << message.DebugString() << "\n";
    //     abort();
    // }
}

// extern "C" int LLVMFuzzerTestOneInput(const uint8_t * aData, size_t aSize)
// {
    // static auto fuzzCampaignStart = std::chrono::steady_clock::now();
    // static auto fuzzCampaignMinutes = [](){
    //     char *envString = getenv("FUZZ_CAMPAIGN_MINUTES");

    //     int minutes = (envString == NULL) ? 0 : atoi(envString);
    //     if (minutes > 0) std::cerr << "FUZZ_CAMPAIGN_MINUTES: " << minutes << std::endl;

    //     return minutes;
    // } ();

    // // Check elapsed time
    // if (fuzzCampaignMinutes > 0) {
    //     auto current = std::chrono::steady_clock::now();
    //     auto elapsedMinutes = std::chrono::duration_cast<std::chrono::minutes>(current - fuzzCampaignStart).count();
    //     if (elapsedMinutes >= fuzzCampaignMinutes) {
    //         // Passed scheduled end
    //         std::cerr << "Stopping fuzzing after " << elapsedMinutes << " minutes" << std::endl; 
    //         __gcov_dump();
    //         exit(0);
    //     }
    // }

    // static bool matterStackInitialized = false;
    // if (!matterStackInitialized)
    // {
    //     // Might be simpler to do ChipLinuxAppInit() with argc == 0, argv set to
    //     // just a fake executable name?
    //     VerifyOrDie(Platform::MemoryInit() == CHIP_NO_ERROR);
    //     VerifyOrDie(PlatformMgr().InitChipStack() == CHIP_NO_ERROR);

	//     VerifyOrDie(chip::examples::InitCommissionableDataProvider(gCommissionableDataProvider,
    //                                                                LinuxDeviceOptions::GetInstance()) == CHIP_NO_ERROR);
    //     SetCommissionableDataProvider(&gCommissionableDataProvider);


    //     // ChipLinuxAppMainLoop blocks, and we don't want that here.
    //     static chip::CommonCaseDeviceServerInitParams initParams;
    //     (void) initParams.InitializeStaticResourcesBeforeServerInit();
    //     VerifyOrDie(Server::GetInstance().Init(initParams) == CHIP_NO_ERROR);

    //     ApplicationInit();

    //     // We don't start the event loop task, because we don't plan to deliver
    //     // data on a separate thread.

    //     matterStackInitialized = true;

    //     // The fuzzer does not have a way to tell us when it's done, so just
    //     // shut down things on exit.
    //     atexit(CleanShutdown);
    // }

    // // For now, just dump the data as a UDP payload into the session manager.
    // // But maybe we should try to separately extract a PeerAddress and data from
    // // the incoming data?
    // Transport::PeerAddress peerAddr;
    // System::PacketBufferHandle buf =
    //     System::PacketBufferHandle::NewWithData(aData, aSize, /* aAdditionalSize = */ 0, /* aReservedSize = */ 0);
    // if (buf.IsNull())
    // {
    //     // Too big; we couldn't represent this as a packetbuffer to start with.
    //     return 0;
    // }

    // // Ignoring the return value from OnMessageReceived, because we might be
    // // passing it all sorts of garbage that will cause it to fail.
    // Server::GetInstance().GetSecureSessionManager().OnMessageReceived(peerAddr, std::move(buf));

    // // Now process pending events until our sentinel is reached.
    // PlatformMgr().ScheduleWork([](intptr_t) { PlatformMgr().StopEventLoopTask(); });
    // PlatformMgr().RunEventLoop();
    // return 0;
// }
