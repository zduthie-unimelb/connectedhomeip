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

#include <CommissionableInit.h>

#include <chrono>
#include <iostream>

#if CHIP_CONFIG_SECURITY_FUZZ_LOGGING
#include <lib/support/BytesToHex.h>
#endif

// extern "C" void __gcov_dump();

using namespace chip;
using namespace chip::DeviceLayer;

namespace {

LinuxCommissionableDataProvider gCommissionableDataProvider;

}

void CleanShutdown()
{
    Server::GetInstance().Shutdown();
    PlatformMgr().Shutdown();
    // TODO: We don't Platform::MemoryShutdown because ~CASESessionManager calls
    // Dnssd::ResolverProxy::Shutdown, which starts doing Platform::Delete.
    // Platform::MemoryShutdown();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * aData, size_t aSize)
{

#if CHIP_CONFIG_SECURITY_FUZZ_LOGGING
    ChipLogProgress(Test, "<SIKE-1>fuzzing-main");
    chip::Encoding::LogBufferAsHex("LLVMFuzzerTestOneInput", chip::ByteSpan(aData, aSize));
#endif


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
            // __gcov_dump();
            exit(0);
        }
    }

    static bool matterStackInitialized = false;
    if (!matterStackInitialized)
    {

        // Debug #defines
        std::cerr << "   *** Initialising:";
        
        #ifdef CHIP_CONFIG_SECURITY_TEST_MODE
        std::cerr << " CHIP_CONFIG_SECURITY_TEST_MODE=" << CHIP_CONFIG_SECURITY_TEST_MODE;
        #else
        std::cerr << " CHIP_CONFIG_SECURITY_TEST_MODE=Undefined"
        #endif

        #ifdef CHIP_CONFIG_SECURITY_FUZZ_MODE
        std::cerr << " CHIP_CONFIG_SECURITY_FUZZ_MODE=" << CHIP_CONFIG_SECURITY_FUZZ_MODE;
        #else
        std::cerr << " CHIP_CONFIG_SECURITY_FUZZ_MODE=Undefined"
        #endif

        #ifdef CHIP_CONFIG_SECURITY_FUZZ_LOGGING
        std::cerr << " CHIP_CONFIG_SECURITY_FUZZ_LOGGING=" << CHIP_CONFIG_SECURITY_FUZZ_LOGGING;
        #else
        std::cerr << " CHIP_CONFIG_SECURITY_FUZZ_LOGGING=Undefined"
        #endif

        #ifdef CHIP_CONFIG_SECURITY_FUZZ_SEED_BUG_1
        std::cerr << " CHIP_CONFIG_SECURITY_FUZZ_SEED_BUG_1=" << CHIP_CONFIG_SECURITY_FUZZ_SEED_BUG_1;
        #else
        std::cerr << " CHIP_CONFIG_SECURITY_FUZZ_SEED_BUG_1=Undefined"
        #endif

        std::cerr << " *** " << std::endl; 

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
        return 0;
    }

    // // Wireshark: Copy as escaped string
// Step1
const char *packet1 = "\x04\x00\x00\x00\xf8\x8a\x34\x05\x13\xdb\x8a\xfa\x59\x1c\xfe\xca" \
    "\x05\x20\x1f\x7d\x00\x00\x15\x30\x01\x20\x63\xfb\x3b\xee\x65\xbf" \
    "\xfb\x11\xc0\xd4\xde\x2c\x18\xdd\x45\x0c\x6d\x9c\xee\x99\xb4\xd0" \
    "\x9c\x01\x16\xda\xba\xaf\xe4\xeb\x1f\xee\x25\x02\x4e\x17\x24\x03" \
    "\x00\x28\x04\x18";
size_t packet1_size = 68;

// // Step2
// const char *packet2 = "\x04\x00\x00\x00\xf9\x8a\x34\x05\x13\xdb\x8a\xfa\x59\x1c\xfe\xca" \
//     "\x05\x22\x1f\x7d\x00\x00\x15\x30\x01\x41\x04\x18" \
//     "\x80\xbf\xd6\xf6\x1c\xd7\x64\xb1\x5d\x78\xa9\x32\x33\xd3\x48\x85" \
//     "\x6a\xb1\x01\xfe\x3c\x46\x51\x7d\xbe\xf1\x88\x63\x77\xb6\x25\x9c" \
//     "\x16\x54\x69\xbd\x57\x98\xb2\x1f\x37\xac\xe7\x17\x74\xda\x81\x06" \
//     "\x14\x88\xae\xbb\x63\xff\x53\x3c\xd9\x7d\x86\x4e\x95\x9b\xc3\x18";
// size_t packet2_size = 92;

// Step2
const char *packet2 = "\x04\x00\x00\x00\xf9\x8a\x34\x05\x13\xdb\x8a\xfa\x59\x1c\xfe\xca" \
    "\x05\x22\x1f\x7d\x00\x00\x5c\x1b\x42\x05\x15\x30\x01\x41\x04\x18" \
    "\x80\xbf\xd6\xf6\x1c\xd7\x64\xb1\x5d\x78\xa9\x32\x33\xd3\x48\x85" \
    "\x6a\xb1\x01\xfe\x3c\x46\x51\x7d\xbe\xf1\x88\x63\x77\xb6\x25\x9c" \
    "\x16\x54\x69\xbd\x57\x98\xb2\x1f\x37\xac\xe7\x17\x74\xda\x81\x06" \
    "\x14\x88\xae\xbb\x63\xff\x53\x3c\xd9\x7d\x86\x4e\x95\x9b\xc3\x18";
size_t packet2_size = 96;

// const char *packet2 = "\x04\x00\x00\x00\xf9\x8a\x34\x05\x13\xdb\x8a\xfa\x59\x1c\xfe\xca" \
// "\x07\x22\x1f\x7d\x00\x00\x5c\x1b\x42\x05\x15\x30\x01\x41\x04\x18" \
// "\x80\xbf\xd6\xf6\x1c\xd7\x64\xb1\x5d\x78\xa9\x32\x33\xd3\x48\x85" \
// "\x6a\xb1\x01\xfe\x3c\x46\x51\x7d\xbe\xf1\x88\x63\x77\xb6\x25\x9c" \
// "\x16\x54\x69\xbd\x57\x98\xb2\x1f\x37\xac\xe7\x17\x74\xda\x81\x06" \
// "\x14\x88\xae\xbb\x63\xff\x53\x3c\xd9\x7d\x86\x4e\x95\x9b\xc3\x18";
// size_t packet2_size = 96;

// // VerifyOrDie(false);
System::PacketBufferHandle buf_1 =
    System::PacketBufferHandle::NewWithData(packet1, packet1_size, 0, 0);
// Server::GetInstance().GetSecureSessionManager().OnMessageReceived(peerAddr, std::move(buf_1));

System::PacketBufferHandle buf_2 =
    System::PacketBufferHandle::NewWithData(packet2, packet2_size, 0, 0);
// Server::GetInstance().GetSecureSessionManager().OnMessageReceived(peerAddr, std::move(buf_2));

    // Ignoring the return value from OnMessageReceived, because we might be
    // passing it all sorts of garbage that will cause it to fail.
    Server::GetInstance().GetSecureSessionManager().OnMessageReceived(peerAddr, std::move(buf));

    // Now process pending events until our sentinel is reached.
    PlatformMgr().ScheduleWork([](intptr_t) { PlatformMgr().StopEventLoopTask(); });
    PlatformMgr().RunEventLoop();
    return 0;
}
