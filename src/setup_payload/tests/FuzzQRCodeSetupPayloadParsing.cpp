#include <cstdint>
#include <iostream>

#include "setup_payload/QRCodeSetupPayloadParser.h"
#include "setup_payload/Base38Decode.h"

using namespace chip;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    chip::Platform::MemoryInit();

    std::string s((const char*)data, len);
    SetupPayload payload;
    CHIP_ERROR err = QRCodeSetupPayloadParser(s).populatePayload(payload);

    if (err == CHIP_NO_ERROR) {
        std::cout << "No error!";
    }

    return 0;
}