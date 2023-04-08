#include <cstddef>
#include <cstdint>

#include "setup_payload/QRCodeSetupPayloadParser.h"
#include "setup_payload/Base38Decode.h"

using namespace chip;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    std::string s((const char*)data, len);
    QRCodeSetupPayloadParser::ExtractPayload(s);
    std::vector<uint8_t> buf;
    base38Decode(s, buf);

    return 0;
}
