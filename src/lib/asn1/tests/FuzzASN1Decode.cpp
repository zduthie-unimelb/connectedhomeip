#include <cstddef>
#include <cstdint>

#include <credentials/CHIPCert.h>
#include <lib/asn1/ASN1.h>

using namespace chip;
using namespace chip::ASN1;
using namespace chip::Credentials;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{
    ASN1Reader reader;
    reader.Init(data, len);

    ChipDN dn;
    ReturnErrorOnFailure(dn.DecodeFromASN1(reader));

    return 0;
}
