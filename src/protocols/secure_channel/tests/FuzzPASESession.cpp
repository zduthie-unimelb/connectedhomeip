
// See TestPASESession.cpp for relevant #include and namespace 
#include <cstddef>
#include <cstdint>
#include <errno.h>

#include <lib/core/CHIPCore.h>
#include <lib/core/CHIPSafeCasts.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/UnitTestContext.h>
#include <lib/support/UnitTestRegistration.h>
#include <lib/support/UnitTestUtils.h>
#include <messaging/tests/MessagingContext.h>
#include <protocols/secure_channel/PASESession.h>
#include <stdarg.h>

using namespace chip;
using namespace chip::Inet;
using namespace chip::Transport;
using namespace chip::Messaging;
using namespace chip::Protocols;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t len)
{

    // Skeleton code for PASESession Fuzz driver

    if (len >= 3 && data[0] == 0x01 && data[1] == 0x02 && data[2] == 0x03) {
        VerifyOrDie(false);
    }

    return 0;
}