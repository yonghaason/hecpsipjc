

#include "cryptoTools/Common/Log.h"
#include <functional>
#include "UnitTests.h"

#include "RsCpsi_Tests.h"
#include "RsPsiInnerproduct_Perf.h"
#include "Pso_Tests.h"

namespace volePSI_Tests
{
    oc::TestCollection Tests([](oc::TestCollection& t) {

#ifdef VOLE_PSI_ENABLE_CPSI
        t.add("Cpsi_Rs_full_prime_test        ", Cpsi_Rs_full_prime_test);
#ifdef VOLE_PSI_ENABLE_SEAL
        t.add("RsPsiInnerproduct_seal_test    ", RsPsiInnerproduct_seal_test);
        t.add("RsPsiInnerproduct_seal_rns_test", RsPsiInnerproduct_seal_rns_test);
        t.add("RsPsiInnerproduct_perf_test    ", RsPsiInnerproduct_perf_test);
        t.add("KLS26_innerprod_32_test        ", Pso_innerprod_32_test);
        t.add("KLS26_innerprod_84_test        ", Pso_innerprod_84_test);
#endif
#endif

    });
}
