#pragma once

#include "cryptoTools/Common/CLP.h"

void RsPsiInnerproduct_perf_test(const oc::CLP&);
#ifdef VOLE_PSI_ENABLE_SEAL
void RsPsiInnerproduct_seal_test(const oc::CLP&);
#endif
