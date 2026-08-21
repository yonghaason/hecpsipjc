#pragma once

#include "volePSI/Defines.h"
#include "volePSI/config.h"
#ifdef VOLE_PSI_ENABLE_CPSI
#include "volePSI/RsCpsi.h"
#include "volePSI/GMW/SilentTripleGen.h"

#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Circuit/BetaLibrary.h"

namespace volePSI
{
    class PsoReceiver : public details::RsCpsiBase, public oc::TimerAdapter
    {
        SilentTripleGen mOtFactory;
        oc::BetaLibrary lib;

    public:
        Proto setup(Socket& chl) {
            auto cuckoo = oc::CuckooIndex<>();
            cuckoo.init(mRecverSize, mSsp, 0, 3);
            auto numBins = cuckoo.mBins.size();
            auto keyBitLength = mSsp + oc::log2ceil(numBins);
            u64 numTriples = 128 * oc::divCeil(numBins, 128) * (keyBitLength - 1) * 2;
            mSetup = true;
            u64 batchSize = 1;
            while (batchSize < numTriples) 
            {
                batchSize <<= 1;
                if (batchSize == (1ull << 25)) break;
            }

            mOtFactory.init(numTriples, batchSize, mNumThreads, Mode::Sender, mPrng.get());
            MC_BEGIN(Proto, this, &chl, setup_end_flag = bool{});
            MC_AWAIT(mOtFactory.generateBaseOts(0, mPrng, chl));
            MC_AWAIT(mOtFactory.expand(chl));
            MC_AWAIT(chl.recv(setup_end_flag));
            comm = chl.bytesSent() - comm;
            setTimePoint("PsoReceiver::CPSI Setup");
            // std::cout << "PsoReceiver::CPSI setup = " << (double) comm / (1 << 20) << " MB" << std::endl;
            MC_END();
        }

        Proto receiveInnerProd(span<block> X, span<int32_t> data, int32_t& innerprod, Socket& chl);
        // 84-bit width harness: XOR arithmetic over 11-byte values. Cost-identical to the
        // additive protocol (same OKVS, OT and MultShare widths); result is not an inner product.
        using Wide = std::array<u8, 11>;
        Proto receiveInnerProdWide(span<block> X, span<Wide> data, Wide& innerprod, Socket& chl);

    };

    class PsoSender : public details::RsCpsiBase, public oc::TimerAdapter
    {
        SilentTripleGen mOtFactory;
        oc::BetaLibrary lib;

    public:
        Proto setup(Socket& chl) {
            auto cuckoo = oc::CuckooIndex<>();
            cuckoo.init(mRecverSize, mSsp, 0, 3);
            auto numBins = cuckoo.mBins.size();
            auto keyBitLength = mSsp + oc::log2ceil(numBins);
            u64 numTriples = 128 * oc::divCeil(numBins, 128) * (keyBitLength - 1) * 2;
            mSetup = true;
            u64 batchSize = 1;
            while (batchSize < numTriples) 
            {
                batchSize <<= 1;
                if (batchSize == (1ull << 25)) break;
            }
            
            mOtFactory.init(numTriples, batchSize, mNumThreads, Mode::Receiver, mPrng.get());

            MC_BEGIN(Proto, this, &chl, setup_end_flag = bool{});
            MC_AWAIT(mOtFactory.generateBaseOts(1, mPrng, chl));
            MC_AWAIT(mOtFactory.expand(chl));
            MC_AWAIT(chl.send(setup_end_flag));
            comm = chl.bytesSent() - comm;
            setTimePoint("PsoSender::CPSI Setup");
            // std::cout << "PsoReceiver::CPSI setup = " << (double) comm / (1 << 20) << " MB" << std::endl;
            MC_END();            
        }

        Proto sendInnerProd(span<block> Y, span<int32_t> data, Socket& chl);
        using Wide = std::array<u8, 11>;
        Proto sendInnerProdWide(span<block> Y, span<Wide> data, Socket& chl);
    };
    

}

#endif
