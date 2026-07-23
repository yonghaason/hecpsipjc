#pragma once

#include "volePSI/RsCpsi.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"

#ifdef VOLE_PSI_ENABLE_CPSI

namespace volePSI
{
    struct PsiInnerproductConfig
    {
        u64 mPrime = RsCpsiDefaultPrime;
        u64 mStatSecParam = 40;
        u64 mNumThreads = 1;

        u64 dataByteLength() const { return RsCpsiDataByteLength(mPrime); }
        u64 shareByteLength() const { return RsCpsiPrimeByteLength(mPrime); }
    };

    inline void writePsiIpPrimeElement(u8* dst, u64 byteLength, u64 v)
    {
        std::memcpy(dst, &v, byteLength);
    }

    inline void setPsiIpPrimeValues(oc::Matrix<u8>& values, span<const u64> associatedData, u64 byteLength)
    {
        for (u64 i = 0; i < associatedData.size(); ++i)
            writePsiIpPrimeElement(&values(i, 0), byteLength, associatedData[i]);
    }

    Proto psiIpB2aValueOwner(
        const oc::BitVector& bitShare,
        oc::MatrixView<u8> values,
        oc::Matrix<u8>& arithmeticShare,
        const PsiInnerproductConfig& config,
        PRNG& prng,
        Socket& chl);

    Proto psiIpB2aChoiceOwner(
        const oc::BitVector& bitShare,
        u64 rowCount,
        u64 valueByteLength,
        oc::Matrix<u8>& arithmeticShare,
        const PsiInnerproductConfig& config,
        PRNG& prng,
        Socket& chl);

    void psiIpAddPrimeShares(
        oc::MatrixView<u8> lhs,
        oc::MatrixView<u8> rhs,
        oc::Matrix<u8>& out,
        const PsiInnerproductConfig& config);

    class PsiInnerproductSender : public oc::TimerAdapter
    {
    public:
        using CpsiSharing = RsCpsiSender::Sharing;

        void init(u64 senderSize, u64 receiverSize, const PsiInnerproductConfig& config, block seed)
        {
            mConfig = config;
            mPrng.SetSeed(seed ^ block(0x6a09e667f3bcc908, 0xbb67ae8584caa73b));
            mCpsi.init(
                senderSize,
                receiverSize,
                mConfig.dataByteLength(),
                mConfig.mStatSecParam,
                seed,
                mConfig.mNumThreads,
                ValueShareType::prime,
                mConfig.mPrime);
        }

        Proto send(span<block> identifiers, span<const u64> associatedData, CpsiSharing& share, Socket& chl)
        {
            if (identifiers.size() != associatedData.size())
            {
                co_await chl.close();
                throw RTE_LOC;
            }

            oc::Matrix<u8> values(associatedData.size(), mConfig.dataByteLength());
            setPsiIpPrimeValues(values, associatedData, mConfig.dataByteLength());

            if (mTimer)
                mCpsi.setTimer(*mTimer);

            co_await mCpsi.send(identifiers, values, share, chl);
        }

        Proto send(span<block> identifiers, span<const u64> associatedData, CpsiSharing& share, oc::Matrix<u8>& arithmeticShare, Socket& chl)
        {
            auto ownedValueShare = oc::Matrix<u8>{};
            auto receivedValueShare = oc::Matrix<u8>{};

            co_await send(identifiers, associatedData, share, chl);
            co_await psiIpB2aValueOwner(share.mFlagBits, share.mValues, ownedValueShare, mConfig, mPrng, chl);
            co_await psiIpB2aChoiceOwner(share.mFlagBits, share.mValues.rows(), share.mValues.cols(), receivedValueShare, mConfig, mPrng, chl);
            psiIpAddPrimeShares(ownedValueShare, receivedValueShare, arithmeticShare, mConfig);
        }

    private:
        PsiInnerproductConfig mConfig;
        PRNG mPrng;
        RsCpsiSender mCpsi;
    };

    class PsiInnerproductReceiver : public oc::TimerAdapter
    {
    public:
        using CpsiSharing = RsCpsiReceiver::Sharing;

        void init(u64 senderSize, u64 receiverSize, const PsiInnerproductConfig& config, block seed)
        {
            mConfig = config;
            mPrng.SetSeed(seed ^ block(0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1));
            mCpsi.init(
                senderSize,
                receiverSize,
                mConfig.dataByteLength(),
                mConfig.mStatSecParam,
                seed,
                mConfig.mNumThreads,
                ValueShareType::prime,
                mConfig.mPrime);
        }

        Proto receive(span<block> identifiers, CpsiSharing& share, Socket& chl)
        {
            if (mTimer)
                mCpsi.setTimer(*mTimer);

            co_await mCpsi.receive(identifiers, share, chl);
        }

        Proto receive(span<block> identifiers, CpsiSharing& share, oc::Matrix<u8>& arithmeticShare, Socket& chl)
        {
            auto receivedValueShare = oc::Matrix<u8>{};
            auto ownedValueShare = oc::Matrix<u8>{};

            co_await receive(identifiers, share, chl);
            co_await psiIpB2aChoiceOwner(share.mFlagBits, share.mValues.rows(), share.mValues.cols(), receivedValueShare, mConfig, mPrng, chl);
            co_await psiIpB2aValueOwner(share.mFlagBits, share.mValues, ownedValueShare, mConfig, mPrng, chl);
            psiIpAddPrimeShares(receivedValueShare, ownedValueShare, arithmeticShare, mConfig);
        }

    private:
        PsiInnerproductConfig mConfig;
        PRNG mPrng;
        RsCpsiReceiver mCpsi;
    };
}

#endif
