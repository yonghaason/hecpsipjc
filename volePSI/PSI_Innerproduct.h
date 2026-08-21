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
        u64 mSealPolyModulusDegree = 4096;
        // Coefficient modulus bit sizes. The last entry is SEAL's special
        // prime, reserved for key switching; this protocol never key switches,
        // so it is kept as small as SEAL allows and the rest of the budget is
        // left to the ciphertext modulus.
        std::vector<int> mSealCoeffModulusBits = { 48, 36, 18 };
        // When false, SEALContext is built with sec_level_type::none. Used by the
        // long-item setting, whose residues exceed SEAL's 128-bit table at N=4096
        // although only the first two coefficient primes are ever used.
        bool mSealEnforceSecurity = true;

        // Residue primes for the long-item setting. Empty means single residue.
        std::vector<u64> mPrimes = {};
        // Payload width; 0 keeps the default half-residue width.
        u64 mDataBitLength = 0;

        u64 residueCount() const { return mPrimes.empty() ? 1 : mPrimes.size(); }
        u64 residuePrime(u64 slot) const
        {
            return mPrimes.empty() ? mPrime : mPrimes[slot % mPrimes.size()];
        }
        u64 dataByteLength() const
        {
            auto one = mDataBitLength ? oc::divCeil(mDataBitLength, 8)
                                      : RsCpsiDataByteLength(mPrime);
            return one * residueCount();
        }
        // width of a single residue share
        u64 shareByteLength() const { return RsCpsiPrimeByteLength(mPrime); }
        // width of a full RNS share across all residues
        u64 totalShareByteLength() const { return shareByteLength() * residueCount(); }
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

    // Long-item layout: the payload is written once per residue slot so that
    // the CPSI data component carries (d, d, ..., d); each slot is then
    // reduced modulo its own residue prime inside RsCpsi.
    inline void setPsiIpPrimeValuesRns(oc::Matrix<u8>& values, span<const u64> associatedData,
        u64 slotByteLength, u64 residueCount)
    {
        for (u64 i = 0; i < associatedData.size(); ++i)
            for (u64 j = 0; j < residueCount; ++j)
                writePsiIpPrimeElement(&values(i, j * slotByteLength), slotByteLength, associatedData[i]);
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

#ifdef VOLE_PSI_ENABLE_SEAL
    Proto psiIpHeSender(oc::MatrixView<u8> arithmeticShare, u64& result,
        const PsiInnerproductConfig& config, PRNG& prng, Socket& chl);
    Proto psiIpHeReceiver(span<const u64> receiverPayload,
        const RsCpsiReceiver::Sharing& receiverSharing, oc::MatrixView<u8> arithmeticShare,
        const PsiInnerproductConfig& config, Socket& chl);

    extern bool gPsiIpRnsDebug;
    bool psiIpSealParamsValid(const PsiInnerproductConfig& config);

    // RNS variants: evaluate one residue at a time and combine by CRT.
    Proto psiIpHeSenderRns(oc::MatrixView<u8> arithmeticShare, unsigned __int128& result,
        const PsiInnerproductConfig& config, PRNG& prng, Socket& chl);
    Proto psiIpHeReceiverRns(span<const u64> receiverPayload,
        const RsCpsiReceiver::Sharing& receiverSharing, oc::MatrixView<u8> arithmeticShare,
        const PsiInnerproductConfig& config, Socket& chl);
#endif

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
                mConfig.mPrime,
                RsCpsiDefaultPrimeStatSecParam,
                mConfig.mPrimes,
                mConfig.mDataBitLength);
        }

        Proto send(span<block> identifiers, span<const u64> associatedData, CpsiSharing& share, Socket& chl)
        {
            if (identifiers.size() != associatedData.size())
            {
                co_await chl.close();
                throw RTE_LOC;
            }

            oc::Matrix<u8> values(associatedData.size(), mConfig.dataByteLength());
            setPsiIpPrimeValuesRns(values, associatedData,
                mConfig.dataByteLength() / mConfig.residueCount(), mConfig.residueCount());

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

#ifdef VOLE_PSI_ENABLE_SEAL
        Proto send(span<block> identifiers, span<const u64> associatedData, CpsiSharing& share,
            oc::Matrix<u8>& arithmeticShare, u64& result, Socket& chl)
        {
            co_await send(identifiers, associatedData, share, arithmeticShare, chl);
            co_await psiIpHeSender(arithmeticShare, result, mConfig, mPrng, chl);
        }
#endif

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
                mConfig.mPrime,
                RsCpsiDefaultPrimeStatSecParam,
                mConfig.mPrimes,
                mConfig.mDataBitLength);
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

#ifdef VOLE_PSI_ENABLE_SEAL
        Proto receive(span<block> identifiers, span<const u64> associatedData, CpsiSharing& share,
            oc::Matrix<u8>& arithmeticShare, Socket& chl)
        {
            if (identifiers.size() != associatedData.size())
            {
                co_await chl.close();
                throw RTE_LOC;
            }
            co_await receive(identifiers, share, arithmeticShare, chl);
            co_await psiIpHeReceiver(associatedData, share, arithmeticShare, mConfig, chl);
        }
#endif

    private:
        PsiInnerproductConfig mConfig;
        PRNG mPrng;
        RsCpsiReceiver mCpsi;
    };
}

#endif
