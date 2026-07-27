#include "PSI_Innerproduct.h"

#ifdef VOLE_PSI_ENABLE_CPSI

#include "libOTe/TwoChooseOne/Silent/SilentOtExtSender.h"
#include "libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h"
#include "cryptoTools/Common/Aligned.h"

namespace volePSI
{
    namespace
    {
        u64 readPsiIpPrimeElement(const u8* src, u64 byteLength)
        {
            auto v = u64{};
            std::memcpy(&v, src, byteLength);
            return v;
        }

        u64 modAddPsiIp(u64 lhs, u64 rhs, u64 prime)
        {
            auto rem = prime - lhs;
            return rhs >= rem ? rhs - rem : lhs + rhs;
        }

        u64 modSubPsiIp(u64 lhs, u64 rhs, u64 prime)
        {
            return lhs >= rhs ? lhs - rhs : prime - (rhs - lhs);
        }

        u64 modNegPsiIp(u64 v, u64 prime)
        {
            return v ? prime - v : 0;
        }

        block encodePsiIpBlock(u64 v)
        {
            return block(0, v);
        }

        u64 decodePsiIpBlock(block v, u64 prime)
        {
            return v.get<u64>(0) % prime;
        }
    }

    Proto psiIpB2aValueOwner(
        const oc::BitVector& bitShare,
        oc::MatrixView<u8> values,
        oc::Matrix<u8>& arithmeticShare,
        const PsiInnerproductConfig& config,
        PRNG& prng,
        Socket& chl)
    {
#ifdef ENABLE_SILENTOT
        auto rowCount = values.rows();
        auto valueByteLength = values.cols();
        auto elemByteLength = config.shareByteLength();
        auto elemCount = valueByteLength / elemByteLength;
        auto otCount = rowCount * elemCount;
        auto otSender = oc::SilentOtExtSender{};
        auto messages = oc::AlignedUnVector<std::array<block, 2>>{};

        if (valueByteLength % elemByteLength)
        {
            co_await chl.close();
            throw RTE_LOC;
        }

        arithmeticShare.resize(rowCount, valueByteLength);
        messages.resize(otCount);

        co_await otSender.genBaseOts(prng, chl);

        for (u64 i = 0, k = 0; i < rowCount; ++i)
        {
            auto b = bitShare[i];
            for (u64 j = 0; j < valueByteLength; j += elemByteLength, ++k)
            {
                auto x = readPsiIpPrimeElement(&values(i, j), elemByteLength) % config.mPrime;
                auto r = prng.get<u64>() % config.mPrime;
                auto zeroShare = modNegPsiIp(r, config.mPrime);
                auto oneShare = modSubPsiIp(x, r, config.mPrime);

                writePsiIpPrimeElement(&arithmeticShare(i, j), elemByteLength, r);

                if (b)
                {
                    messages[k][0] = encodePsiIpBlock(oneShare);
                    messages[k][1] = encodePsiIpBlock(zeroShare);
                }
                else
                {
                    messages[k][0] = encodePsiIpBlock(zeroShare);
                    messages[k][1] = encodePsiIpBlock(oneShare);
                }
            }
        }

        co_await otSender.sendChosen(messages, prng, chl);
#else
        (void)bitShare;
        (void)values;
        (void)arithmeticShare;
        (void)config;
        (void)prng;
        co_await chl.close();
        throw RTE_LOC;
#endif
    }

    Proto psiIpB2aChoiceOwner(
        const oc::BitVector& bitShare,
        u64 rowCount,
        u64 valueByteLength,
        oc::Matrix<u8>& arithmeticShare,
        const PsiInnerproductConfig& config,
        PRNG& prng,
        Socket& chl)
    {
#ifdef ENABLE_SILENTOT
        auto elemByteLength = config.shareByteLength();
        auto elemCount = valueByteLength / elemByteLength;
        auto otCount = rowCount * elemCount;
        auto choices = oc::BitVector{};
        auto otReceiver = oc::SilentOtExtReceiver{};
        auto messages = oc::AlignedUnVector<block>{};

        if (valueByteLength % elemByteLength)
        {
            co_await chl.close();
            throw RTE_LOC;
        }

        arithmeticShare.resize(rowCount, valueByteLength);
        choices.resize(otCount);
        messages.resize(otCount);

        for (u64 i = 0, k = 0; i < rowCount; ++i)
        {
            auto b = bitShare[i];
            for (u64 j = 0; j < elemCount; ++j, ++k)
                choices[k] = b;
        }

        co_await otReceiver.genBaseOts(prng, chl);
        co_await otReceiver.receiveChosen(choices, messages, prng, chl);

        for (u64 i = 0, k = 0; i < rowCount; ++i)
        {
            for (u64 j = 0; j < valueByteLength; j += elemByteLength, ++k)
            {
                auto v = decodePsiIpBlock(messages[k], config.mPrime);
                writePsiIpPrimeElement(&arithmeticShare(i, j), elemByteLength, v);
            }
        }
#else
        (void)bitShare;
        (void)rowCount;
        (void)valueByteLength;
        (void)arithmeticShare;
        (void)config;
        (void)prng;
        co_await chl.close();
        throw RTE_LOC;
#endif
    }

    void psiIpAddPrimeShares(
        oc::MatrixView<u8> lhs,
        oc::MatrixView<u8> rhs,
        oc::Matrix<u8>& out,
        const PsiInnerproductConfig& config)
    {
        auto elemByteLength = config.shareByteLength();

        if (lhs.rows() != rhs.rows() || lhs.cols() != rhs.cols() || lhs.cols() % elemByteLength)
            throw RTE_LOC;

        out.resize(lhs.rows(), lhs.cols());

        for (u64 i = 0; i < lhs.rows(); ++i)
        {
            for (u64 j = 0; j < lhs.cols(); j += elemByteLength)
            {
                auto a = readPsiIpPrimeElement(&lhs(i, j), elemByteLength);
                auto b = readPsiIpPrimeElement(&rhs(i, j), elemByteLength);
                writePsiIpPrimeElement(&out(i, j), elemByteLength, modAddPsiIp(a, b, config.mPrime));
            }
        }
    }
}

#endif
