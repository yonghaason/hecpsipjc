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

        u64 samplePsiIpPrimeElement(PRNG& prng, u64 prime)
        {
            auto threshold = (u64(0) - prime) % prime;
            while (true)
            {
                auto candidate = prng.get<u64>();
                if (candidate >= threshold)
                    return candidate % prime;
            }
        }

        u64 psiIpRotKeyLow32ToField(block key, u64 prime)
        {
            return static_cast<u64>(key.get<u32>(0)) % prime;
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
        auto rotKeys = oc::AlignedUnVector<std::array<block, 2>>{};
        auto corrections = std::vector<u8>{};

        if (config.mPrime < 2 ||
            elemByteLength > sizeof(u64) ||
            valueByteLength % elemByteLength ||
            bitShare.size() < rowCount)
        {
            co_await chl.close();
            throw RTE_LOC;
        }

        arithmeticShare.resize(rowCount, valueByteLength);
        rotKeys.resize(otCount);
        corrections.resize(otCount * 2 * elemByteLength);

        for (u64 i = 0, k = 0; i < rowCount; ++i)
        {
            for (u64 j = 0; j < valueByteLength; j += elemByteLength, ++k)
            {
                auto r = samplePsiIpPrimeElement(prng, config.mPrime);
                writePsiIpPrimeElement(&arithmeticShare(i, j), elemByteLength, r);
            }
        }

        co_await otSender.genBaseOts(prng, chl);
        co_await otSender.send(rotKeys, prng, chl);

        for (u64 i = 0, k = 0; i < rowCount; ++i)
        {
            auto b = bitShare[i];
            for (u64 j = 0; j < valueByteLength; j += elemByteLength, ++k)
            {
                auto x = readPsiIpPrimeElement(&values(i, j), elemByteLength) % config.mPrime;
                auto r = readPsiIpPrimeElement(&arithmeticShare(i, j), elemByteLength);
                auto zeroShare = modNegPsiIp(r, config.mPrime);
                auto oneShare = modSubPsiIp(x, r, config.mPrime);
                auto m0 = b ? oneShare : zeroShare;
                auto m1 = b ? zeroShare : oneShare;
                auto mask0 = psiIpRotKeyLow32ToField(rotKeys[k][0], config.mPrime);
                auto mask1 = psiIpRotKeyLow32ToField(rotKeys[k][1], config.mPrime);

                writePsiIpPrimeElement(
                    corrections.data() + (2 * k) * elemByteLength,
                    elemByteLength,
                    modSubPsiIp(m0, mask0, config.mPrime));
                writePsiIpPrimeElement(
                    corrections.data() + (2 * k + 1) * elemByteLength,
                    elemByteLength,
                    modSubPsiIp(m1, mask1, config.mPrime));
            }
        }

        co_await chl.send(std::move(corrections));
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
        auto selectedKeys = oc::AlignedUnVector<block>{};
        auto corrections = std::vector<u8>{};

        if (config.mPrime < 2 ||
            elemByteLength > sizeof(u64) ||
            valueByteLength % elemByteLength ||
            bitShare.size() < rowCount)
        {
            co_await chl.close();
            throw RTE_LOC;
        }

        arithmeticShare.resize(rowCount, valueByteLength);
        choices.resize(otCount);
        selectedKeys.resize(otCount);
        corrections.resize(otCount * 2 * elemByteLength);

        for (u64 i = 0, k = 0; i < rowCount; ++i)
        {
            auto b = bitShare[i];
            for (u64 j = 0; j < elemCount; ++j, ++k)
                choices[k] = b;
        }

        co_await otReceiver.genBaseOts(prng, chl);
        co_await otReceiver.receive(choices, selectedKeys, prng, chl);
        co_await chl.recv(corrections);

        for (u64 i = 0, k = 0; i < rowCount; ++i)
        {
            for (u64 j = 0; j < valueByteLength; j += elemByteLength, ++k)
            {
                auto choice = static_cast<u64>(choices[k]);
                auto correction = readPsiIpPrimeElement(
                    corrections.data() + (2 * k + choice) * elemByteLength,
                    elemByteLength);
                auto mask = psiIpRotKeyLow32ToField(selectedKeys[k], config.mPrime);
                auto value = modAddPsiIp(correction, mask, config.mPrime);

                writePsiIpPrimeElement(
                    &arithmeticShare(i, j),
                    elemByteLength,
                    value);
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
