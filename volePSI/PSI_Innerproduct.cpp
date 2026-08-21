#include "volePSI/config.h"
#ifdef VOLE_PSI_ENABLE_SEAL
#include "seal/seal.h"
#endif
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

        u64 psiIpPrimeBitLength(u64 prime)
        {
            auto maxFieldElement = prime - 1;
            auto bitLength = u64{ 0 };
            while (maxFieldElement)
            {
                ++bitLength;
                maxFieldElement >>= 1;
            }
            return bitLength;
        }

        u64 psiIpRotKeyPrimeBitsToField(block key, u64 prime, u64 primeBitLength)
        {
            auto lowBits = key.get<u64>(0);
            if (primeBitLength < 64)
                lowBits &= (u64(1) << primeBitLength) - 1;

            return lowBits % prime;
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
        auto primeBitLength = psiIpPrimeBitLength(config.mPrime);
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
                auto r = samplePsiIpPrimeElement(prng, config.residuePrime(j / elemByteLength));
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
                auto prime = config.residuePrime(j / elemByteLength);
                auto x = readPsiIpPrimeElement(&values(i, j), elemByteLength) % prime;
                auto r = readPsiIpPrimeElement(&arithmeticShare(i, j), elemByteLength);
                auto zeroShare = modNegPsiIp(r, prime);
                auto oneShare = modSubPsiIp(x, r, prime);
                auto m0 = b ? oneShare : zeroShare;
                auto m1 = b ? zeroShare : oneShare;
                auto mask0 = psiIpRotKeyPrimeBitsToField(rotKeys[k][0], prime, primeBitLength);
                auto mask1 = psiIpRotKeyPrimeBitsToField(rotKeys[k][1], prime, primeBitLength);

                writePsiIpPrimeElement(
                    corrections.data() + (2 * k) * elemByteLength,
                    elemByteLength,
                    modSubPsiIp(m0, mask0, prime));
                writePsiIpPrimeElement(
                    corrections.data() + (2 * k + 1) * elemByteLength,
                    elemByteLength,
                    modSubPsiIp(m1, mask1, prime));
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
        auto primeBitLength = psiIpPrimeBitLength(config.mPrime);
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
                auto prime = config.residuePrime(j / elemByteLength);
                auto mask = psiIpRotKeyPrimeBitsToField(selectedKeys[k], prime, primeBitLength);
                auto value = modAddPsiIp(correction, mask, prime);

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
                writePsiIpPrimeElement(&out(i, j), elemByteLength,
                    modAddPsiIp(a, b, config.residuePrime(j / elemByteLength)));
            }
        }
    }
}

#endif

#if defined(VOLE_PSI_ENABLE_CPSI) && defined(VOLE_PSI_ENABLE_SEAL)

#include <sstream>

namespace volePSI
{
    namespace
    {
        u64 readElement(const u8* src, u64 bytes)
        {
            u64 value = 0;
            std::memcpy(&value, src, bytes);
            return value;
        }

        u64 addMod(u64 a, u64 b, u64 p)
        {
            auto remainder = p - a;
            return b >= remainder ? b - remainder : a + b;
        }

        u64 mulMod(u64 a, u64 b, u64 p)
        {
            return static_cast<u64>((static_cast<unsigned __int128>(a) * b) % p);
        }

        u64 sampleField(PRNG& prng, u64 p)
        {
            auto threshold = (u64(0) - p) % p;
            for (;;)
            {
                auto value = prng.get<u64>();
                if (value >= threshold)
                    return value % p;
            }
        }

        template<typename T>
        std::vector<u8> saveSeal(const T& object)
        {
            std::ostringstream stream(std::ios::binary);
            object.save(stream, seal::compr_mode_type::none);
            auto bytes = stream.str();
            return std::vector<u8>(bytes.begin(), bytes.end());
        }

        std::istringstream loadStream(const std::vector<u8>& bytes)
        {
            return std::istringstream(
                std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size()),
                std::ios::binary);
        }

        seal::EncryptionParameters makeParameters(const PsiInnerproductConfig& config)
        {
            if (config.mPrime < 2 || config.mSealPolyModulusDegree < 1024)
                throw std::invalid_argument("invalid BGV parameters");
            seal::EncryptionParameters parms(seal::scheme_type::bgv);
            parms.set_poly_modulus_degree(config.mSealPolyModulusDegree);
            parms.set_coeff_modulus(seal::CoeffModulus::Create(config.mSealPolyModulusDegree, config.mSealCoeffModulusBits));
            parms.set_plain_modulus(config.mPrime);
            return parms;
        }

        seal::Plaintext encodeScalar(u64 value)
        {
            return seal::Plaintext(value ? seal::util::uint_to_hex_string(&value, 1) : "0");
        }

        struct Encoding
        {
            bool batching = false;
            u64 slots = 1;
        };

        Encoding encodingFor(const seal::SEALContext& context)
        {
            auto batching = context.first_context_data()->qualifiers().using_batching;
            return { batching, batching ? context.first_context_data()->parms().poly_modulus_degree() : 1 };
        }

        seal::Plaintext encodeChunk(const std::vector<u64>& values, u64 offset, u64 used,
            const Encoding& encoding, seal::BatchEncoder* encoder)
        {
            if (!encoding.batching)
                return encodeScalar(values[offset]);
            std::vector<u64> slots(encoding.slots, 0);
            std::copy_n(values.begin() + offset, used, slots.begin());
            seal::Plaintext plain;
            encoder->encode(slots, plain);
            return plain;
        }
    }

    namespace
    {
        using u128 = unsigned __int128;

        u64 modInvPsiIp(u64 a, u64 m)
        {
            auto r = u64{1}, b = a % m, e = m - 2;
            while (e)
            {
                if (e & 1) r = u64((u128(r) * b) % m);
                b = u64((u128(b) * b) % m);
                e >>= 1;
            }
            return r;
        }

        // Garner reconstruction of x < prod(primes) from x mod primes[j].
        u128 crtCombine(span<const u64> residues, span<const u64> primes)
        {
            auto x = u128(residues[0]);
            auto modulus = u128(primes[0]);
            for (u64 j = 1; j < primes.size(); ++j)
            {
                auto pj = primes[j];
                auto cur = u64(x % pj);
                auto diff = residues[j] >= cur ? residues[j] - cur : pj - (cur - residues[j]);
                auto t = u64((u128(diff) * modInvPsiIp(u64(modulus % pj), pj)) % pj);
                x += modulus * t;
                modulus *= pj;
            }
            return x;
        }

        // Copy the residue-j column block out of an RNS share matrix.
        oc::Matrix<u8> residueSlice(oc::MatrixView<u8> share, u64 slot, u64 width)
        {
            oc::Matrix<u8> out(share.rows(), width);
            for (u64 i = 0; i < share.rows(); ++i)
                std::memcpy(&out(i, 0), &share(i, slot * width), width);
            return out;
        }
    }

    Proto psiIpHeReceiver(span<const u64> receiverPayload,
        const RsCpsiReceiver::Sharing& sharing, oc::MatrixView<u8> arithmeticShare,
        const PsiInnerproductConfig& config, Socket& chl)
    {
        if (receiverPayload.size() != sharing.mMapping.size() ||
            arithmeticShare.cols() != config.shareByteLength())
        {
            co_await chl.close();
            throw RTE_LOC;
        }
        std::vector<u64> aligned(arithmeticShare.rows(), 0);
        for (u64 inputIdx = 0; inputIdx < receiverPayload.size(); ++inputIdx)
        {
            auto outputRowIdx = sharing.mMapping[inputIdx];
            if (outputRowIdx >= aligned.size())
            {
                co_await chl.close();
                throw RTE_LOC;
            }
            aligned[outputRowIdx] = receiverPayload[inputIdx] % config.mPrime;
        }

        auto parms = makeParameters(config);
        auto context = seal::SEALContext(parms);
        if (!context.parameters_set())
            throw std::invalid_argument(context.parameter_error_message());
        auto encoding = encodingFor(context);
        auto encoder = encoding.batching ? std::make_unique<seal::BatchEncoder>(context) : nullptr;
        seal::KeyGenerator keygen(context);
        auto secretKey = keygen.secret_key();
        seal::Encryptor encryptor(context, secretKey);

        auto parameterBytes = saveSeal(parms);
        co_await chl.send(std::move(parameterBytes));
        u64 chunkCount = (aligned.size() + encoding.slots - 1) / encoding.slots;
        co_await chl.send(chunkCount);
        for (u64 chunk = 0; chunk < chunkCount; ++chunk)
        {
            auto offset = chunk * encoding.slots;
            auto used = std::min<u64>(encoding.slots, aligned.size() - offset);
            auto plain = encodeChunk(aligned, offset, used, encoding, encoder.get());
            seal::Serializable<seal::Ciphertext> encrypted = encryptor.encrypt_symmetric(plain);
            auto ciphertextBytes = saveSeal(encrypted);
            co_await chl.send(std::move(ciphertextBytes));
        }

        seal::Decryptor decryptor(context, secretKey);
        u64 maskedInnerProduct = 0;
        if (chunkCount)
        {
            std::vector<u8> bytes;
            co_await chl.recvResize(bytes);
            auto stream = loadStream(bytes);
            seal::Ciphertext encrypted;
            encrypted.load(context, stream);
            seal::Plaintext plain;
            decryptor.decrypt(encrypted, plain);
            std::vector<u64> decoded;
            if (encoding.batching)
                encoder->decode(plain, decoded);
            else
                decoded.push_back(plain[0] % config.mPrime);
            for (u64 value : decoded)
                maskedInnerProduct = addMod(maskedInnerProduct, value % config.mPrime, config.mPrime);
        }
        for (u64 row = 0; row < aligned.size(); ++row)
        {
            auto receiverShare = readElement(&arithmeticShare(row, 0), config.shareByteLength()) % config.mPrime;
            maskedInnerProduct = addMod(maskedInnerProduct,
                mulMod(aligned[row], receiverShare, config.mPrime), config.mPrime);
        }
        co_await chl.send(maskedInnerProduct);
    }

    Proto psiIpHeSender(oc::MatrixView<u8> arithmeticShare, u64& result,
        const PsiInnerproductConfig& config, PRNG& prng, Socket& chl)
    {
        if (arithmeticShare.cols() != config.shareByteLength())
        {
            co_await chl.close();
            throw RTE_LOC;
        }
        std::vector<u8> parameterBytes;
        co_await chl.recvResize(parameterBytes);
        auto parameterStream = loadStream(parameterBytes);
        seal::EncryptionParameters parms;
        parms.load(parameterStream);
        if (parms.scheme() != seal::scheme_type::bgv || parms.plain_modulus().value() != config.mPrime ||
            parms.poly_modulus_degree() != config.mSealPolyModulusDegree)
            throw std::invalid_argument("receiver supplied unexpected BGV parameters");
        auto context = seal::SEALContext(parms);
        seal::Evaluator evaluator(context);
        auto encoding = encodingFor(context);
        auto encoder = encoding.batching ? std::make_unique<seal::BatchEncoder>(context) : nullptr;
        u64 chunkCount = 0;
        co_await chl.recv(chunkCount);
        auto expectedChunks = (arithmeticShare.rows() + encoding.slots - 1) / encoding.slots;
        if (chunkCount != expectedChunks)
            throw std::invalid_argument("unexpected ciphertext count");

        std::vector<u64> senderShares(arithmeticShare.rows()), masks(arithmeticShare.rows());
        u64 maskSum = 0;
        for (u64 i = 0; i < arithmeticShare.rows(); ++i)
        {
            senderShares[i] = readElement(&arithmeticShare(i, 0), config.shareByteLength()) % config.mPrime;
            masks[i] = sampleField(prng, config.mPrime);
            maskSum = addMod(maskSum, masks[i], config.mPrime);
        }
        seal::Ciphertext accumulated;
        for (u64 chunk = 0; chunk < chunkCount; ++chunk)
        {
            std::vector<u8> bytes;
            co_await chl.recvResize(bytes);
            auto stream = loadStream(bytes);
            seal::Ciphertext encryptedData;
            encryptedData.load(context, stream);
            auto offset = chunk * encoding.slots;
            auto used = std::min<u64>(encoding.slots, arithmeticShare.rows() - offset);
            auto sharePlain = encodeChunk(senderShares, offset, used, encoding, encoder.get());
            auto maskPlain = encodeChunk(masks, offset, used, encoding, encoder.get());
            evaluator.multiply_plain_inplace(encryptedData, sharePlain);
            evaluator.sub_plain_inplace(encryptedData, maskPlain);
            if (chunk)
                evaluator.add_inplace(accumulated, encryptedData);
            else
                accumulated = std::move(encryptedData);
        }
        if (chunkCount)
        {
            evaluator.mod_switch_to_next_inplace(accumulated);
            co_await chl.send(saveSeal(accumulated));
        }
        u64 maskedInnerProduct = 0;

        co_await chl.recv(maskedInnerProduct);
        result = addMod(maskedInnerProduct % config.mPrime, maskSum, config.mPrime);
    }

    Proto psiIpHeSenderRns(oc::MatrixView<u8> arithmeticShare, unsigned __int128& result,
        const PsiInnerproductConfig& config, PRNG& prng, Socket& chl)
    {
        auto k = config.residueCount();
        auto width = config.shareByteLength();
        auto residues = std::vector<u64>(k, 0);
        auto primes = std::vector<u64>{};
        for (u64 j = 0; j < k; ++j)
            primes.push_back(config.residuePrime(j));

        for (u64 j = 0; j < k; ++j)
        {
            auto cfg = config;
            cfg.mPrime = primes[j];
            cfg.mPrimes.clear();
            auto slice = residueSlice(arithmeticShare, j, width);
            co_await psiIpHeSender(slice, residues[j], cfg, prng, chl);
        }
        result = crtCombine(residues, primes);
    }

    Proto psiIpHeReceiverRns(span<const u64> receiverPayload,
        const RsCpsiReceiver::Sharing& sharing, oc::MatrixView<u8> arithmeticShare,
        const PsiInnerproductConfig& config, Socket& chl)
    {
        auto k = config.residueCount();
        auto width = config.shareByteLength();
        for (u64 j = 0; j < k; ++j)
        {
            auto cfg = config;
            cfg.mPrime = config.residuePrime(j);
            cfg.mPrimes.clear();
            auto slice = residueSlice(arithmeticShare, j, width);
            co_await psiIpHeReceiver(receiverPayload, sharing, slice, cfg, chl);
        }
    }

    bool psiIpSealParamsValid(const PsiInnerproductConfig& config)
    {
        try
        {
            seal::EncryptionParameters parms(seal::scheme_type::bgv);
            parms.set_poly_modulus_degree(config.mSealPolyModulusDegree);
            parms.set_coeff_modulus(seal::CoeffModulus::Create(
                config.mSealPolyModulusDegree, config.mSealCoeffModulusBits));
            parms.set_plain_modulus(config.mPrime);
            seal::SEALContext ctx(parms, true, seal::sec_level_type::tc128);
            return ctx.parameters_set();
        }
        catch (...) { return false; }
    }

}

#endif
