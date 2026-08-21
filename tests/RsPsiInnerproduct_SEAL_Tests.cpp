#include "Common.h"
#include "volePSI/PSI_Innerproduct.h"

#ifdef VOLE_PSI_ENABLE_SEAL

using coproto::LocalAsyncSocket;
using namespace oc;
using namespace volePSI;

namespace
{
    u64 addMod(u64 a, u64 b, u64 p)
    {
        auto remainder = p - a;
        return b >= remainder ? b - remainder : a + b;
    }

    u64 mulMod(u64 a, u64 b, u64 p)
    {
        return static_cast<u64>((static_cast<unsigned __int128>(a) * b) % p);
    }

    void writeElement(oc::Matrix<u8>& matrix, u64 row, u64 bytes, u64 value)
    {
        std::memcpy(&matrix(row, 0), &value, bytes);
    }

    void runCase(u64 rows, bool reverseMapping)
    {
        PsiInnerproductConfig config;
        config.mPrime = RsCpsiDefaultPrime;
        config.mSealPolyModulusDegree = 4096;
        auto bytes = config.shareByteLength();
        oc::Matrix<u8> senderShare(rows, bytes), receiverShare(rows, bytes);
        RsCpsiReceiver::Sharing sharing;
        sharing.mMapping.resize(rows);
        std::vector<u64> receiverPayload(rows);
        u64 expected = 0;

        for (u64 input = 0; input < rows; ++input)
        {
            auto row = reverseMapping ? rows - 1 - input : input;
            sharing.mMapping[input] = row;
            auto dy = input % 11 == 0 ? 0 : input % 13 == 0 ? config.mPrime - 1 : (input * 29 + 7) % config.mPrime;
            auto productShare = input % 3 == 0 ? 0 : input % 17 == 0 ? config.mPrime - 1 : (input * 13 + 5) % config.mPrime;
            auto r = (input * 101 + 19) % config.mPrime;
            receiverPayload[input] = dy;
            writeElement(senderShare, row, bytes, r);
            writeElement(receiverShare, row, bytes, addMod(productShare, r ? config.mPrime - r : 0, config.mPrime));
            expected = addMod(expected, mulMod(dy, productShare, config.mPrime), config.mPrime);
        }

        auto sockets = LocalAsyncSocket::makePair();
        PRNG prng(block(91, 92));
        u64 result = ~u64(0);
        auto receiver = psiIpHeReceiver(receiverPayload, sharing, receiverShare, config, sockets[0]);
        auto sender = psiIpHeSender(senderShare, result, config, prng, sockets[1]);
        eval(receiver, sender);
        if (result != expected)
        {
            throw RTE_LOC;
        }
    }

    // Integer-inner-product setting: 32-bit payloads need an arithmetic space of
    // 2*32 + log2(rows) bits, which exceeds what one SEAL plaintext modulus
    // holds. Represent Z_P with two 42-bit residues and combine by CRT.
    void runRnsCase(u64 rows)
    {
        using u128 = unsigned __int128;
        PsiInnerproductConfig config;
        // sweepable via -p0/-p1/-N/-cm for the residue-width experiment
        config.mPrimes = { RsCpsiRnsPrime0, RsCpsiRnsPrime1 };
        config.mPrime = config.mPrimes[0];
        config.mDataBitLength = 32;
        config.mSealPolyModulusDegree = 4096;
        config.mSealCoeffModulusBits = { 60, 45, 20 };
        config.mSealEnforceSecurity = false;

        auto k = config.residueCount();
        auto width = config.shareByteLength();
        oc::Matrix<u8> senderShare(rows, width * k), receiverShare(rows, width * k);
        RsCpsiReceiver::Sharing sharing;
        sharing.mMapping.resize(rows);
        std::vector<u64> receiverPayload(rows);
        u128 expected = 0;

        for (u64 input = 0; input < rows; ++input)
        {
            auto row = rows - 1 - input;
            sharing.mMapping[input] = row;
            // full 32-bit payloads, including the extremes
            u64 dy = input % 11 == 0 ? 0
                : input % 13 == 0 ? 0xffffffffull
                : (input * 2654435761ull) & 0xffffffffull;
            u64 dx = input % 7 == 0 ? 0
                : input % 19 == 0 ? 0xffffffffull
                : (input * 40503ull + 12345) & 0xffffffffull;
            receiverPayload[input] = dy;
            expected += u128(dy) * dx;

            for (u64 j = 0; j < k; ++j)
            {
                auto pj = config.residuePrime(j);
                auto r = (input * 101 + 19 + j * 7919) % pj;
                auto share = addMod(dx % pj, r ? pj - r : 0, pj);
                std::memcpy(&senderShare(row, j * width), &r, width);
                std::memcpy(&receiverShare(row, j * width), &share, width);
            }
        }

        if (gPsiIpRnsDebug) std::cerr << "[exp] k=" << k << " width=" << width << " rows=" << rows << std::endl;
        for (u64 j = 0; j < k && gPsiIpRnsDebug; ++j)
            std::cerr << "[exp] residue " << j << " p=" << config.residuePrime(j)
                      << " r=" << (u64)(expected % config.residuePrime(j)) << std::endl;
        if (gPsiIpRnsDebug) std::cerr << "[exp] integer hi=" << (u64)(expected >> 64) << " lo=" << (u64)expected << std::endl;
        auto sockets = LocalAsyncSocket::makePair();
        PRNG prng(block(91, 92));
        u128 result = 0;
        auto receiver = psiIpHeReceiverRns(receiverPayload, sharing, receiverShare, config, sockets[0]);
        auto sender = psiIpHeSenderRns(senderShare, result, config, prng, sockets[1]);
        eval(receiver, sender);
        if (result != expected)
            throw RTE_LOC;
    }
}

void RsPsiInnerproduct_seal_test(const CLP& cmd)
{
    runCase(cmd.getOr("rows", u64(4099)), true);
}

void RsPsiInnerproduct_seal_rns_test(const CLP& cmd)
{
    runRnsCase(cmd.getOr("rows", u64(4099)));
}

// Probe whether a given (residue primes, N, coeff modulus) combination
// decrypts correctly. Used to pick the residue width.
bool psiIpRnsProbe(std::vector<u64> primes, u64 N, std::vector<int> cmBits, u64 rows)
{
    using u128 = unsigned __int128;
    PsiInnerproductConfig config;
    config.mPrimes = primes;
    config.mPrime = primes[0];
    config.mDataBitLength = 32;
    config.mSealPolyModulusDegree = N;
    config.mSealCoeffModulusBits = cmBits;

    auto k = config.residueCount();
    auto width = config.shareByteLength();
    oc::Matrix<u8> senderShare(rows, width * k), receiverShare(rows, width * k);
    RsCpsiReceiver::Sharing sharing;
    sharing.mMapping.resize(rows);
    std::vector<u64> receiverPayload(rows);
    u128 expected = 0;
    for (u64 input = 0; input < rows; ++input)
    {
        auto row = rows - 1 - input;
        sharing.mMapping[input] = row;
        u64 dy = (input * 2654435761ull) & 0xffffffffull;
        u64 dx = (input * 40503ull + 12345) & 0xffffffffull;
        receiverPayload[input] = dy;
        expected += u128(dy) * dx;
        for (u64 j = 0; j < k; ++j)
        {
            auto pj = config.residuePrime(j);
            auto r = (input * 101 + 19 + j * 7919) % pj;
            auto share = addMod(dx % pj, r ? pj - r : 0, pj);
            std::memcpy(&senderShare(row, j * width), &r, width);
            std::memcpy(&receiverShare(row, j * width), &share, width);
        }
    }
    if (!psiIpSealParamsValid(config))
    {
        std::cout << "    [invalid SEAL parameters] ";
        return false;
    }
    try
    {
        auto sockets = LocalAsyncSocket::makePair();
        PRNG prng(block(91, 92));
        u128 result = 0;
        auto rc = psiIpHeReceiverRns(receiverPayload, sharing, receiverShare, config, sockets[0]);
        auto sd = psiIpHeSenderRns(senderShare, result, config, prng, sockets[1]);
        eval(rc, sd);
        return result == expected;
    }
    catch (...) { return false; }
}

#endif


// Sweep residue width against the coefficient modulus split, to see whether
// reclaiming SEAL's unused special prime lets two residues suffice.
