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

    // Long-item setting: 32-bit payloads need an arithmetic space of
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
void RsPsiInnerproduct_seal_rns_sweep_test(const CLP& cmd)
{
    std::vector<u64> p32 = { 4294475777ULL, 4294483969ULL, 4294729729ULL };
    std::vector<u64> p42 = { 4398046486529ULL, 4398046240769ULL };
    std::vector<u64> p48 = { 281474976694273ULL, 281474976636929ULL };
    struct Cfg { std::vector<u64> pr; u64 N; std::vector<int> cm; const char* note; };
    std::vector<Cfg> cfgs = {
        {p32,              4096,{48,36,18},    "k=3 x 32  special 18 (current)"},
        {p42,              4096,{48,36,18},    "k=2 x 42  special 18"},
        {p42,              4096,{60,40,9},     "k=2 x 42  special 9"},
        {p42,              4096,{54,46,9},     "k=2 x 42  special 9"},
        {p42,              4096,{50,50,9},     "k=2 x 42  special 9"},
        {p48,              4096,{60,40,9},     "k=2 x 48  special 9"},
        {{p32[0],p32[1]},  4096,{60,40,9},     "k=2 x 32  special 9"},
        {p42,              8192,{60,60,60,38}, "k=2 x 42  N=8192"},
        {p42,              4096,{60,32,17},    "k=2 x 42  N=4096 max ctxt 92"},
        {p42,              4096,{55,37,17},    "k=2 x 42  N=4096 max ctxt 92"},
        {p42,              8192,{60,42,17},    "k=2 x 42  N=8192 ctxt 102"},
        {p42,              8192,{52,50,17},    "k=2 x 42  N=8192 ctxt 102"},
        {p42,              8192,{48,36,18},    "k=2 x 42  N=8192 ctxt 84"},
    };
    auto only = cmd.getOr("cfg", u64(~u64(0)));
    for (u64 idx = 0; idx < cfgs.size(); ++idx)
    {
        if (only != ~u64(0) && idx != only) continue;
        auto& c = cfgs[idx];
        int tot = 0; for (int b : c.cm) tot += b;
        auto L = u64{0};
        for (auto q : c.pr) L += oc::log2ceil(q);
        auto ok = psiIpRnsProbe(c.pr, c.N, c.cm, 4099);
        std::cout << "  " << c.note
                  << "  N=" << c.N << "  cm=" << tot << " (ctxt " << tot - c.cm.back() << ")"
                  << "  L=" << L
                  << "  -> " << (ok ? "PASS" : "fail") << std::endl;
    }
}


// Repeat a single-residue HE round trip twice in one process, to see whether
// a second SEAL context with the same parameters misbehaves.
void RsPsiInnerproduct_seal_repeat_test(const CLP& cmd)
{
    auto prime = cmd.getOr("prime", RsCpsiRnsPrime0);
    auto N = cmd.getOr("N", u64(4096));
    auto cm = cmd.isSet("cm6032") ? std::vector<int>{60,32,17} : std::vector<int>{48,36,18};
    auto reps = cmd.getOr("reps", u64(3));
    for (u64 r = 0; r < reps; ++r)
    {
        auto ok = psiIpRnsProbe({ prime }, N, cm, 4099);
        std::cout << "  rep " << r << " prime=" << prime << " N=" << N
                  << " cm=" << cm[0] << "," << cm[1] << "," << cm[2]
                  << " -> " << (ok ? "PASS" : "fail") << std::endl;
    }
}
