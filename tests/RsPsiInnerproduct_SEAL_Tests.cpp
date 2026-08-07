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
        config.mSealPolyModulusDegree = 8192;
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
}

void RsPsiInnerproduct_seal_test(const CLP& cmd)
{
    // Covers all/partial/no-match rows through nonzero/zero product shares,
    // zero and p-1 payloads, wrap-around, reverse mapping, two chunks and padding.
    runCase(cmd.getOr("rows", u64(8195)), true);
}

#endif
