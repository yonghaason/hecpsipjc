#include "RsPsiInnerproduct_Perf.h"

#include "Common.h"
#include "volePSI/PSI_Innerproduct.h"
#include "coproto/Socket/AsioSocket.h"

#include <chrono>
#include <future>
#include <iomanip>

using coproto::LocalAsyncSocket;
using namespace oc;
using namespace volePSI;

namespace
{
    struct Measurement
    {
        u64 mReceiverSent = 0;
        u64 mSenderSent = 0;
        double mSeconds = 0;
    };

    u64 readElement(const u8* src, u64 byteLength)
    {
        auto value = u64{};
        std::memcpy(&value, src, byteLength);
        return value;
    }

    u64 addMod(u64 lhs, u64 rhs, u64 prime)
    {
        auto remainder = prime - lhs;
        return rhs >= remainder ? rhs - remainder : lhs + rhs;
    }

    u64 mulMod(u64 lhs, u64 rhs, u64 prime)
    {
        return static_cast<u64>((static_cast<unsigned __int128>(lhs) * rhs) % prime);
    }

    template<typename Fn>
    Measurement measure(Socket& receiverSocket, Socket& senderSocket, Fn&& fn)
    {
        auto receiverBefore = receiverSocket.bytesSent();
        auto senderBefore = senderSocket.bytesSent();
        auto begin = std::chrono::steady_clock::now();
        fn();
        auto end = std::chrono::steady_clock::now();
        return {
            receiverSocket.bytesSent() - receiverBefore,
            senderSocket.bytesSent() - senderBefore,
            std::chrono::duration<double>(end - begin).count()
        };
    }

    void printMeasurement(const char* name, const Measurement& value)
    {
        auto totalBytes = value.mReceiverSent + value.mSenderSent;
        std::cout
            << name << ","
            << value.mReceiverSent << ","
            << value.mSenderSent << ","
            << totalBytes << ","
            << static_cast<double>(totalBytes) / (1024.0 * 1024.0) << ","
            << value.mSeconds << std::endl;
    }

    Measurement addMeasurements(const Measurement& a, const Measurement& b)
    {
        return { a.mReceiverSent + b.mReceiverSent, a.mSenderSent + b.mSenderSent,
            a.mSeconds + b.mSeconds };
    }

    std::array<Socket, 2> makeSockets(bool tcp, u64 port)
    {
        if (!tcp)
        {
            auto local = LocalAsyncSocket::makePair();
            return { std::move(local[0]), std::move(local[1]) };
        }

        auto address = std::string("127.0.0.1:") + std::to_string(port);
        auto server = std::async(std::launch::async, [&] {
            return coproto::asioConnect(address, true);
        });
        auto client = coproto::asioConnect(address, false);
        return { server.get(), std::move(client) };
    }
}

void RsPsiInnerproduct_perf_test(const CLP& cmd)
{
    auto n = cmd.getOr("n", u64(1) << 20);
    auto prime = cmd.getOr("p", RsCpsiDefaultPrime);
    auto numThreads = cmd.getOr("nt", u64(1));
    auto intersectionSize = cmd.getOr("intersection", n / 2);
    auto tcp = cmd.isSet("tcp");
    auto port = cmd.getOr("port", u64(18181));
    // -rns: long-item setting, 32-bit payloads over P = p0*p1 (84 bits)
    auto rns = cmd.isSet("rns");
    gPsiIpRnsDebug = cmd.isSet("rnsdebug");
    if (n == 0 || intersectionSize > n || numThreads == 0)
        throw RTE_LOC;
    auto primes = rns ? std::vector<u64>{ RsCpsiRnsPrime0, RsCpsiRnsPrime1 }
                      : std::vector<u64>{ prime };
    if (rns) prime = primes[0];
    auto dataBits = rns ? u64(32) : RsCpsiDataBitLength(prime);

    auto receiverSet = std::vector<block>(n);
    auto senderSet = std::vector<block>(n);
    auto associatedData = std::vector<u64>(n);
    auto receiverData = std::vector<u64>(n);
    auto expected = std::vector<u64>(n, 0);
    auto inputPrng = PRNG(block(0x12345678, 0x9abcdef0));
    inputPrng.get(receiverSet.data(), receiverSet.size());
    inputPrng.get(senderSet.data(), senderSet.size());

    auto maxData = (u64(1) << dataBits) - 1;
    for (u64 i = 0; i < n; ++i)
    {
        // multiplicative hashes spread the payloads over the full width; the
        // original affine forms stayed far below 2^32 for every n used here
        associatedData[i] = (i * 2654435761ull + 0x9e3779b9ull) & maxData;
        receiverData[i] = (i * 40503ull + 0x7f4a7c15ull) & maxData;
    }

    u64 expectedInnerproduct = 0;
    unsigned __int128 expectedInteger = 0;

    for (u64 senderIdx = 0; senderIdx < intersectionSize; ++senderIdx)
    {
        auto receiverIdx = n - 1 - senderIdx;
        senderSet[senderIdx] = receiverSet[receiverIdx];
        expected[receiverIdx] = associatedData[senderIdx];
        expectedInnerproduct = addMod(expectedInnerproduct,
            mulMod(associatedData[senderIdx], receiverData[receiverIdx], prime), prime);
        expectedInteger += (unsigned __int128)associatedData[senderIdx] * receiverData[receiverIdx];
    }

    auto sockets = makeSockets(tcp, port);
    auto config = PsiInnerproductConfig{};
    config.mPrime = prime;
    config.mNumThreads = numThreads;
    if (rns)
    {
        config.mPrimes = primes;
        config.mDataBitLength = dataBits;
        config.mSealCoeffModulusBits = { 60, 45, 20 };
        config.mSealEnforceSecurity = false;
    }
    auto sender = PsiInnerproductSender{};
    auto receiver = PsiInnerproductReceiver{};
    sender.init(n, n, config, block(1, 2));
    receiver.init(n, n, config, block(3, 4));

    auto senderCpsi = PsiInnerproductSender::CpsiSharing{};
    auto receiverCpsi = PsiInnerproductReceiver::CpsiSharing{};
    auto senderOwned = oc::Matrix<u8>{};
    auto senderReceived = oc::Matrix<u8>{};
    auto receiverOwned = oc::Matrix<u8>{};
    auto receiverReceived = oc::Matrix<u8>{};
    auto senderOutput = oc::Matrix<u8>{};
    auto receiverOutput = oc::Matrix<u8>{};
    auto senderPrng0 = PRNG(block(11, 12));
    auto senderPrng1 = PRNG(block(13, 14));
    auto receiverPrng0 = PRNG(block(15, 16));
    auto receiverPrng1 = PRNG(block(17, 18));

    auto totalBegin = std::chrono::steady_clock::now();

    auto commBreakdown = RsCpsiCommBreakdown{};
    auto timeBreakdown = RsCpsiTimeBreakdown{};
    gRsCpsiCommBreakdown = &commBreakdown;
    gRsCpsiTimeBreakdown = &timeBreakdown;

    auto cpsi = measure(sockets[0], sockets[1], [&] {
        auto p0 = receiver.receive(receiverSet, receiverCpsi, sockets[0]);
        auto p1 = sender.send(senderSet, associatedData, senderCpsi, sockets[1]);
        eval(p0, p1);
    });
    gRsCpsiCommBreakdown = nullptr;
    gRsCpsiTimeBreakdown = nullptr;

    auto vole = [&] {
        auto voleSockets = LocalAsyncSocket::makePair();
        auto voleSender = oc::SilentVoleSender<block, block, oc::CoeffCtxGF128>{};
        auto voleReceiver = oc::SilentVoleReceiver<block, block, oc::CoeffCtxGF128>{};
        auto prng0 = PRNG(block(21, 22));
        auto prng1 = PRNG(block(23, 24));
        voleReceiver.mNumThreads = numThreads;
        return measure(voleSockets[0], voleSockets[1], [&] {
            auto p0 = voleSender.silentSendInplace(prng0.get<block>(), receiverCpsi.mValues.rows(), prng0, voleSockets[0]);
            auto p1 = voleReceiver.silentReceiveInplace(receiverCpsi.mValues.rows(), prng1, voleSockets[1]);
            eval(p0, p1);
        });
    }();

    auto b2aSenderValue = measure(sockets[0], sockets[1], [&] {
        auto p0 = psiIpB2aChoiceOwner(
            receiverCpsi.mFlagBits,
            receiverCpsi.mValues.rows(),
            receiverCpsi.mValues.cols(),
            receiverReceived,
            config,
            receiverPrng0,
            sockets[0]);
        auto p1 = psiIpB2aValueOwner(
            senderCpsi.mFlagBits,
            senderCpsi.mValues,
            senderOwned,
            config,
            senderPrng0,
            sockets[1]);
        eval(p0, p1);
    });

    auto b2aReceiverValue = measure(sockets[0], sockets[1], [&] {
        auto p0 = psiIpB2aValueOwner(
            receiverCpsi.mFlagBits,
            receiverCpsi.mValues,
            receiverOwned,
            config,
            receiverPrng1,
            sockets[0]);
        auto p1 = psiIpB2aChoiceOwner(
            senderCpsi.mFlagBits,
            senderCpsi.mValues.rows(),
            senderCpsi.mValues.cols(),
            senderReceived,
            config,
            senderPrng1,
            sockets[1]);
        eval(p0, p1);
    });

    auto addShares = measure(sockets[0], sockets[1], [&] {
        psiIpAddPrimeShares(senderOwned, senderReceived, senderOutput, config);
        psiIpAddPrimeShares(
            receiverReceived, receiverOwned, receiverOutput, config);
    });

#ifdef VOLE_PSI_ENABLE_SEAL
    auto he = Measurement{};
    u64 senderResult = 0;
    unsigned __int128 senderResultInteger = 0;
    he = measure(sockets[0], sockets[1], [&] {
        if (rns)
        {
            auto p0 = psiIpHeReceiverRns(receiverData, receiverCpsi, receiverOutput, config, sockets[0]);
            auto p1 = psiIpHeSenderRns(senderOutput, senderResultInteger, config, senderPrng0, sockets[1]);
            eval(p0, p1);
        }
        else
        {
            auto p0 = psiIpHeReceiver(receiverData, receiverCpsi, receiverOutput, config, sockets[0]);
            auto p1 = psiIpHeSender(senderOutput, senderResult, config, senderPrng0, sockets[1]);
            eval(p0, p1);
        }
    });
    if (rns && gPsiIpRnsDebug)
        for (u64 j = 0; j < config.residueCount(); ++j)
        {
            auto pj = config.residuePrime(j);
            std::cerr << "[perf] residue " << j << " p=" << pj
                      << " want=" << (u64)(expectedInteger % pj)
                      << " got=" << (u64)(senderResultInteger % pj) << std::endl;
        }
    if (rns && gPsiIpRnsDebug)
        std::cerr << "[perf] integer want hi=" << (u64)(expectedInteger >> 64) << " lo=" << (u64)expectedInteger
                  << "  got hi=" << (u64)(senderResultInteger >> 64) << " lo=" << (u64)senderResultInteger << std::endl;
    if (rns ? (senderResultInteger != expectedInteger) : (senderResult != expectedInnerproduct))
    {
        std::cerr << "[perf] rns=" << rns
                  << " got hi=" << (u64)(senderResultInteger >> 64) << " lo=" << (u64)senderResultInteger
                  << " want hi=" << (u64)(expectedInteger >> 64) << " lo=" << (u64)expectedInteger
                  << " | mod want=" << expectedInnerproduct << " got=" << senderResult << std::endl;
        throw RTE_LOC;
    }
#endif

    auto totalEnd = std::chrono::steady_clock::now();
    auto total = Measurement{
        sockets[0].bytesSent(),
        sockets[1].bytesSent(),
        std::chrono::duration<double>(totalEnd - totalBegin).count()
    };
    // The standalone VOLE run is calibration used to split OPRF. It is not
    // part of the end-to-end protocol represented by the primary sockets.
    total.mSeconds -= vole.mSeconds;

    auto elementBytes = config.shareByteLength();
    for (u64 receiverIdx = 0; receiverIdx < n; ++receiverIdx)
    {
        auto shareIdx = receiverCpsi.mMapping[receiverIdx];
        for (u64 j = 0; j < config.residueCount(); ++j)
        {
            auto pj = config.residuePrime(j);
            auto receiverValue =
                readElement(&receiverOutput(shareIdx, j * elementBytes), elementBytes);
            auto senderValue =
                readElement(&senderOutput(shareIdx, j * elementBytes), elementBytes);
            if (addMod(receiverValue, senderValue, pj) != expected[receiverIdx] % pj)
                throw RTE_LOC;
        }
    }

    std::cout << std::fixed << std::setprecision(6);
    std::cout
        << "RS_PSI_INNERPRODUCT_PERF"
        << " n=" << n
        << " intersection=" << intersectionSize
        << " rows=" << receiverOutput.rows()
#ifdef VOLE_PSI_ENABLE_SEAL
        << " heChunks=" << oc::divCeil(receiverOutput.rows(), config.mSealPolyModulusDegree)
#endif
        << " prime=" << prime
        << " residues=" << config.residueCount()
        << " dataBits=" << dataBits
        << " nt=" << numThreads
        << " transport=" << (tcp ? "tcp" : "local") << std::endl;
    std::cout
        << "phase,receiverSentBytes,senderSentBytes,totalBytes,totalMiB,seconds"
        << std::endl;
    printMeasurement("cpsi", cpsi);
    printMeasurement("vole", vole);
    auto maxOprf = std::max(timeBreakdown.mSenderOprf, timeBreakdown.mReceiverOprf);
    auto maxOpprf = std::max(timeBreakdown.mSenderOpprf, timeBreakdown.mReceiverOpprf);
    auto maxPeqt = std::max(timeBreakdown.mSenderPeqt, timeBreakdown.mReceiverPeqt);
    auto voleBytes = vole.mReceiverSent + vole.mSenderSent;
    auto oprfBytes = commBreakdown.mOprf > voleBytes ? commBreakdown.mOprf - voleBytes : 0;
    printMeasurement("oprf_without_vole", { 0, oprfBytes,
        maxOprf > vole.mSeconds ? maxOprf - vole.mSeconds : 0 });
    printMeasurement("opprf", { 0, commBreakdown.mOpprf,
        maxOpprf > maxOprf ? maxOpprf - maxOprf : 0 });
    printMeasurement("peqt", { 0, commBreakdown.mPeqt, maxPeqt });
    printMeasurement("b2a_ot", addMeasurements(b2aSenderValue, b2aReceiverValue));
    printMeasurement("add_shares", addShares);
#ifdef VOLE_PSI_ENABLE_SEAL
    printMeasurement("he", he);
#endif
    printMeasurement("total", total);
}
