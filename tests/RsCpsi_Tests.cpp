#include "RsCpsi_Tests.h"
#include "volePSI/RsPsi.h"
#include "volePSI/RsCpsi.h"
#include "volePSI/PSI_Innerproduct.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"
#include "Common.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include <chrono>
#include <iomanip>
#include <thread>

using coproto::LocalAsyncSocket;
using namespace oc;
using namespace volePSI;

namespace
{
    //0719
    struct CpsiRunOutput
    {
        std::vector<u64> mIntersection;
        u64 mRecvBytes = 0;
        u64 mSendBytes = 0;
        double mSeconds = 0;
    };

    //0719
    struct CpsiStats
    {
        u64 mTotalBytes = 0;
        u64 mRecvBytes = 0;
        u64 mSendBytes = 0;
        double mMeanSeconds = 0;
    };

    //0714
    //0719
    u64 valueWord(block v, u64 idx, u64 prime)
    {
        return v.get<u32>(idx) % (u64(1) << RsCpsiDataBitLength(prime));
    }

    //0719
    u64 readPrimeElement(const u8* src, u64 byteLength)
    {
        auto v = u64{};
        std::memcpy(&v, src, byteLength);
        return v;
    }

    //0719
    void writePrimeElement(u8* dst, u64 byteLength, u64 v)
    {
        std::memcpy(dst, &v, byteLength);
    }

    //0719
    u64 modAddPrime(u64 lhs, u64 rhs, u64 prime)
    {
        auto rem = prime - lhs;
        return rhs >= rem ? rhs - rem : lhs + rhs;
    }

    //0719
    void setPrimeValues(oc::Matrix<u8>& values, const std::vector<block>& set, u64 prime, u64 dataByteLength)
    {
        for (u64 i = 0; i < set.size(); ++i)
            writePrimeElement(&values(i, 0), dataByteLength, valueWord(set[i], 0, prime));
    }

    std::vector<u64> runCpsi(
        PRNG& prng,
        std::vector<block>& recvSet,
        std::vector<block>& sendSet,
        u64 nt = 1,
        ValueShareType type = ValueShareType::Xor,
        //0719
        u64 prime = RsCpsiDefaultPrime)
    {
        auto sockets = LocalAsyncSocket::makePair();


        RsCpsiReceiver recver;
        RsCpsiSender sender;

        //0714
        //0719
        auto dataElemByteLength = RsCpsiDataByteLength(prime);
        auto shareElemByteLength = RsCpsiPrimeByteLength(prime);
        auto byteLength = type == ValueShareType::prime ?
            dataElemByteLength :
            sizeof(block);
        oc::Matrix<u8> senderValues(sendSet.size(), byteLength);

        //0714
        //0719
        if (type == ValueShareType::prime)
            setPrimeValues(senderValues, sendSet, prime, dataElemByteLength);
        else
        {
            for (u64 i = 0; i < sendSet.size(); ++i)
                std::memcpy(&senderValues(i, 0), &sendSet[i], byteLength);
        }

        //0714
        //0719
        recver.init(sendSet.size(), recvSet.size(), byteLength, 40, prng.get(), nt, type, prime);
        sender.init(sendSet.size(), recvSet.size(), byteLength, 40, prng.get(), nt, type, prime);

        RsCpsiReceiver::Sharing rShare;
        RsCpsiSender::Sharing sShare;

        auto p0 = recver.receive(recvSet, rShare, sockets[0]);
        auto p1 = sender.send(sendSet, senderValues, sShare, sockets[1]);

        eval(p0, p1);
        
        bool failed = false;
        std::vector<u64> intersection;
        for (u64 i = 0; i < recvSet.size(); ++i)
        {
            auto k = rShare.mMapping[i];

            if (rShare.mFlagBits[k] ^ sShare.mFlagBits[k])
            {
                intersection.push_back(i);

                if (type == ValueShareType::Xor)
                {
                    std::vector<u8> act(byteLength);
                    for (u64 j = 0; j < byteLength; ++j)
                        act[j] = rShare.mValues(k, j) ^ sShare.mValues(k, j);

                    if (std::memcmp(act.data(), &recvSet[i], byteLength))
                    {
                        if(!failed)
                            std::cout << i << " xor value mismatch" << std::endl;
                        failed = true;
                        //throw RTE_LOC;
                    }
                }
                //0714
                else if (type == ValueShareType::add32)
                {

                    for (u64 j = 0; j < 4; ++j)
                    {
                        auto rv = (u32*)&rShare.mValues(k, 0);
                        auto sv = (u32*)&sShare.mValues(k, 0);

                        if (recvSet[i].get<u32>(j) != (sv[j] + rv[j]))
                        {
                            throw RTE_LOC;
                        }
                    }
                }
                //0714
                //0719
                else if (type == ValueShareType::prime)
                {
                    auto rv = readPrimeElement(&rShare.mValues(k, 0), shareElemByteLength);
                    auto sv = readPrimeElement(&sShare.mValues(k, 0), shareElemByteLength);
                    auto act = modAddPrime(rv, sv, prime);

                    if (act != valueWord(recvSet[i], 0, prime))
                        throw RTE_LOC;
                }
                else
                {
                    throw RTE_LOC;
                }
            }
        }

        return intersection;
    }

    //0719
    CpsiRunOutput runCpsiMeasured(
        PRNG& prng,
        std::vector<block>& recvSet,
        std::vector<block>& sendSet,
        u64 nt,
        ValueShareType type,
        u64 prime,
        u64 valueByteLengthOverride = 0)
    {
        auto sockets = LocalAsyncSocket::makePair();
        RsCpsiReceiver recver;
        RsCpsiSender sender;

        auto dataElemByteLength = RsCpsiDataByteLength(prime);
        auto shareElemByteLength = RsCpsiPrimeByteLength(prime);
        auto byteLength = type == ValueShareType::prime ?
            dataElemByteLength :
            sizeof(block);
        if (valueByteLengthOverride)
            byteLength = valueByteLengthOverride;

        oc::Matrix<u8> senderValues(sendSet.size(), byteLength);
        if (type == ValueShareType::prime)
            setPrimeValues(senderValues, sendSet, prime, dataElemByteLength);
        else
        {
            for (u64 i = 0; i < sendSet.size(); ++i)
                std::memcpy(&senderValues(i, 0), &sendSet[i], byteLength);
        }

        recver.init(sendSet.size(), recvSet.size(), byteLength, 40, prng.get(), nt, type, prime);
        sender.init(sendSet.size(), recvSet.size(), byteLength, 40, prng.get(), nt, type, prime);

        RsCpsiReceiver::Sharing rShare;
        RsCpsiSender::Sharing sShare;

        auto p0 = recver.receive(recvSet, rShare, sockets[0]);
        auto p1 = sender.send(sendSet, senderValues, sShare, sockets[1]);

        auto begin = std::chrono::steady_clock::now();
        eval(p0, p1);
        auto end = std::chrono::steady_clock::now();

        std::vector<u64> intersection;
        for (u64 i = 0; i < recvSet.size(); ++i)
        {
            auto k = rShare.mMapping[i];
            if (rShare.mFlagBits[k] ^ sShare.mFlagBits[k])
            {
                intersection.push_back(i);

                if (type == ValueShareType::Xor)
                {
                    std::vector<u8> act(byteLength);
                    for (u64 j = 0; j < byteLength; ++j)
                        act[j] = rShare.mValues(k, j) ^ sShare.mValues(k, j);

                    if (std::memcmp(act.data(), &recvSet[i], byteLength))
                        throw RTE_LOC;
                }
                else if (type == ValueShareType::prime)
                {
                    auto rv = readPrimeElement(&rShare.mValues(k, 0), shareElemByteLength);
                    auto sv = readPrimeElement(&sShare.mValues(k, 0), shareElemByteLength);
                    auto act = modAddPrime(rv, sv, prime);

                    if (act != valueWord(recvSet[i], 0, prime))
                        throw RTE_LOC;
                }
            }
        }

        CpsiRunOutput out;
        out.mIntersection = std::move(intersection);
        out.mRecvBytes = sockets[0].bytesSent();
        out.mSendBytes = sockets[1].bytesSent();
        out.mSeconds = std::chrono::duration<double>(end - begin).count();
        return out;
    }

    //0719
    CpsiStats summarizeRuns(const std::vector<CpsiRunOutput>& runs)
    {
        CpsiStats out;
        out.mRecvBytes = runs.front().mRecvBytes;
        out.mSendBytes = runs.front().mSendBytes;
        out.mTotalBytes = out.mRecvBytes + out.mSendBytes;

        auto sum = double{};
        for (auto& r : runs)
            sum += r.mSeconds;
        out.mMeanSeconds = sum / runs.size();

        return out;
    }

    //0719
    void printMissing(const char* mode, const std::vector<u64>& intersection, u64 n)
    {
        std::set<u64> act(intersection.begin(), intersection.end());
        std::cout << mode << " intersection=" << intersection.size()
            << " expected=" << n
            << " firstMissing=";
        for (u64 i = 0, c = 0; i < n && c < 10; ++i)
        {
            if (act.find(i) == act.end())
            {
                std::cout << i << " ";
                ++c;
            }
        }
        std::cout << std::endl;
    }

}


void Cpsi_Rs_empty_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 133);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());

    auto inter = runCpsi(prng, recvSet, sendSet);

    if (inter.size())
        throw RTE_LOC;
}


void Cpsi_Rs_partial_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 128);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());

    for (u64 i = 0; i < n; ++i)
    {
        sendSet[i].set<u64>(0, i);
        recvSet[i].set<u64>(0, i);
    }

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
    {
        if (prng.getBit())
        {
            recvSet[i] = sendSet[(i + 312) % n];
            exp.insert(i);
        }
    }

    auto inter = runCpsi(prng, recvSet, sendSet);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
    {
        auto rem = exp;
        for (auto a : act)
            rem.erase(a);

        std::cout << "missing " << *rem.begin() << " " << recvSet[*rem.begin()] << std::endl;
        throw RTE_LOC;
    }
}


void Cpsi_Rs_full_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    sendSet = recvSet;

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
        exp.insert(i);

    auto inter = runCpsi(prng, recvSet, sendSet);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
        throw RTE_LOC;
}

void Cpsi_Rs_full_asym_test(const CLP& cmd)
{
    u64 ns = cmd.getOr("ns", 2432);
    u64 nr = cmd.getOr("nr", 212);
    std::vector<block> recvSet(nr), sendSet(ns);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    prng.SetSeed(ZeroBlock);
    prng.get(sendSet.data(), sendSet.size());

    std::set<u64> exp;
    for (u64 i = 0; i < std::min<u64>(ns,nr); ++i)
        exp.insert(i);

    auto inter = runCpsi(prng, recvSet, sendSet);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
        throw RTE_LOC;
}




void Cpsi_Rs_full_add32_test(const CLP& cmd)
{
    //u64 n = cmd.getOr("n", 13243);
    //std::vector<block> recvSet(n), sendSet(n);
    //PRNG prng(ZeroBlock);
    //prng.get(recvSet.data(), recvSet.size());
    //sendSet = recvSet;

    //std::set<u64> exp;
    //for (u64 i = 0; i < n; ++i)
    //    exp.insert(i);

    //auto inter = runCpsi(prng, recvSet, sendSet, 1, ValueShareType::add32);
    //std::set<u64> act(inter.begin(), inter.end());
    //if (act != exp)
    //    throw RTE_LOC;
}

//0714
//0719
void Cpsi_Rs_full_prime_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 243);
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    sendSet = recvSet;

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
        exp.insert(i);

    auto inter = runCpsi(prng, recvSet, sendSet, 1, ValueShareType::prime);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
        throw RTE_LOC;
}

//0719
void Cpsi_Rs_full_prime_param_test(const CLP& cmd)
{
    u64 n = cmd.getOr("n", 243);
    auto prime = cmd.getOr("p", u64(16777259));
    std::vector<block> recvSet(n), sendSet(n);
    PRNG prng(ZeroBlock);
    prng.get(recvSet.data(), recvSet.size());
    sendSet = recvSet;

    std::set<u64> exp;
    for (u64 i = 0; i < n; ++i)
        exp.insert(i);

    auto inter = runCpsi(prng, recvSet, sendSet, 1, ValueShareType::prime, prime);
    std::set<u64> act(inter.begin(), inter.end());
    if (act != exp)
        throw RTE_LOC;
}

//0719
void Cpsi_Rs_comm_time_compare_test(const CLP& cmd)
{
    auto n = cmd.getOr("n", u64(243));
    auto prime = cmd.getOr("p", RsCpsiDefaultPrime);
    auto nt = cmd.getOr("nt", u64(1));
    auto rounds = cmd.getOr("rounds", u64(2));
    auto warmup = cmd.getOr("warmup", u64(1));
    auto dataByteLength = RsCpsiDataByteLength(prime);

    auto runOne = [&](ValueShareType type, u64 seedIdx) {
        std::vector<block> recvSet(n), sendSet(n);
        PRNG prng(block(seedIdx, seedIdx));
        prng.get(recvSet.data(), recvSet.size());
        sendSet = recvSet;

        auto valueBytes = type == ValueShareType::Xor ? dataByteLength : 0;
        return runCpsiMeasured(prng, recvSet, sendSet, nt, type, prime, valueBytes);
    };

    for (u64 i = 0; i < warmup; ++i)
    {
        auto xorWarm = CpsiRunOutput{};
        auto primeWarm = CpsiRunOutput{};
        if (i % 2)
        {
            primeWarm = runOne(ValueShareType::prime, i + 1);
            xorWarm = runOne(ValueShareType::Xor, i + 1);
        }
        else
        {
            xorWarm = runOne(ValueShareType::Xor, i + 1);
            primeWarm = runOne(ValueShareType::prime, i + 1);
        }

        if (xorWarm.mIntersection.size() != n || primeWarm.mIntersection.size() != n)
        {
            printMissing("xor-warmup", xorWarm.mIntersection, n);
            printMissing("prime-warmup", primeWarm.mIntersection, n);
            throw RTE_LOC;
        }
    }

    std::vector<CpsiRunOutput> xorRuns, primeRuns;
    xorRuns.reserve(rounds);
    primeRuns.reserve(rounds);

    for (u64 i = 0; i < rounds; ++i)
    {
        auto seedIdx = i + warmup + 1;
        auto xorOut = CpsiRunOutput{};
        auto primeOut = CpsiRunOutput{};

        if (i % 2)
        {
            primeOut = runOne(ValueShareType::prime, seedIdx);
            xorOut = runOne(ValueShareType::Xor, seedIdx);
        }
        else
        {
            xorOut = runOne(ValueShareType::Xor, seedIdx);
            primeOut = runOne(ValueShareType::prime, seedIdx);
        }

        if (xorOut.mIntersection.size() != n || primeOut.mIntersection.size() != n)
        {
            printMissing("xor", xorOut.mIntersection, n);
            printMissing("prime", primeOut.mIntersection, n);
            throw RTE_LOC;
        }

        xorRuns.push_back(std::move(xorOut));
        primeRuns.push_back(std::move(primeOut));
    }

    auto xorStats = summarizeRuns(xorRuns);
    auto primeStats = summarizeRuns(primeRuns);

    std::cout << std::fixed << std::setprecision(6);
    std::cout << "CPSI_COMPARE n=" << n
        << " prime=" << prime
        << " dataBytes=" << dataByteLength
        << " dataElements=1"
        << " nt=" << nt
        << " rounds=" << rounds
        << " warmup=" << warmup << std::endl;
    std::cout << "mode,totalBytes,totalBits,timeMeanSeconds" << std::endl;
    std::cout << "xor,"
        << xorStats.mTotalBytes << ","
        << (xorStats.mTotalBytes * 8) << ","
        << xorStats.mMeanSeconds << std::endl;
    std::cout << "prime,"
        << primeStats.mTotalBytes << ","
        << (primeStats.mTotalBytes * 8) << ","
        << primeStats.mMeanSeconds << std::endl;
}


//0719
void Cpsi_PsiInnerproduct_b2a_test(const CLP& cmd)
{
    auto n = cmd.getOr("n", u64(64));
    auto prime = cmd.getOr("p", RsCpsiDefaultPrime);
    auto nt = cmd.getOr("nt", u64(1));
    auto sockets = LocalAsyncSocket::makePair();
    auto config = PsiInnerproductConfig{};
    config.mPrime = prime;
    config.mNumThreads = nt;

    std::vector<block> recvSet(n), sendSet(n);
    std::vector<u64> associatedData(n);
    auto prng = PRNG(block(101, 102));
    prng.get(recvSet.data(), recvSet.size());
    prng.get(sendSet.data(), sendSet.size());

    for (u64 i = 0; i < n / 2; ++i)
        sendSet[i] = recvSet[i];

    for (u64 i = 0; i < n; ++i)
        associatedData[i] = (i + 17) % prime;

    auto sender = PsiInnerproductSender{};
    auto receiver = PsiInnerproductReceiver{};
    sender.init(sendSet.size(), recvSet.size(), config, block(111, 112));
    receiver.init(sendSet.size(), recvSet.size(), config, block(113, 114));

    PsiInnerproductSender::CpsiSharing sCpsiShare;
    PsiInnerproductReceiver::CpsiSharing rCpsiShare;
    oc::Matrix<u8> sArithmeticShare;
    oc::Matrix<u8> rArithmeticShare;

    auto p0 = receiver.receive(recvSet, rCpsiShare, rArithmeticShare, sockets[0]);
    auto p1 = sender.send(sendSet, associatedData, sCpsiShare, sArithmeticShare, sockets[1]);
    eval(p0, p1);

    auto shareByteLength = config.shareByteLength();
    for (u64 i = 0; i < n; ++i)
    {
        auto k = rCpsiShare.mMapping[i];
        auto rv = readPrimeElement(&rArithmeticShare(k, 0), shareByteLength);
        auto sv = readPrimeElement(&sArithmeticShare(k, 0), shareByteLength);
        auto act = modAddPrime(rv, sv, prime);
        auto exp = i < n / 2 ? associatedData[i] : u64(0);

        if (act != exp)
        {
            std::cout << "idx=" << i << " act=" << act << " exp=" << exp << std::endl;
            throw RTE_LOC;
        }
    }
}

//0719
void Cpsi_Rs_toy_comm_breakdown_test(const CLP& cmd)
{
    auto n = cmd.getOr("n", u64(1) << 20);
    auto prime = cmd.getOr("p", RsCpsiDefaultPrime);
    auto nt = cmd.getOr("nt", std::max<u64>(u64(1), std::thread::hardware_concurrency()));
    auto dataByteLength = RsCpsiDataByteLength(prime);
    auto primePayloadBytes = RsCpsiPrimeByteLength(prime);

    auto params = oc::CuckooIndex<>::selectParams(n, 40, 0, 3);
    auto numBins = params.numBins();
    auto keyBitLength = u64(40) + oc::log2ceil(numBins);
    auto logN = oc::log2ceil(n);

    struct PartMeasure
    {
        u64 mBytes = 0;
        double mSeconds = 0;
    };

    struct ModeMeasure
    {
        RsCpsiCommBreakdown mComm;
        CpsiRunOutput mRun;
    };

    auto sent = [](std::array<LocalAsyncSocket, 2>& sockets) {
        return sockets[0].bytesSent() + sockets[1].bytesSent();
    };

    auto timeRun = [&](auto&& fn) {
        auto begin = std::chrono::steady_clock::now();
        auto bytes = fn();
        auto end = std::chrono::steady_clock::now();
        return PartMeasure{ bytes, std::chrono::duration<double>(end - begin).count() };
    };

    auto measureVole = [&]() {
        return timeRun([&]() {
            auto sockets = LocalAsyncSocket::makePair();
            auto sender = oc::SilentVoleSender<block, block, oc::CoeffCtxGF128>{};
            auto receiver = oc::SilentVoleReceiver<block, block, oc::CoeffCtxGF128>{};
            auto prng0 = PRNG(block(11, 12));
            auto prng1 = PRNG(block(13, 14));
            auto delta = prng0.get<block>();

            receiver.mNumThreads = nt;
            auto p0 = sender.silentSendInplace(delta, numBins, prng0, sockets[0]);
            auto p1 = receiver.silentReceiveInplace(numBins, prng1, sockets[1]);
            eval(p0, p1);
            return sent(sockets);
        });
    };

    auto runMode = [&](ValueShareType type, u64 valueBytes, block seed) {
        std::vector<block> recvSet(n), sendSet(n);
        auto prng = PRNG(seed);
        prng.get(recvSet.data(), recvSet.size());
        sendSet = recvSet;

        auto breakdown = RsCpsiCommBreakdown{};
        gRsCpsiCommBreakdown = &breakdown;
        auto out = runCpsiMeasured(prng, recvSet, sendSet, nt, type, prime, valueBytes);
        gRsCpsiCommBreakdown = nullptr;

        if (out.mIntersection.size() != n)
        {
            printMissing(type == ValueShareType::prime ? "prime-cpsi" : "xor-cpsi", out.mIntersection, n);
            throw RTE_LOC;
        }

        if (breakdown.total() != out.mRecvBytes + out.mSendBytes)
            throw RTE_LOC;

        return ModeMeasure{ breakdown, std::move(out) };
    };

    auto roundBitsToBytes = [](u64 bits) {
        return oc::divCeil(bits, u64(8)) * u64(8);
    };

    auto theoryOprfBits = double(roundBitsToBytes(128)) * 1.3 * 1.3 * double(n);
    auto theoryOpprfXorBits = 3.0 * 1.3 * double(n) * double(roundBitsToBytes(40 + logN + 8 * dataByteLength));
    auto theoryOpprfPrimeBits = 3.0 * 1.3 * double(n) * double(roundBitsToBytes(40 + logN + 8 * primePayloadBytes));
    auto theoryPeqtBits = 4.0 * 1.3 * double(n) * double(roundBitsToBytes(40 + logN));
    auto theoryOtherBits = double(roundBitsToBytes(128));

    auto vole = measureVole();
    auto xorMode = runMode(ValueShareType::Xor, dataByteLength, block(41, 42));
    auto primeMode = runMode(ValueShareType::prime, 0, block(43, 44));

    auto splitOprf = [&](u64 oprfBytes) {
        return oprfBytes > vole.mBytes ? oprfBytes - vole.mBytes : u64(0);
    };

    auto xorOprfNoVole = splitOprf(xorMode.mComm.mOprf);
    auto primeOprfNoVole = splitOprf(primeMode.mComm.mOprf);
    auto xorTotalBits = 8 * (vole.mBytes + xorOprfNoVole + xorMode.mComm.mOpprf + xorMode.mComm.mPeqt + xorMode.mComm.mOther);
    auto primeTotalBits = 8 * (vole.mBytes + primeOprfNoVole + primeMode.mComm.mOpprf + primeMode.mComm.mPeqt + primeMode.mComm.mOther);
    auto theoryXorTotal = theoryOprfBits + theoryOpprfXorBits + theoryPeqtBits + theoryOtherBits;
    auto theoryPrimeTotal = theoryOprfBits + theoryOpprfPrimeBits + theoryPeqtBits + theoryOtherBits;

    std::cout << std::fixed << std::setprecision(6);
    std::cout << "CPSI_TOY_PART_COMPARE n=" << n
        << " numBins=" << numBins
        << " keyBits=" << keyBitLength
        << " xorPayloadBytes=" << dataByteLength
        << " primePayloadBytes=" << primePayloadBytes
        << " nt=" << nt << std::endl;
    std::cout << "part,theoryXorBits,theoryPrimeBits,xorActualBits,primeActualBits" << std::endl;
    std::cout << "VOLE,-,-," << (8 * vole.mBytes) << "," << (8 * vole.mBytes) << std::endl;
    std::cout << "OPRF," << theoryOprfBits << "," << theoryOprfBits << ","
        << (8 * xorOprfNoVole) << "," << (8 * primeOprfNoVole) << std::endl;
    std::cout << "OPPRF," << theoryOpprfXorBits << "," << theoryOpprfPrimeBits << ","
        << (8 * xorMode.mComm.mOpprf) << "," << (8 * primeMode.mComm.mOpprf) << std::endl;
    std::cout << "PEQT," << theoryPeqtBits << "," << theoryPeqtBits << ","
        << (8 * xorMode.mComm.mPeqt) << "," << (8 * primeMode.mComm.mPeqt) << std::endl;
    std::cout << "Others," << theoryOtherBits << "," << theoryOtherBits << ","
        << (8 * xorMode.mComm.mOther) << "," << (8 * primeMode.mComm.mOther) << std::endl;
    std::cout << "Total," << theoryXorTotal << "," << theoryPrimeTotal << ","
        << xorTotalBits << "," << primeTotalBits << std::endl;
    std::cout << "mode,totalActualBits,totalTimeSeconds" << std::endl;
    std::cout << "xor," << (8 * (xorMode.mRun.mRecvBytes + xorMode.mRun.mSendBytes)) << ","
        << xorMode.mRun.mSeconds << std::endl;
    std::cout << "prime," << (8 * (primeMode.mRun.mRecvBytes + primeMode.mRun.mSendBytes)) << ","
        << primeMode.mRun.mSeconds << std::endl;
    std::cout << "vole," << (8 * vole.mBytes) << "," << vole.mSeconds << std::endl;
}
