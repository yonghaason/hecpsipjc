#include "RsCpsi_Tests.h"
#include "volePSI/RsPsi.h"
#include "volePSI/RsCpsi.h"
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
