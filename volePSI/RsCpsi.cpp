#include "RsCpsi.h"

//0714
#include <limits>
#include <sstream>

namespace volePSI
{
    //0714
    namespace
    {
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
        u64 primeBitMask(u64 bitLength)
        {
            return bitLength == sizeof(u64) * 8 ?
                std::numeric_limits<u64>::max() :
                ((u64(1) << bitLength) - 1);
        }

        //0719
        u64 samplePrime(PRNG& prng, u64 prime, u64 bitLength, u64 byteLength)
        {
            auto mask = primeBitMask(bitLength);
            auto v = u64{};

            do
            {
                v = 0;
                prng.get<u8>(span<u8>((u8*)&v, byteLength));
                v &= mask;
            } while (v >= prime);

            return v;
        }

        //0719
        void samplePrimeShares(MatrixView<u8> values, PRNG& prng, u64 prime, u64 bitLength, u64 byteLength)
        {
            for (u64 i = 0; i < values.rows(); ++i)
            {
                for (u64 j = 0; j < values.cols(); j += byteLength)
                {
                    writePrimeElement(&values(i, j), byteLength, samplePrime(prng, prime, bitLength, byteLength));
                }
            }
        }

        //0719
        u64 modSubPrime(u64 lhs, u64 rhs, u64 prime)
        {
            return lhs >= rhs ?
                lhs - rhs :
                prime - (rhs - lhs);
        }

        //0719
        u64 primeShareByteLength(u64 valueByteLength, u64 dataByteLength, u64 primeByteLength)
        {
            return (valueByteLength / dataByteLength) * primeByteLength;
        }
    }

    Proto RsCpsiSender::send(span<block> Y, oc::MatrixView<u8> values, Sharing& ret, Socket& chl)
    {
            auto cuckooSeed = block{};
            auto params = oc::CuckooParam{};
            auto numBins = u64{};
            auto sIdx = SimpleIndex{};
            auto keyBitLength = u64{};
            auto keyByteLength = u64{};
            auto hashers = std::array<oc::AES, 3> {};
            auto Ty = std::vector<block>{};
            auto Tv = Matrix<u8>{};
            auto r = Matrix<u8>{};
            auto TyIter = std::vector<block>::iterator{};
            auto TvIter = Matrix<u8>::iterator{};
            auto rIter = Matrix<u8>::iterator{};
            auto opprf = std::make_unique<RsOpprfSender>();
            auto cmp = std::make_unique<Gmw>();
            auto cir = BetaCircuit{};
            //0719
            auto shareByteLength = u64{};

        setTimePoint("RsCpsiSender::send begin");
        if (mSenderSize != Y.size() || mValueByteLength != values.cols())
        {
            co_await chl.close();
            throw RTE_LOC;
        }
        //0714
        //0719
        if (mType == ValueShareType::prime)
        {
            shareByteLength = primeShareByteLength(mValueByteLength, mPrimeDataByteLength, mPrimeByteLength);
        }
        else
        {
            shareByteLength = values.cols();
        }

        co_await (chl.recv(cuckooSeed));
        setTimePoint("RsCpsiSender::send recv");

        params = oc::CuckooIndex<>::selectParams(mRecverSize, mSsp, 0, 3);
        numBins = params.numBins();
        sIdx.init(numBins, mSenderSize, mSsp, 3);
        sIdx.insertItems(Y, cuckooSeed);

        setTimePoint("RsCpsiSender::send simpleHash");


        keyBitLength = mSsp + oc::log2ceil(params.numBins());
        keyByteLength = oc::divCeil(keyBitLength, 8);

        hashers[0].setKey(block(3242, 23423) ^ cuckooSeed);
        hashers[1].setKey(block(4534, 45654) ^ cuckooSeed);
        hashers[2].setKey(block(5677, 67867) ^ cuckooSeed);

        // The OPPRF input value of the i'th input under the j'th cuckoo
        // hash function.
        Ty.resize(Y.size() * 3);

        // The value associated with the k'th OPPRF input
        Tv.resize(Y.size() * 3, keyByteLength + shareByteLength, oc::AllocType::Uninitialized);

        // The special value assigned to the i'th bin.
        r.resize(numBins, keyByteLength, oc::AllocType::Uninitialized);

        TyIter = Ty.begin();
        TvIter = Tv.begin();
        rIter = r.begin();
        ret.mValues.resize(numBins, shareByteLength, oc::AllocType::Uninitialized);
        mPrng.get<u8>(r);
        //0714
        //0719
        if (mType == ValueShareType::prime)
            samplePrimeShares(ret.mValues, mPrng, mPrime, mPrimeBitLength, mPrimeByteLength);
        else
            mPrng.get<u8>(ret.mValues);



        for (u64 i = 0; i < numBins; ++i)
        {
            auto bin = sIdx.mBins[i];
            auto size = sIdx.mBinSizes[i];

            for (u64 p = 0; p < size; ++p)
            {
                auto j = bin[p].hashIdx();
                auto& hj = hashers[j];
                auto b = bin[p].idx();
                *TyIter = hj.hashBlock(Y[b]);
                memcpy(&*TvIter, &*rIter, keyByteLength);
                TvIter += keyByteLength;

                if (values.size())
                {
                    memcpy(&*TvIter, &values(b, 0), values.cols());

                    if (mType == ValueShareType::Xor)
                    {
                        for (u64 k = 0; k < values.cols(); ++k)
                        {
                            TvIter[k] ^= ret.mValues(i, k);
                        }
                    }
                    else if (mType == ValueShareType::add32)
                    {
                        assert(values.cols() % sizeof(u32) == 0);
                        auto ss = values.cols() / sizeof(u32);
                        auto tv = (u32*)&*TvIter;
                        auto rr = (u32*)&ret.mValues(i, 0);
                        for (u64 k = 0; k < ss; ++k)
                            tv[k] -= rr[k];
                    }
                    //0714
                    //0719
                    else if (mType == ValueShareType::prime)
                    {
                        auto srcOffset = u64{};
                        auto dstOffset = u64{};
                        while (srcOffset < values.cols())
                        {
                            auto tv = readPrimeElement(&values(b, srcOffset), mPrimeDataByteLength);
                            auto rr = readPrimeElement(&ret.mValues(i, dstOffset), mPrimeByteLength);

                            writePrimeElement(&*TvIter + dstOffset, mPrimeByteLength, modSubPrime(tv, rr, mPrime));
                            srcOffset += mPrimeDataByteLength;
                            dstOffset += mPrimeByteLength;
                        }
                    }
                    else
                    {
                        co_await chl.close();
                        throw RTE_LOC;
                    }
                    TvIter += shareByteLength;
                }

                ++TyIter;
            }
            rIter += keyByteLength;
        }

        while (TyIter != Ty.end())
        {
            *TyIter = mPrng.get();
            ++TyIter;
        }

        setTimePoint("RsCpsiSender::send setValues");

        if (mTimer)
            opprf->setTimer(*mTimer);

        co_await (opprf->send(numBins, Ty, Tv, mPrng, mNumThreads, chl));

        if (mTimer)
            cmp->setTimer(*mTimer);

        cir = isZeroCircuit(keyBitLength);
        cmp->init(r.rows(), cir, mNumThreads, 1, mPrng.get());

        cmp->setInput(0, r);
        {
            auto before = chl.bytesSent();
            auto phaseBegin = std::chrono::steady_clock::now();
            co_await (cmp->run(chl));
            if (gRsCpsiTimeBreakdown)
                gRsCpsiTimeBreakdown->mSenderPeqt = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - phaseBegin).count();
            if (gRsCpsiCommBreakdown)
            {
                co_await chl.flush();
                addRsCpsiComm(gRsCpsiCommBreakdown->mPeqt, before, chl.bytesSent());
            }
        }

        {

            auto ss = cmp->getOutputView(0);
            ret.mFlagBits.resize(numBins);
            std::copy(ss.begin(), ss.begin() + ret.mFlagBits.sizeBytes(), ret.mFlagBits.data());
        }
    }

    Proto RsCpsiReceiver::receive(span<block> X, Sharing& ret, Socket& chl)
    {
        auto cuckooSeed = block{};
            auto cuckoo = oc::CuckooIndex<>{};
            auto Tx = std::vector<block>{};
            auto hashers = std::array<oc::AES, 3> {};
            auto numBins = u64{};
            auto keyBitLength = u64{};
            auto keyByteLength = u64{};
            auto r = Matrix<u8>{};
            auto opprf = std::make_unique<RsOpprfReceiver>();
            auto cmp = std::make_unique<Gmw>();
            auto cir = BetaCircuit{};
            //0719
            auto shareByteLength = u64{};

        if (mRecverSize != X.size())
            throw RTE_LOC;
        //0714
        //0719
        if (mType == ValueShareType::prime)
            shareByteLength = primeShareByteLength(mValueByteLength, mPrimeDataByteLength, mPrimeByteLength);
        else
            shareByteLength = mValueByteLength;

        setTimePoint("RsCpsiReceiver::receive begin");

        cuckooSeed = mPrng.get();
        {
            auto before = chl.bytesSent();
            co_await (chl.send(std::move(cuckooSeed)));
            if (gRsCpsiCommBreakdown)
            {
                co_await chl.flush();
                addRsCpsiComm(gRsCpsiCommBreakdown->mOther, before, chl.bytesSent());
            }
        }
        cuckoo.init(mRecverSize, mSsp, 0, 3);

        cuckoo.insert(X, cuckooSeed);
        Tx.resize(cuckoo.mNumBins);

        setTimePoint("RsCpsiReceiver::receive cuckoo");

        hashers[0].setKey(block(3242, 23423) ^ cuckooSeed);
        hashers[1].setKey(block(4534, 45654) ^ cuckooSeed);
        hashers[2].setKey(block(5677, 67867) ^ cuckooSeed);

        ret.mMapping.resize(X.size(), ~u64(0));
        numBins = cuckoo.mBins.size();
        for (u64 i = 0; i < numBins; ++i)
        {
            auto& bin = cuckoo.mBins[i];
            if (bin.isEmpty() == false)
            {
                auto j = bin.hashIdx();
                auto b = bin.idx();
            
                //j = oc::CuckooIndex<>::minCollidingHashIdx(i, cuckoo.mHashes[b], 3, numBins);

                auto& hj = hashers[j];
                Tx[i] = hj.hashBlock(X[b]);
                ret.mMapping[b] = i;
            }
            else
            {
                Tx[i] = block(i, 0);
            }
        }
        setTimePoint("RsCpsiReceiver::receive values");

        keyBitLength = mSsp + oc::log2ceil(Tx.size());
        keyByteLength = oc::divCeil(keyBitLength, 8);

        r.resize(Tx.size(), keyByteLength + shareByteLength, oc::AllocType::Uninitialized);

        if (mTimer)
            opprf->setTimer(*mTimer);

        co_await (opprf->receive(mSenderSize * 3, Tx, r, mPrng, mNumThreads, chl));

        if (mTimer)
            cmp->setTimer(*mTimer);

        cir = isZeroCircuit(keyBitLength);
        cmp->init(r.rows(), cir, mNumThreads, 0, mPrng.get());

        cmp->implSetInput(0, r, r.cols());

        {
            auto before = chl.bytesSent();
            auto phaseBegin = std::chrono::steady_clock::now();
            co_await (cmp->run(chl));
            if (gRsCpsiTimeBreakdown)
                gRsCpsiTimeBreakdown->mReceiverPeqt = std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - phaseBegin).count();
            if (gRsCpsiCommBreakdown)
            {
                co_await chl.flush();
                addRsCpsiComm(gRsCpsiCommBreakdown->mPeqt, before, chl.bytesSent());
            }
        }

        {
            auto ss = cmp->getOutputView(0);

            ret.mFlagBits.resize(numBins);
            std::copy(ss.begin(), ss.begin() + ret.mFlagBits.sizeBytes(), ret.mFlagBits.data());

            if (shareByteLength)
            {
                ret.mValues.resize(numBins, shareByteLength);

                for (u64 i = 0; i < numBins; ++i)
                {
                    std::memcpy(&ret.mValues(i, 0), &r(i, keyByteLength), shareByteLength);
                }
            }
        }

        setTimePoint("RsCpsiReceiver::receive done");
    }


}
