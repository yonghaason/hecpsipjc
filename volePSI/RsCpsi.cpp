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
        void samplePrimeShares(MatrixView<u8> values, PRNG& prng, span<const u64> primes,
            u64 bitLength, u64 byteLength)
        {
            for (u64 i = 0; i < values.rows(); ++i)
            {
                auto slot = u64{};
                for (u64 j = 0; j < values.cols(); j += byteLength, ++slot)
                {
                    auto prime = primes[slot % primes.size()];
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

        using u128 = unsigned __int128;

        // The encoded data component can exceed 64 bits, so it is read and
        // written through a u128 rather than a u64.
        u128 readEncodedElement(const u8* src, u64 byteLength)
        {
            auto v = u128{};
            std::memcpy(&v, src, byteLength);
            return v;
        }

        void writeEncodedElement(u8* dst, u64 byteLength, u128 v)
        {
            std::memcpy(dst, &v, byteLength);
        }

        // floor(2^encBitLength / prime): the number of representatives of each
        // residue class that fit in encBitLength bits.
        u128 primeCosetSize(u64 prime, u64 encBitLength)
        {
            return (u128(1) << encBitLength) / prime;
        }

        u128 sampleBelow(PRNG& prng, u128 bound)
        {
            auto bits = u64{};
            for (auto t = bound - 1; t; t >>= 1)
                ++bits;

            if (bits == 0)
                return 0;

            auto mask = bits >= 128 ?
                ~u128(0) :
                ((u128(1) << bits) - 1);
            auto v = u128{};

            do
            {
                v = 0;
                prng.get<u8>(span<u8>((u8*)&v, sizeof(v)));
                v &= mask;
            } while (v >= bound);

            return v;
        }

        // Map u in [0,p) to a uniformly chosen representative u + p*rho that
        // fits in encBitLength bits. The result is uniform over [0, p*cosetSize)
        // and therefore within p / 2^encBitLength <= 2^-statSecParam of uniform
        // over all encBitLength-bit strings.
        u128 encodePrimeElement(PRNG& prng, u64 u, u64 prime, u128 cosetSize)
        {
            return u128(u) + u128(prime) * sampleBelow(prng, cosetSize);
        }

        u64 decodePrimeElement(u128 encoded, u64 prime)
        {
            return u64(encoded % prime);
        }

        u64 primeEncShareByteLength(u64 valueByteLength, u64 dataByteLength, u64 encByteLength)
        {
            return (valueByteLength / dataByteLength) * encByteLength;
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
            auto okvsValueByteLength = u64{};
            auto cosetSizes = std::vector<u128>{};

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
            okvsValueByteLength = primeEncShareByteLength(mValueByteLength, mPrimeDataByteLength, mPrimeEncByteLength);
            for (auto q : mPrimes)
                cosetSizes.push_back(primeCosetSize(q, mPrimeEncBitLength));
        }
        else
        {
            shareByteLength = values.cols();
            okvsValueByteLength = shareByteLength;
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
        Tv.resize(Y.size() * 3, keyByteLength + okvsValueByteLength, oc::AllocType::Uninitialized);

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
            samplePrimeShares(ret.mValues, mPrng, mPrimes, mPrimeBitLength, mPrimeByteLength);
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
                    if (mType != ValueShareType::prime)
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
                        auto shareOffset = u64{};
                        auto encOffset = u64{};
                        auto slot = u64{};
                        while (srcOffset < values.cols())
                        {
                            auto prime = mPrimes[slot % mPrimes.size()];
                            auto tv = readPrimeElement(&values(b, srcOffset), mPrimeDataByteLength) % prime;
                            auto rr = readPrimeElement(&ret.mValues(i, shareOffset), mPrimeByteLength);
                            auto u = modSubPrime(tv, rr, prime);

                            writeEncodedElement(&*TvIter + encOffset, mPrimeEncByteLength,
                                encodePrimeElement(mPrng, u, prime, cosetSizes[slot % mPrimes.size()]));

                            srcOffset += mPrimeDataByteLength;
                            shareOffset += mPrimeByteLength;
                            encOffset += mPrimeEncByteLength;
                            ++slot;
                        }
                    }
                    else
                    {
                        co_await chl.close();
                        throw RTE_LOC;
                    }
                    TvIter += okvsValueByteLength;
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
        applyTriples(*cmp);

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
            auto okvsValueByteLength = u64{};

        if (mRecverSize != X.size())
            throw RTE_LOC;
        //0714
        //0719
        if (mType == ValueShareType::prime)
        {
            shareByteLength = primeShareByteLength(mValueByteLength, mPrimeDataByteLength, mPrimeByteLength);
            okvsValueByteLength = primeEncShareByteLength(mValueByteLength, mPrimeDataByteLength, mPrimeEncByteLength);
        }
        else
        {
            shareByteLength = mValueByteLength;
            okvsValueByteLength = shareByteLength;
        }

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

        r.resize(Tx.size(), keyByteLength + okvsValueByteLength, oc::AllocType::Uninitialized);

        if (mTimer)
            opprf->setTimer(*mTimer);

        co_await (opprf->receive(mSenderSize * 3, Tx, r, mPrng, mNumThreads, chl));

        if (mTimer)
            cmp->setTimer(*mTimer);

        cir = isZeroCircuit(keyBitLength);
        cmp->init(r.rows(), cir, mNumThreads, 0, mPrng.get());
        applyTriples(*cmp);

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

                //0719
                if (mType == ValueShareType::prime)
                {
                    // undo the redundant encoding: the share is the recovered
                    // representative reduced modulo p.
                    for (u64 i = 0; i < numBins; ++i)
                    {
                        auto shareOffset = u64{};
                        auto encOffset = u64{};
                        auto slot = u64{};
                        while (shareOffset < shareByteLength)
                        {
                            auto encoded = readEncodedElement(
                                &r(i, keyByteLength + encOffset), mPrimeEncByteLength);

                            writePrimeElement(&ret.mValues(i, shareOffset), mPrimeByteLength,
                                decodePrimeElement(encoded, mPrimes[slot % mPrimes.size()]));

                            shareOffset += mPrimeByteLength;
                            encOffset += mPrimeEncByteLength;
                            ++slot;
                        }
                    }
                }
                else
                {
                    for (u64 i = 0; i < numBins; ++i)
                    {
                        std::memcpy(&ret.mValues(i, 0), &r(i, keyByteLength), shareByteLength);
                    }
                }
            }
        }

        setTimePoint("RsCpsiReceiver::receive done");
    }


}
