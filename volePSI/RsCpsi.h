#pragma once
// © 2022 Visa.
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


#include "volePSI/Defines.h"
#include "volePSI/config.h"
#ifdef VOLE_PSI_ENABLE_CPSI

#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "volePSI/RsOpprf.h"
#include "volePSI/GMW/Gmw.h"
#include "volePSI/SimpleIndex.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Common/BitVector.h"

namespace volePSI
{
    constexpr bool RsCpsiSenderDebug = false;

    enum ValueShareType
    {
        Xor,
        add32,
        //0714
        prime
    };

    //0714
    //0719
    // The default prime is the largest prime smaller than 2^32.
    constexpr u64 RsCpsiDefaultPrime = 4294967291ULL;

    //0719
    inline u64 RsCpsiPrimeBitLength(u64 primeModulus)
    {
        return oc::log2ceil(primeModulus);
    }

    //0719
    inline u64 RsCpsiPrimeByteLength(u64 primeModulus)
    {
        return oc::divCeil(RsCpsiPrimeBitLength(primeModulus), 8);
    }

    //0719
    inline u64 RsCpsiDataBitLength(u64 primeModulus)
    {
        return RsCpsiPrimeBitLength(primeModulus) / 2;
    }

    //0719
    inline u64 RsCpsiDataByteLength(u64 primeModulus)
    {
        return oc::divCeil(RsCpsiDataBitLength(primeModulus), 8);
    }

    namespace details
    {

        struct RsCpsiBase
        {

            u64 mSenderSize = 0;
            u64 mRecverSize = 0;
            u64 mValueByteLength = 0;
            u64 mSsp = 0, mNumThreads = 0;
            PRNG mPrng;
            ValueShareType mType = ValueShareType::Xor;
            //0719
            u64 mPrime = RsCpsiDefaultPrime;
            u64 mPrimeBitLength = RsCpsiPrimeBitLength(RsCpsiDefaultPrime);
            u64 mPrimeByteLength = RsCpsiPrimeByteLength(RsCpsiDefaultPrime);
            //0719
            u64 mPrimeDataBitLength = RsCpsiDataBitLength(RsCpsiDefaultPrime);
            u64 mPrimeDataByteLength = RsCpsiDataByteLength(RsCpsiDefaultPrime);

            void init(
                u64 senderSize,
                u64 recverSize,
                u64 valueByteLength,
                u64 statSecParam,
                block seed,
                u64 numThreads,
                ValueShareType type = ValueShareType::Xor,
                //0719
                u64 primeModulus = RsCpsiDefaultPrime)
            {
                //0719
                auto primeBitLength = RsCpsiPrimeBitLength(primeModulus);
                auto primeByteLength = RsCpsiPrimeByteLength(primeModulus);
                auto primeDataBitLength = RsCpsiDataBitLength(primeModulus);
                auto primeDataByteLength = RsCpsiDataByteLength(primeModulus);

                mSenderSize = senderSize;
                mRecverSize = recverSize;
                mValueByteLength = valueByteLength;
                mSsp = statSecParam;
                mPrng.SetSeed(seed);
                mNumThreads = numThreads;
                mType = type;
                //0719
                mPrime = primeModulus;
                mPrimeBitLength = primeBitLength;
                mPrimeByteLength = primeByteLength;
                mPrimeDataBitLength = primeDataBitLength;
                mPrimeDataByteLength = primeDataByteLength;
            }
        };
    }

    class RsCpsiSender : public details::RsCpsiBase, public oc::TimerAdapter
    {
    public:
        struct Sharing
        {
            // The sender's share of the bit vector indicating that
            // the i'th row is a real row (1) or a row (0).
            oc::BitVector mFlagBits;

            // Secret share of the values associated with the output
            // elements. These values are from the sender.
            oc::Matrix<u8> mValues;

            // The mapping of the senders input rows to output rows.
            // Each input row might have been mapped to one of three
            // possible output rows.
            std::vector<std::array<u64, 3>> mMapping;

        };

        // perform the join with Y being the join keys with associated values.
        // The output is written to s.
        Proto send(span<block> Y, oc::MatrixView<u8> values, Sharing& s, Socket& chl);

    };


    class RsCpsiReceiver :public details::RsCpsiBase, public oc::TimerAdapter
    {
    public:

        struct Sharing
        {
            // The sender's share of the bit vector indicating that
            // the i'th row is a real row (1) or a row (0).
            oc::BitVector mFlagBits;

            // Secret share of the values associated with the output
            // elements. These values are from the sender.
            oc::Matrix<u8> mValues;

            // The mapping of the receiver's input rows to output rows.
            std::vector<u64> mMapping;

        };

        // perform the join with X being the join keys.
        // The output is written to s.
        Proto receive(span<block> X, Sharing& s, Socket& chl);

    };

}

#endif
