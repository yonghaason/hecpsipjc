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
    // The largest prime below 2^32 satisfying p = 1 mod 16384. This enables
    // SEAL batching with the default polynomial modulus degree N = 8192.
    constexpr u64 RsCpsiDefaultPrime = 4294475777ULL;

    // Residue primes for the integer-inner-product setting. A correct integer inner
    // product needs an arithmetic space of 2*l + ceil(log2 |X n Y|) bits,
    // which for l = 32 and |X n Y| <= 2^20 is 84 bits. No single RLWE
    // plaintext modulus holds that: SEAL caps plain_modulus at 60 bits. Two
    // 42-bit residues reach exactly 84; both are 1 mod 8192 so each residue
    // batches at N = 4096.
    //
    // A 42-bit plaintext needs more ciphertext modulus than SEAL's 128-bit
    // security table allows at N = 4096 (109 bits total). The protocol only
    // ever uses the first two coefficient primes, the third being SEAL's
    // key-switching prime which we never use. The two primes actually used,
    // 60+45 = 105 bits, are within the 109-bit bound for 128-bit security at
    // N = 4096; SEAL's check counts the unused third prime too and rejects
    // the split, so it is skipped (sec_level_type::none). Security is not
    // reduced: {60,45,20}. Measured
    // with uniformly random plaintexts at n = 2^20 (338 accumulated
    // ciphertexts), the invariant noise budget after modulus switching is
    // 6-7 bits; lowering the first prime below 60 or the second below 45
    // drops it to 0-2. (The first prime is what the transmitted ciphertext
    // lives on after modulus switching, so it sets the HE communication.)
    constexpr u64 RsCpsiRnsPrime0 = 4398046486529ULL;
    constexpr u64 RsCpsiRnsPrime1 = 4398046240769ULL;

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
    // Default payload width. Half the residue width keeps a single product
    // inside one residue; the integer-inner-product setting overrides it explicitly.
    inline u64 RsCpsiDataBitLength(u64 primeModulus)
    {
        return RsCpsiPrimeBitLength(primeModulus) / 2;
    }

    //0719
    inline u64 RsCpsiDataByteLength(u64 primeModulus)
    {
        return oc::divCeil(RsCpsiDataBitLength(primeModulus), 8);
    }

    // Statistical security parameter for the redundant encoding of a Z_p
    // element inside the OKVS value.
    //
    // Writing u in [0,p) as a plain ceil(log2 p)-bit string does not cover the
    // bit strings uniformly when p is not a power of two. In a bin that is not
    // in the intersection the OKVS decoder recovers a pseudorandom string, so
    // it can test whether the recovered data component lies in [0,p) and learn
    // non-membership for free -- with the default prime that test succeeds with
    // probability (2^32 - p)/2^32 ~= 2^-13.1 per bin. Encoding u as u + p*rho
    // over ceil(log2 p) + statSecParam bits removes the test, since every
    // encoded string is then a valid representative of some residue class.
    constexpr u64 RsCpsiDefaultPrimeStatSecParam = 40;

    inline u64 RsCpsiPrimeEncBitLength(u64 primeModulus, u64 statSecParam)
    {
        return RsCpsiPrimeBitLength(primeModulus) + statSecParam;
    }

    inline u64 RsCpsiPrimeEncByteLength(u64 primeModulus, u64 statSecParam)
    {
        return oc::divCeil(RsCpsiPrimeEncBitLength(primeModulus, statSecParam), 8);
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
            // One prime per residue. Single-residue mode holds just mPrime.
            std::vector<u64> mPrimes = { RsCpsiDefaultPrime };
            u64 mPrimeBitLength = RsCpsiPrimeBitLength(RsCpsiDefaultPrime);
            u64 mPrimeByteLength = RsCpsiPrimeByteLength(RsCpsiDefaultPrime);
            //0719
            u64 mPrimeDataBitLength = RsCpsiDataBitLength(RsCpsiDefaultPrime);
            u64 mPrimeDataByteLength = RsCpsiDataByteLength(RsCpsiDefaultPrime);
            u64 mPrimeStatSecParam = RsCpsiDefaultPrimeStatSecParam;
            u64 mPrimeEncBitLength =
                RsCpsiPrimeEncBitLength(RsCpsiDefaultPrime, RsCpsiDefaultPrimeStatSecParam);
            u64 mPrimeEncByteLength =
                RsCpsiPrimeEncByteLength(RsCpsiDefaultPrime, RsCpsiDefaultPrimeStatSecParam);

            void init(
                u64 senderSize,
                u64 recverSize,
                u64 valueByteLength,
                u64 statSecParam,
                block seed,
                u64 numThreads,
                ValueShareType type = ValueShareType::Xor,
                //0719
                u64 primeModulus = RsCpsiDefaultPrime,
                u64 primeStatSecParam = RsCpsiDefaultPrimeStatSecParam,
                std::vector<u64> residuePrimes = {},
                u64 dataBitLengthOverride = 0)
            {
                if (residuePrimes.empty())
                    residuePrimes = { primeModulus };
                // all residues share a width so the slot strides stay uniform
                for (auto q : residuePrimes)
                    if (RsCpsiPrimeBitLength(q) != RsCpsiPrimeBitLength(residuePrimes[0]))
                        throw RTE_LOC;
                primeModulus = residuePrimes[0];
                //0719
                auto primeBitLength = RsCpsiPrimeBitLength(primeModulus);
                auto primeByteLength = RsCpsiPrimeByteLength(primeModulus);
                auto primeDataBitLength = RsCpsiDataBitLength(primeModulus);
                auto primeDataByteLength = RsCpsiDataByteLength(primeModulus);
                auto primeEncBitLength =
                    RsCpsiPrimeEncBitLength(primeModulus, primeStatSecParam);
                auto primeEncByteLength =
                    RsCpsiPrimeEncByteLength(primeModulus, primeStatSecParam);

                // the encoded element is held in an unsigned __int128
                if (primeEncBitLength >= 128)
                    throw RTE_LOC;

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
                mPrimes = std::move(residuePrimes);
                if (dataBitLengthOverride)
                {
                    primeDataBitLength = dataBitLengthOverride;
                    primeDataByteLength = oc::divCeil(dataBitLengthOverride, 8);
                    // A payload may exceed one residue (each slot reduces it mod
                    // its own prime); it must only fit the full RNS modulus P.
                    if (dataBitLengthOverride >= primeBitLength * mPrimes.size())
                        throw RTE_LOC;
                }
                mPrimeDataBitLength = primeDataBitLength;
                mPrimeDataByteLength = primeDataByteLength;
                mPrimeStatSecParam = primeStatSecParam;
                mPrimeEncBitLength = primeEncBitLength;
                mPrimeEncByteLength = primeEncByteLength;
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
