#pragma once
#include "cryptoTools/Common/block.h"
#include <array>
#include <cstdint>
#include <cstring>
namespace volePSI {
// Arithmetic in Z/(2^84), serialized in 11 little-endian bytes.
using UInt84Bytes = std::array<uint8_t, 11>;
using UInt128 = unsigned __int128;
constexpr UInt128 UInt84Mask = (UInt128(1) << 84) - 1;
inline UInt128 load84(const void* p) { UInt128 x=0; std::memcpy(&x,p,11); return x & UInt84Mask; }
inline UInt84Bytes store84(UInt128 x) { UInt84Bytes a{}; x &= UInt84Mask; std::memcpy(a.data(),&x,11); return a; }
inline UInt84Bytes operator+(const UInt84Bytes& a,const UInt84Bytes& b) { return store84(load84(a.data())+load84(b.data())); }
inline UInt84Bytes operator-(const UInt84Bytes& a,const UInt84Bytes& b) { return store84(load84(a.data())-load84(b.data())); }
inline UInt84Bytes operator-(const UInt84Bytes& a) { return store84(-load84(a.data())); }
inline UInt84Bytes wTrunc(const osuCrypto::block& k) { return store84(load84(&k)); }
inline UInt84Bytes wShl(const UInt84Bytes& a,uint64_t j) { return store84(load84(a.data()) << j); }
inline UInt84Bytes wMul(const UInt84Bytes& a,const UInt84Bytes& b) { return store84(load84(a.data())*load84(b.data())); }
}
