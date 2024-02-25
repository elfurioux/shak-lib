#ifndef __SHACOM_H__
#define __SHACOM_H__


typedef unsigned long long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

// typedef __uint128_t word128;     -> not useful ATM
// typedef uint16 word16;           -> not useful ATM

typedef uint64 word64;
typedef uint32 word32;
typedef uint8 word8;


// SHRⁿ(𝑥) = 𝑥 >> 𝑛
word32 SHR(uint8 n, word32 x);
// ROTLⁿ(𝑥) = (𝑥 << 𝑛) ∨ (𝑥 >> 𝑤-𝑛)
word32 ROTR(uint8 n, word32 x);
// ROTRⁿ(𝑥) = (𝑥 >> 𝑛) ∨ (𝑥 << 𝑤-𝑛)
word32 ROTL(uint8 n, word32 x);
// 𝐶𝐻(𝑥, 𝑦, 𝑧) = (𝑥 ∧ 𝑦) ⊕ (¬𝑥 ∧ 𝑧)
word32 ch(word32 x, word32 y, word32 z);
// 𝑀𝐴𝐽(𝑥, 𝑦, 𝑧) = (𝑥 ∧ 𝑦) ⊕ (𝑥 ∧ 𝑧) ⊕ (𝑦 ∧ 𝑧)
word32 maj(word32 x, word32 y, word32 z);
// Parity(𝑥, 𝑦, 𝑧) = 𝑥 ⊕ 𝑦 ⊕ 𝑧
word32 parity(word32 x, word32 y, word32 z);

// those functions are for 1024bit-sized block hash functions computations and are equivalent
// to their 32 bit versions. only difference is that they are meant for 64bit words.

// SHR64ⁿ(𝑥) = 𝑥 >> 𝑛
word64 SHR64(uint8 n, word64 x);
// ROTL64ⁿ(𝑥) = (𝑥 << 𝑛) ∨ (𝑥 >> 𝑤-𝑛)
word64 ROTR64(uint8 n, word64 x);
// ROTR64ⁿ(𝑥) = (𝑥 >> 𝑛) ∨ (𝑥 << 𝑤-𝑛)
word64 ROTL64(uint8 n, word64 x);
// 𝐶𝐻64(𝑥, 𝑦, 𝑧) = (𝑥 ∧ 𝑦) ⊕ (¬𝑥 ∧ 𝑧)
word64 ch64(word64 x, word64 y, word64 z);
// 𝑀𝐴𝐽64(𝑥, 𝑦, 𝑧) = (𝑥 ∧ 𝑦) ⊕ (𝑥 ∧ 𝑧) ⊕ (𝑦 ∧ 𝑧)
word64 maj64(word64 x, word64 y, word64 z);


#endif
