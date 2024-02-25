#ifndef __SHA2_32_H__
#define __SHA2_32_H__

#include "shacom.h"


// {256} Σ₀(𝑥) = ROTR²(𝑥) ⊕ ROTR¹³(𝑥) ⊕ ROTR²²(𝑥)
word32 sha256_bsigma_0(word32 x);
// {256} Σ₁(𝑥) = ROTR⁶(𝑥) ⊕ ROTR¹¹(𝑥) ⊕ ROTR²⁵(𝑥)
word32 sha256_bsigma_1(word32 x);
// {256} σ₀(𝑥) = ROTR⁷(𝑥) ⊕ ROTR¹⁸(𝑥) ⊕ SHR³(𝑥)
word32 sha256_ssigma_0(word32 x);
// {256} σ₁(𝑥) = ROTR¹⁷(𝑥) ⊕ ROTR¹⁹(𝑥) ⊕ SHR¹⁰(𝑥)
word32 sha256_ssigma_1(word32 x);

void sha256_parse(BLOCK32* mblocks, word64 block_count, word8* message);
void sha256_digest(word32* H, BLOCK32* mblocks, int block_count);

#endif
