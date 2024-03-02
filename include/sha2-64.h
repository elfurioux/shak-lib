#ifndef __SHA2_64_H__
#define __SHA2_64_H__

#include "shacom.h"


// {512} Σ₀(𝑥) = ROTR²⁸(𝑥) ⊕ ROTR³⁴(𝑥) ⊕ ROTR³⁹(𝑥)
word64 sha512_bsigma_0(word64 x);
// {512} Σ₁(𝑥) = ROTR¹⁴(𝑥) ⊕ ROTR¹⁸(𝑥) ⊕ ROTR⁴¹(𝑥)
word64 sha512_bsigma_1(word64 x);
// {512} σ₀(𝑥) = ROTR¹(𝑥) ⊕ ROTR⁸(𝑥) ⊕ SHR⁷(𝑥)
word64 sha512_ssigma_0(word64 x);
// {512} σ₁(𝑥) = ROTR¹⁹(𝑥) ⊕ ROTR⁶¹(𝑥) ⊕ SHR⁶(𝑥)
word64 sha512_ssigma_1(word64 x);

void sha512_parse(BLOCK64* mblocks, word64 block_count, word8* message);
void sha512_digest(word64* H, BLOCK64* mblocks, int block_count /*, verbose vbtype */);

#endif
