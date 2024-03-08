#include <stdio.h>
#include <stdlib.h>

#include "shacom.h"
#include "shaconstants.h"
#include "sha2-64.h"


#define SHA512_CONST_LEN 80


const word64 SHA512_K[SHA512_CONST_LEN] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};


word64 sha512_bsigma_0(word64 x) {
    return ROTR64(28,x) ^ ROTR64(34,x) ^ ROTR64(39,x);
}

word64 sha512_bsigma_1(word64 x) {
    return ROTR64(14,x) ^ ROTR64(18,x) ^ ROTR64(41,x);
}

word64 sha512_ssigma_0(word64 x) {
    return ROTR64(1,x) ^ ROTR64(8,x) ^ SHR64(7,x);
}

word64 sha512_ssigma_1(word64 x) {
    return ROTR64(19,x) ^ ROTR64(61,x) ^ SHR64(6,x);
}

void sha512_parse(BLOCK64* mblocks, word64 block_count, word8* message) {
    int offset = 0;
    for (int i = 0; i < block_count; i++) {
        offset = (i*1024)/8; // <=> ((i-1)*1024)/8+128 (if i > 0)

        mblocks[i].w0    = ((word64)(message[offset+0])<<56) +((word64)(message[offset+1])<<48) +((word64)(message[offset+2])<<40) +((word64)(message[offset+3])<<32) +
                           ((word64)(message[offset+4])<<24) +((word64)(message[offset+5])<<16) +((word64)(message[offset+6])<<8)  +((word64)(message[offset+7]));
        mblocks[i].w1    = ((word64)(message[offset+8])<<56) +((word64)(message[offset+9])<<48) +((word64)(message[offset+10])<<40)+((word64)(message[offset+11])<<32) +
                           ((word64)(message[offset+12])<<24)+((word64)(message[offset+13])<<16)+((word64)(message[offset+14])<<8) +((word64)(message[offset+15]));
        offset += 16; // <=> (i*1024)/8 + 16

        mblocks[i].w2    = ((word64)(message[offset+0])<<56) +((word64)(message[offset+1])<<48) +((word64)(message[offset+2])<<40) +((word64)(message[offset+3])<<32) +
                           ((word64)(message[offset+4])<<24) +((word64)(message[offset+5])<<16) +((word64)(message[offset+6])<<8)  +((word64)(message[offset+7]));
        mblocks[i].w3    = ((word64)(message[offset+8])<<56) +((word64)(message[offset+9])<<48) +((word64)(message[offset+10])<<40)+((word64)(message[offset+11])<<32) +
                           ((word64)(message[offset+12])<<24)+((word64)(message[offset+13])<<16)+((word64)(message[offset+14])<<8) +((word64)(message[offset+15]));
        offset += 16; // <=> (i*1024)/8 + 32

        mblocks[i].w4    = ((word64)(message[offset+0])<<56) +((word64)(message[offset+1])<<48) +((word64)(message[offset+2])<<40) +((word64)(message[offset+3])<<32) +
                           ((word64)(message[offset+4])<<24) +((word64)(message[offset+5])<<16) +((word64)(message[offset+6])<<8)  +((word64)(message[offset+7]));
        mblocks[i].w5    = ((word64)(message[offset+8])<<56) +((word64)(message[offset+9])<<48) +((word64)(message[offset+10])<<40)+((word64)(message[offset+11])<<32) +
                           ((word64)(message[offset+12])<<24)+((word64)(message[offset+13])<<16)+((word64)(message[offset+14])<<8) +((word64)(message[offset+15]));
        offset += 16; // <=> (i*1024)/8 + 48

        mblocks[i].w6    = ((word64)(message[offset+0])<<56) +((word64)(message[offset+1])<<48) +((word64)(message[offset+2])<<40) +((word64)(message[offset+3])<<32) +
                           ((word64)(message[offset+4])<<24) +((word64)(message[offset+5])<<16) +((word64)(message[offset+6])<<8)  +((word64)(message[offset+7]));
        mblocks[i].w7    = ((word64)(message[offset+8])<<56) +((word64)(message[offset+9])<<48) +((word64)(message[offset+10])<<40)+((word64)(message[offset+11])<<32) +
                           ((word64)(message[offset+12])<<24)+((word64)(message[offset+13])<<16)+((word64)(message[offset+14])<<8) +((word64)(message[offset+15]));
        offset += 16; // <=> (i*1024)/8 + 64
        
        mblocks[i].w8    = ((word64)(message[offset+0])<<56) +((word64)(message[offset+1])<<48) +((word64)(message[offset+2])<<40) +((word64)(message[offset+3])<<32) +
                           ((word64)(message[offset+4])<<24) +((word64)(message[offset+5])<<16) +((word64)(message[offset+6])<<8)  +((word64)(message[offset+7]));
        mblocks[i].w9    = ((word64)(message[offset+8])<<56) +((word64)(message[offset+9])<<48) +((word64)(message[offset+10])<<40)+((word64)(message[offset+11])<<32) +
                           ((word64)(message[offset+12])<<24)+((word64)(message[offset+13])<<16)+((word64)(message[offset+14])<<8) +((word64)(message[offset+15]));
        offset += 16; // <=> (i*1024)/8 + 80

        mblocks[i].w10   = ((word64)(message[offset+0])<<56) +((word64)(message[offset+1])<<48) +((word64)(message[offset+2])<<40) +((word64)(message[offset+3])<<32) +
                           ((word64)(message[offset+4])<<24) +((word64)(message[offset+5])<<16) +((word64)(message[offset+6])<<8)  +((word64)(message[offset+7]));
        mblocks[i].w11   = ((word64)(message[offset+8])<<56) +((word64)(message[offset+9])<<48) +((word64)(message[offset+10])<<40)+((word64)(message[offset+11])<<32) +
                           ((word64)(message[offset+12])<<24)+((word64)(message[offset+13])<<16)+((word64)(message[offset+14])<<8) +((word64)(message[offset+15]));
        offset += 16; // <=> (i*1024)/8 + 96

        mblocks[i].w12   = ((word64)(message[offset+0])<<56) +((word64)(message[offset+1])<<48) +((word64)(message[offset+2])<<40) +((word64)(message[offset+3])<<32) +
                           ((word64)(message[offset+4])<<24) +((word64)(message[offset+5])<<16) +((word64)(message[offset+6])<<8)  +((word64)(message[offset+7]));
        mblocks[i].w13   = ((word64)(message[offset+8])<<56) +((word64)(message[offset+9])<<48) +((word64)(message[offset+10])<<40)+((word64)(message[offset+11])<<32) +
                           ((word64)(message[offset+12])<<24)+((word64)(message[offset+13])<<16)+((word64)(message[offset+14])<<8) +((word64)(message[offset+15]));
        offset += 16; // <=> (i*1024)/8 + 112

        mblocks[i].w14   = ((word64)(message[offset+0])<<56) +((word64)(message[offset+1])<<48) +((word64)(message[offset+2])<<40) +((word64)(message[offset+3])<<32) +
                           ((word64)(message[offset+4])<<24) +((word64)(message[offset+5])<<16) +((word64)(message[offset+6])<<8)  +((word64)(message[offset+7]));
        mblocks[i].w15   = ((word64)(message[offset+8])<<56) +((word64)(message[offset+9])<<48) +((word64)(message[offset+10])<<40)+((word64)(message[offset+11])<<32) +
                           ((word64)(message[offset+12])<<24)+((word64)(message[offset+13])<<16)+((word64)(message[offset+14])<<8) +((word64)(message[offset+15]));
    }
}

void sha512_digest(word64* H, BLOCK64* mblocks, int block_count /*, verbose vbtype */) {
    word64 a = 0;
    word64 b = 0;
    word64 c = 0;
    word64 d = 0;
    word64 e = 0;
    word64 f = 0;
    word64 g = 0;
    word64 h = 0;
    word64 tmp1 = 0;
    word64 tmp2 = 0;

    // hash values, at the end of the computation this array will be the final hash
    H[0] = SHA512_H0;
    H[1] = SHA512_H1;
    H[2] = SHA512_H2;
    H[3] = SHA512_H3;
    H[4] = SHA512_H4;
    H[5] = SHA512_H5;
    H[6] = SHA512_H6;
    H[7] = SHA512_H7;
    word64 W[80] = {0}; // message schedule values

    for (int m = 0; m < block_count; m++) {

        // preparing message schedule
        W[0]  = mblocks[m].w0;
        W[1]  = mblocks[m].w1;
        W[2]  = mblocks[m].w2;
        W[3]  = mblocks[m].w3;
        W[4]  = mblocks[m].w4;
        W[5]  = mblocks[m].w5;
        W[6]  = mblocks[m].w6;
        W[7]  = mblocks[m].w7;
        W[8]  = mblocks[m].w8;
        W[9]  = mblocks[m].w9;
        W[10] = mblocks[m].w10;
        W[11] = mblocks[m].w11;
        W[12] = mblocks[m].w12;
        W[13] = mblocks[m].w13;
        W[14] = mblocks[m].w14;
        W[15] = mblocks[m].w15;
        for (int t = 16; t < 80; t++) {
            W[t] = sha512_ssigma_1(W[t-2]) + W[t-7] + sha512_ssigma_0(W[t-15]) + W[t-16];
        }

        // init the working variables with the precedent hash values
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];

        // actual core hash process
        for (int t = 0; t < 80; t++) {
            tmp1 = h + sha512_bsigma_1(e) + ch64(e,f,g) + SHA512_K[t] + W[t];
            tmp2 = sha512_bsigma_0(a) + maj64(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + tmp1;
            d = c;
            c = b;
            b = a;
            a = tmp1 + tmp2;
        }

        // compute the m'th intermediate hash values
        H[0] = a + H[0];
        H[1] = b + H[1];
        H[2] = c + H[2];
        H[3] = d + H[3];
        H[4] = e + H[4];
        H[5] = f + H[5];
        H[6] = g + H[6];
        H[7] = h + H[7];
    }
}

// this is a temporary solution, some SERIOUS refactoring needs to be done
void sha384_digest(word64* H, BLOCK64* mblocks, int block_count /*, verbose vbtype */) {
    word64 a = 0;
    word64 b = 0;
    word64 c = 0;
    word64 d = 0;
    word64 e = 0;
    word64 f = 0;
    word64 g = 0;
    word64 h = 0;
    word64 tmp1 = 0;
    word64 tmp2 = 0;

    // hash values, at the end of the computation this array will be the final hash
    H[0] = SHA384_H0;
    H[1] = SHA384_H1;
    H[2] = SHA384_H2;
    H[3] = SHA384_H3;
    H[4] = SHA384_H4;
    H[5] = SHA384_H5;
    H[6] = SHA384_H6;
    H[7] = SHA384_H7;
    word64 W[80] = {0}; // message schedule values

    for (int m = 0; m < block_count; m++) {

        // preparing message schedule
        W[0]  = mblocks[m].w0;
        W[1]  = mblocks[m].w1;
        W[2]  = mblocks[m].w2;
        W[3]  = mblocks[m].w3;
        W[4]  = mblocks[m].w4;
        W[5]  = mblocks[m].w5;
        W[6]  = mblocks[m].w6;
        W[7]  = mblocks[m].w7;
        W[8]  = mblocks[m].w8;
        W[9]  = mblocks[m].w9;
        W[10] = mblocks[m].w10;
        W[11] = mblocks[m].w11;
        W[12] = mblocks[m].w12;
        W[13] = mblocks[m].w13;
        W[14] = mblocks[m].w14;
        W[15] = mblocks[m].w15;
        for (int t = 16; t < 80; t++) {
            W[t] = sha512_ssigma_1(W[t-2]) + W[t-7] + sha512_ssigma_0(W[t-15]) + W[t-16];
        }

        // init the working variables with the precedent hash values
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];

        // actual core hash process
        for (int t = 0; t < 80; t++) {
            tmp1 = h + sha512_bsigma_1(e) + ch64(e,f,g) + SHA512_K[t] + W[t];
            tmp2 = sha512_bsigma_0(a) + maj64(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + tmp1;
            d = c;
            c = b;
            b = a;
            a = tmp1 + tmp2;
        }

        // compute the m'th intermediate hash values
        H[0] = a + H[0];
        H[1] = b + H[1];
        H[2] = c + H[2];
        H[3] = d + H[3];
        H[4] = e + H[4];
        H[5] = f + H[5];
        H[6] = g + H[6];
        H[7] = h + H[7];
    }
    H[6] = 0x00; // truncate the output
    H[7] = 0x00; // truncate the output
}

