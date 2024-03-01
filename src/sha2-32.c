#include <stdio.h>
#include <stdlib.h>

#include "shacom.h"
#include "sha2-32.h"


#define SHA256_CONST_LEN 64

#define SHA256_H0 0x6a09e667
#define SHA256_H1 0xbb67ae85
#define SHA256_H2 0x3c6ef372
#define SHA256_H3 0xa54ff53a
#define SHA256_H4 0x510e527f
#define SHA256_H5 0x9b05688c
#define SHA256_H6 0x1f83d9ab
#define SHA256_H7 0x5be0cd19

#define SHA224_H0 0xc1059ed8
#define SHA224_H1 0x367cd507
#define SHA224_H2 0x3070dd17
#define SHA224_H3 0xf70e5939
#define SHA224_H4 0xffc00b31
#define SHA224_H5 0x68581511
#define SHA224_H6 0x64f98fa7
#define SHA224_H7 0xbefa4fa4


const word32 SHA256_K[SHA256_CONST_LEN] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


word32 sha256_bsigma_0(word32 x) {
    return ROTR(2,x) ^ ROTR(13,x) ^ ROTR(22,x);
}

word32 sha256_bsigma_1(word32 x) {
    return ROTR(6,x) ^ ROTR(11,x) ^ ROTR(25,x);
}

word32 sha256_ssigma_0(word32 x) {
    return ROTR(7,x) ^ ROTR(18,x) ^ SHR(3,x);
}

word32 sha256_ssigma_1(word32 x) {
    return ROTR(17,x) ^ ROTR(19,x) ^ SHR(10,x);
}

void sha256_parse(BLOCK32* mblocks, word64 block_count, word8* message) {
    int offset = 0;
    for (int i = 0; i < block_count; i++) {
        offset = (i*512)/8;

        mblocks[i].w0    = (word32)(message[offset+0]<<24)  + (word32)(message[offset+1]<<16)  + (word32)(message[offset+2]<<8)  +(word32)(message[offset+3]);
        mblocks[i].w1    = (word32)(message[offset+4]<<24)  + (word32)(message[offset+5]<<16)  + (word32)(message[offset+6]<<8)  +(word32)(message[offset+7]);
        mblocks[i].w2    = (word32)(message[offset+8]<<24)  + (word32)(message[offset+9]<<16)  + (word32)(message[offset+10]<<8) +(word32)(message[offset+11]);
        mblocks[i].w3    = (word32)(message[offset+12]<<24) + (word32)(message[offset+13]<<16) + (word32)(message[offset+14]<<8) +(word32)(message[offset+15]);
        offset += 16;
        mblocks[i].w4    = (word32)(message[offset+0]<<24)  + (word32)(message[offset+1]<<16)  + (word32)(message[offset+2]<<8)  +(word32)(message[offset+3]);
        mblocks[i].w5    = (word32)(message[offset+4]<<24)  + (word32)(message[offset+5]<<16)  + (word32)(message[offset+6]<<8)  +(word32)(message[offset+7]);
        mblocks[i].w6    = (word32)(message[offset+8]<<24)  + (word32)(message[offset+9]<<16)  + (word32)(message[offset+10]<<8) +(word32)(message[offset+11]);
        mblocks[i].w7    = (word32)(message[offset+12]<<24) + (word32)(message[offset+13]<<16) + (word32)(message[offset+14]<<8) +(word32)(message[offset+15]);
        offset += 16;
        mblocks[i].w8    = (word32)(message[offset+0]<<24)  + (word32)(message[offset+1]<<16)  + (word32)(message[offset+2]<<8)  +(word32)(message[offset+3]);
        mblocks[i].w9    = (word32)(message[offset+4]<<24)  + (word32)(message[offset+5]<<16)  + (word32)(message[offset+6]<<8)  +(word32)(message[offset+7]);
        mblocks[i].w10   = (word32)(message[offset+8]<<24)  + (word32)(message[offset+9]<<16)  + (word32)(message[offset+10]<<8) +(word32)(message[offset+11]);
        mblocks[i].w11   = (word32)(message[offset+12]<<24) + (word32)(message[offset+13]<<16) + (word32)(message[offset+14]<<8) +(word32)(message[offset+15]);
        offset += 16;
        mblocks[i].w12   = (word32)(message[offset+0]<<24)  + (word32)(message[offset+1]<<16)  + (word32)(message[offset+2]<<8)  +(word32)(message[offset+3]);
        mblocks[i].w13   = (word32)(message[offset+4]<<24)  + (word32)(message[offset+5]<<16)  + (word32)(message[offset+6]<<8)  +(word32)(message[offset+7]);
        mblocks[i].w14   = (word32)(message[offset+8]<<24)  + (word32)(message[offset+9]<<16)  + (word32)(message[offset+10]<<8) +(word32)(message[offset+11]);
        mblocks[i].w15   = (word32)(message[offset+12]<<24) + (word32)(message[offset+13]<<16) + (word32)(message[offset+14]<<8) +(word32)(message[offset+15]);
    }
}

void sha256_digest(word32* H, BLOCK32* mblocks, int block_count, verbose vbtype) {
    word32 a = 0;
    word32 b = 0;
    word32 c = 0;
    word32 d = 0;
    word32 e = 0;
    word32 f = 0;
    word32 g = 0;
    word32 h = 0;
    word32 tmp1 = 0;
    word32 tmp2 = 0;

    // hash values, at the end of the computation this array will be the final hash
    H[0] = SHA256_H0;
    H[1] = SHA256_H1;
    H[2] = SHA256_H2;
    H[3] = SHA256_H3;
    H[4] = SHA256_H4;
    H[5] = SHA256_H5;
    H[6] = SHA256_H6;
    H[7] = SHA256_H7;
    word32 W[64]; // message schedule values

    for (int m = 0; m < block_count; m++) { // executed for each message block
        if (vbtype==VERBOSE_MAX) {printf("%6s   %-5s    %-5s    %-5s    %-5s    %-5s    %-5s    %-5s    %-5s\n","","A","B","C","D","E","F","G","H");}

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
        for (int t = 16; t < 64; t++) {
            W[t] = sha256_ssigma_1(W[t-2]) + W[t-7] + sha256_ssigma_0(W[t-15]) + W[t-16];
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
        for (int t = 0; t < 64; t++) {
            tmp1 = h + sha256_bsigma_1(e) + ch(e,f,g) + SHA256_K[t] + W[t];
            tmp2 = sha256_bsigma_0(a) + maj(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + tmp1;
            d = c;
            c = b;
            b = a;
            a = tmp1 + tmp2;
            if (vbtype==VERBOSE_MAX) {printf("t=%2u: %.8X %.8X %.8X %.8X %.8X %.8X %.8X %.8X\n", t, a, b, c, d, e, f, g, h);}
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

        if (vbtype==VERBOSE_MAX) {printf(SEP);}
    }
}

void sha224_digest(word32* H, BLOCK32* mblocks, int block_count, verbose vbtype) {
    word32 a = 0;
    word32 b = 0;
    word32 c = 0;
    word32 d = 0;
    word32 e = 0;
    word32 f = 0;
    word32 g = 0;
    word32 h = 0;
    word32 tmp1 = 0;
    word32 tmp2 = 0;

    // hash values, at the end of the computation this array will be the final hash
    H[0] = SHA224_H0;
    H[1] = SHA224_H1;
    H[2] = SHA224_H2;
    H[3] = SHA224_H3;
    H[4] = SHA224_H4;
    H[5] = SHA224_H5;
    H[6] = SHA224_H6;
    H[7] = SHA224_H7;
    word32 W[64]; // message schedule values

    for (int m = 0; m < block_count; m++) { // executed for each message block
        if (vbtype==VERBOSE_MAX) {printf("%6s   %-5s    %-5s    %-5s    %-5s    %-5s    %-5s    %-5s    %-5s\n","","A","B","C","D","E","F","G","H");}

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
        for (int t = 16; t < 64; t++) {
            W[t] = sha256_ssigma_1(W[t-2]) + W[t-7] + sha256_ssigma_0(W[t-15]) + W[t-16];
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
        for (int t = 0; t < 64; t++) {
            tmp1 = h + sha256_bsigma_1(e) + ch(e,f,g) + SHA256_K[t] + W[t];
            tmp2 = sha256_bsigma_0(a) + maj(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + tmp1;
            d = c;
            c = b;
            b = a;
            a = tmp1 + tmp2;
            if (vbtype==VERBOSE_MAX) {printf("t=%2u: %.8X %.8X %.8X %.8X %.8X %.8X %.8X %.8X\n", t, a, b, c, d, e, f, g, h);}
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

        if (vbtype==VERBOSE_MAX) {printf(SEP);}
    }
    H[7] = 0x00; // truncate the output
}
