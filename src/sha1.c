#include <stdio.h>
#include <stdlib.h>

#include "shacom.h"
#include "shaconstants.h"
#include "sha1.h"


#define SHA1_CONST_LEN 4


const word32 SHA1_K[SHA1_CONST_LEN] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};


word32 sha1_f(uint8 t, word32 x, word32 y, word32 z) {
    if (t >= 0 && t < 20) {
        return ch(x,y,z);
    } else if (t >= 20 && t < 40) {
        return parity(x,y,z);
    } else if (t >= 40 && t < 60) {
        return maj(x,y,z);
    } else if (t >= 60 && t < 80) {
        return parity(x,y,z);
    }

    return -1;
}

void sha1_setconstants(word32* H) {
    // hash values, at the end of the computation this array will be the final hash
    H[0] = SHA1_H0;
    H[1] = SHA1_H1;
    H[2] = SHA1_H2;
    H[3] = SHA1_H3;
    H[4] = SHA1_H4;
    H[5] = 0x00; // not used here
    H[6] = 0x00; // not used here
    H[7] = 0x00; // not used here
}

void sha1_digest(word32* H, BLOCK32* mblocks, int block_count, verbose vbtype) {
    word32 a = 0;
    word32 b = 0;
    word32 c = 0;
    word32 d = 0;
    word32 e = 0;
    word32 tmp = 0;

    word32 W[80]; // message schedule values

    for (int m = 0; m < block_count; m++) { // executed for each message block
        if (vbtype==VERBOSE_MAX) {printf("%6s   %-5s    %-5s    %-5s    %-5s    %-5s\n","","A","B","C","D","E");}

        // prepare the message schedule
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
            W[t] = ROTL(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
        }

        // init the working variables with the precedent hash values
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];

        // actual core hash process
        for (int t = 0; t < 80; t++) {
            tmp = ROTL(5, a) + sha1_f(t, b, c, d) + e + SHA1_K[t/20] + W[t];
            e = d;
            d = c;
            c = ROTL(30, b);
            b = a;
            a = tmp;
            if (vbtype==VERBOSE_MAX) {printf("t=%2u: %.8X %.8X %.8X %.8X %.8X\n", t, a, b, c, d, e);}
        }

        // compute the m'th intermediate hash values
        H[0] = a + H[0];
        H[1] = b + H[1];
        H[2] = c + H[2];
        H[3] = d + H[3];
        H[4] = e + H[4];

        if (vbtype==VERBOSE_MAX) {printf(SEP);}
    }
}
