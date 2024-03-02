#include "shacom.h"

uint16 get_zbitcount(word64 msglen, const int BLOCKSIZE) {
    uint16 lblen = (msglen+1) % BLOCKSIZE; // last block lenght
    uint16 zbitcount = -1;

    if (lblen <= BLOCKSIZE*.875) {
        zbitcount = BLOCKSIZE*.875 - lblen;
    } else {
        zbitcount = (BLOCKSIZE+BLOCKSIZE*.875) - lblen; // 960 - lblen; for BLOCKSIZE = 512
    }

    return zbitcount;
}

word64 get_block_count(word64 msglen, const int BLOCKSIZE) {
    // lenghts are in bits

    word64 block_count = (msglen+1 + get_zbitcount(msglen, BLOCKSIZE) + BLOCKSIZE*.125)/BLOCKSIZE;

    return block_count;
}

word32 SHR(uint8 n, word32 x) {
    n = n%32;
    return x>>n;
}
word64 SHR64(uint8 n, word64 x) {
    n = n%64;
    return x>>n;
}

word32 ROTL(uint8 n, word32 x) {
    n = n%32;
    return (x<<n) | (x>>(32-n));
}
word64 ROTL64(uint8 n, word64 x) {
    n = n%64;
    return (x<<n) | (x>>(64-n));
}

word32 ROTR(uint8 n, word32 x) {
    n = n%32;
    return (x>>n) | (x<<(32-n));
}
word64 ROTR64(uint8 n, word64 x) {
    n = n%64;
    return (x>>n) | (x<<(64-n));
}

word32 ch(word32 x, word32 y, word32 z) {
    return (x&y) ^ (~x&z);
}
word64 ch64(word64 x, word64 y, word64 z) {
    return (x&y) ^ (~x&z);
}

word32 maj(word32 x, word32 y, word32 z) {
    return (x&y) ^ (x&z) ^ (y&z);
}
word64 maj64(word64 x, word64 y, word64 z) {
    return (x&y) ^ (x&z) ^ (y&z);
}

word32 parity(word32 x, word32 y, word32 z) {
    return x ^ y ^ z;
}
