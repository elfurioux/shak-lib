#include "../include/shacom.h"

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
word64 ROTR64(uint8 n, word64 x) {
    n = n%64;
    return (x<<n) | (x>>(64-n));
}

word32 ROTR(uint8 n, word32 x) {
    n = n%32;
    return (x>>n) | (x<<(32-n));
}
word64 ROTL64(uint8 n, word64 x) {
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
