#ifndef __SHA1_H__
#define __SHA1_H__

#include "shacom.h"


word32 sha1_f(uint8 t, word32 x, word32 y, word32 z);

void sha1_digest(word32* H, BLOCK32* mblocks, int block_count, verbose vbtype);

#endif
