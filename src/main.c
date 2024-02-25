#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/shacom.h"


#define MSGMAXLEN 1024
#define SEP "==============================\n"


int main(int argc, char *argv[]) {
    if (argc > 2) {
        fprintf(stderr, "USAGE: %s <message>", argv[0]);
        return EXIT_FAILURE;
    } else if (argc == 1) {
        argv[1] = "\0";
    }

    if (strlen(argv[1]) > MSGMAXLEN) {
        fprintf(stderr, "ERROR: <message> IS OVER %d BYTES. NOT SUPPORTED AT THE MOMENT.", MSGMAXLEN);
        return EXIT_FAILURE;
    }


    /* MESSAGE PADDING */

    word64 msglen = strlen(argv[1])*8;
    word64 block_count = get_block_count(msglen,512);
    uint16 zbitcount = get_zbitcount(msglen,512);

    // TODO: Verbose mode
    /*
    printf("l=%d=(%d*512+%d) k=%d\n",msglen,msglen/512,msglen%512,zbitcount);
    printf("l+1+k = %d = %dmod512\n",(msglen+1+zbitcount),(msglen+1+zbitcount)%512);
    printf("block_count=%d\n",block_count);
    printf(SEP);
    */

    // puts the characters in the word8 message array
    word8 message[MSGMAXLEN];
    int i = 0;
    while (zbitcount > 0) {
        if (i < msglen/8) {
            message[i] = argv[1][i];
        } else if (i == msglen/8) {
            zbitcount -= 7;
            message[i] = 0b10000000;
        } else {
            zbitcount -= 8;
            message[i] = 0b00000000;
        }
        i++;
    }
    // appends the message lenght to the end of the message blocks
    int j = i; // offset
    for (i = 0; i < 8; i++) {
        message[j+i] = (word8)(msglen>>56);
        msglen = msglen<<8;
    }


    /* PARSING THE MESSAGE */

    BLOCK32 mblocks[block_count];
    sha256_parse(mblocks, block_count, message);

    /*
    // prints the message blocks, parsed this time
    for (int i = 0; i < block_count; i++) {
        printf("%.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X\n",
            mblocks[i].w0,mblocks[i].w1,mblocks[i].w2,mblocks[i].w3,
            mblocks[i].w4,mblocks[i].w5,mblocks[i].w6,mblocks[i].w7,
            mblocks[i].w8,mblocks[i].w9,mblocks[i].w10,mblocks[i].w11,
            mblocks[i].w12,mblocks[i].w13,mblocks[i].w14,mblocks[i].w15
        );
    }
    printf(SEP);
    */

    /* ACTUAL HASH COMPUTATION */

    word32 H[8];
    sha256_digest(H, mblocks, block_count);

    // printf("%.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x\n",H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]);
    printf("sha256: 0x%.8x%.8x%.8x%.8x%.8x%.8x%.8x%.8x\n",H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]);

    return EXIT_SUCCESS;
}
