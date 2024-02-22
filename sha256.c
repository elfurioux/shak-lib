#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MSGMAXLEN 1024
#define SHA256_CONST_LEN 64

typedef unsigned long long word64;
typedef unsigned int word32;
typedef unsigned char uint8;
typedef unsigned char word8;
typedef struct BLOCK {
    word32 w0;  word32 w1;  word32 w2;  word32 w3;
    word32 w4;  word32 w5;  word32 w6;  word32 w7;
    word32 w8;  word32 w9;  word32 w10; word32 w11;
    word32 w12; word32 w13; word32 w14; word32 w15;
}BLOCK;


const word32 SHA256_CONST[SHA256_CONST_LEN] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


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


    /* ==================================== MESSAGE PADDING ==================================== */

    // lenghts are in bits
    int msglen = strlen(argv[1])*8;
    int lblen = (msglen+1)%512; // last block lenght
    int zbitcount = -1;
    if (lblen <=448) {
        zbitcount = 448 - lblen;
    } else {
        zbitcount = (512+448) - lblen; // 960 - lblen
    }
    int block_count = (msglen+1 + zbitcount + 64)/512;

    printf("l=%d=(%d*512+%d) k=%d\n",msglen,msglen/512,msglen%512,zbitcount);
    printf("l+1+k = %d = %dmod512\n",(msglen+1+zbitcount),(msglen+1+zbitcount)%512);
    printf("block_count=%d\n",block_count);
    printf("================-================-================-================-================-================-================-================\n");

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
    word64 msglen_o = msglen/8;
    for (i = 0; i < 8; i++) {
        message[j+i] = (word8)(msglen_o>>56);
        msglen_o = msglen_o<<8;
    }

    // Prints the unparsed message blocks
    for (int i = 0; i < block_count*64 ; i++) {
        printf("%.2X",message[i]);
        if (i%64 == 63) {
            printf("\n");
        } else if (i%8==7) {
            printf(" ");
        }
    }
    printf("================-================-================-================-================-================-================-================\n");


    /* =================================== PARSE THE MESSAGE =================================== */

    BLOCK mblocks[block_count];
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

    // prints the message blocks, parsed this time
    for (int i = 0; i < block_count; i++) {
        printf("%.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X\n",
            mblocks[i].w0,mblocks[i].w1,mblocks[i].w2,mblocks[i].w3,
            mblocks[i].w4,mblocks[i].w5,mblocks[i].w6,mblocks[i].w7,
            mblocks[i].w8,mblocks[i].w9,mblocks[i].w10,mblocks[i].w11,
            mblocks[i].w12,mblocks[i].w13,mblocks[i].w14,mblocks[i].w15
        );
    }
    printf("================-================-================-================-================-================-================-================\n");
    printf("done!");

    return EXIT_SUCCESS;
}
