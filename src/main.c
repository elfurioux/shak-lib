#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/shacom.h"


#define MSGMAXLEN 1024
#define SEP "==============================\n"

#define USAGE "USAGE: '%s' <message> [options]"
#define USAGE_HELP "See \"'%s' --help\" for more infos."

#define ARGPARSE_MODE

typedef enum hash_type {
    default_hash = 0,
    all = 1,
    sha256 = 2,
    sha1 = -1,
    sha224 = -2,
    sha384 = -3,
    sha512 = -4,
    sha3_224 = -5,
    sha3_256 = -6,
    sha3_384 = -7,
    sha3_512 = -8,
    md4 = -9,
    md5 = -10
} hash_type;

typedef enum verbose {
    VERBOSE_NONE = 0,
    VERBOSE_NORMAL = 1,
    VERBOSE_MAX = 2
} verbose;

// displays help page
void display_help(const char* command_argv0);
int argparse(int argc, char *argv[], hash_type* htype, verbose* vblevel);

int main(int argc, char *argv[]) {
    hash_type htype = default_hash; // default hash algorithm is sha256
    verbose vblevel = VERBOSE_NONE; // default verbose level is 0

    if (argc == 1) {
        argv[1] = "\0";
    } else if (strcmp(argv[1], "-h")==0 || strcmp(argv[1], "--help")==0) {
        display_help(argv[0]);
        return EXIT_SUCCESS;
    } else /* if (argc > 2)*/ {
        // If the command has arguments
        int retval = argparse(argc,argv,&htype,&vblevel);
        if (retval != EXIT_SUCCESS) {return EXIT_FAILURE;}
    }

    if (strlen(argv[1]) > MSGMAXLEN) {
        fprintf(stderr, "ERROR: <message> IS OVER %d BYTES. NOT SUPPORTED AT THE MOMENT.", MSGMAXLEN);
        return EXIT_FAILURE;
    }
    if (htype < 0) {
        fprintf(stderr, "WARNING: This hash algorithm is not supported yet.\n" USAGE_HELP "\n", argv[0]);
    }

    return EXIT_SUCCESS;

    #ifndef ARGPARSE_MODE
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
#endif
}

void display_help(const char* command_argv0) {
    // printf("================================================================================\n");
    printf(USAGE "\n\n", command_argv0);
    printf("  --help            Shows this help page then exit.\n");
    printf("  -h                Equivalent of --help\n");
    printf("  --hash <hash>     Specifies the type of hash to use. (default sha256)\n");
    printf("         sha256     You can see the list of any valid <hash> value. The values\n");
    printf("     [!] sha1       preceded by a \"[!]\" are not implemented yet, they will be\n");
    printf("     [!] sha224     in the future but if you try to use them now it will throw a\n");
    printf("     [!] sha384     warning message and exit.\n");
    printf("     [!] sha512\n");
    printf("     [!] sha3-224\n");
    printf("     [!] sha3-256\n");
    printf("     [!] sha3-384\n");
    printf("     [!] sha3-512\n");
    printf("  -a                Hash the <message> with all hash algorithms available.\n");
    printf("  -v=[0-2]          Specifies the level of verbose. (default is 0)\n");
    printf("                    0 (VERBOSE_NONE): Just the hash hex digest, preceded by its\n");
    printf("                        algorithm name if many or if --hash is unspecified.\n");
    printf("                    1 (VERBOSE_NORMAL): Specifies the algorithm name before the\n");
    printf("                        digest.\n");
    printf("                    2 (VERBOSE_MAX): Goes into the detail of everything the pro-\n");
    printf("                        gram does, display every computation step, might be a\n");
    printf("                        bunch of informations.\n");
    printf("  --verbose=[0-2]   equivalent of -v");

    return;
}

int argparse(int argc, char *argv[], hash_type* htype, verbose* vblevel) {
    for (int o = 2; o < argc; o++) {
        // printf("option %d (argv[%d]): '%s'\n", o-2, o, argv[o]);

        if (strcmp(argv[o], "--hash")==0) {
            o++;
            if (o >= argc) {
                fprintf(stderr, "ERROR: --hash needs to be followed by a hash type.\n" USAGE_HELP "\n", argv[0]);
                return EXIT_FAILURE;
            }

            if (strcmp(argv[o], "sha256")==0) {
                *htype = sha256;
            } else if (strcmp(argv[o], "sha1")==0) {
                *htype = sha1;
            } else if (strcmp(argv[o], "sha224")==0) {
                *htype = sha224;
            } else if (strcmp(argv[o], "sha384")==0) {
                *htype = sha384;
            } else if (strcmp(argv[o], "sha512")==0) {
                *htype = sha512;
            } else if (strcmp(argv[o], "sha3_224")==0) {
                *htype = sha3_224;
            } else if (strcmp(argv[o], "sha3_256")==0) {
                *htype = sha3_256;
            } else if (strcmp(argv[o], "sha3_384")==0) {
                *htype = sha3_384;
            } else if (strcmp(argv[o], "sha3_512")==0) {
                *htype = sha3_512;
            } else if (strcmp(argv[o], "md4")==0) {
                *htype = md4;
            } else if (strcmp(argv[o], "md5")==0) {
                *htype = md5;
            }
            else {
                fprintf(stderr, "ERROR: hash type \"%s\" not recognised.\n" USAGE_HELP "\n", argv[o], argv[0]);
                return EXIT_FAILURE;
            }
        } else if (strcmp(argv[o], "-a")==0) {
            *htype = all;
        } else if (strncmp(argv[o], "-v=", 3)==0 || strncmp(argv[o], "--verbose=", 10)==0) {
            char chr = '\0';
            if (strlen(argv[o])==4) {
                chr = argv[o][3];
            } else if (strlen(argv[o])==11) {
                chr = argv[o][10];
            } else {
                fprintf(stderr, "ERROR: argument \"%s\" is invalid.\n" USAGE_HELP "\n", argv[o], argv[0]);
                return EXIT_FAILURE;
            }

            chr -= 48; // 48 is the decimal place of the 0 in the ASCII table
            if (chr < 0 || chr > 2) {
                fprintf(stderr, "ERROR: argument \"%s\" is invalid.\n" USAGE_HELP "\n", argv[o], argv[0]);
                return EXIT_FAILURE;
            }
            *vblevel = chr;
        } else {
            fprintf(stderr, "ERROR: unrecognised argument \"%s\"\n" USAGE_HELP "\n", argv[o], argv[0]);
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
