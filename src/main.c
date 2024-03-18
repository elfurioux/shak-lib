#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shacom.h"
#include "sha2-32.h"
#include "sha2-64.h"
#include "sha1.h"


#define USAGE "USAGE: shak <message> [options]"
#define USAGE_HELP "See \"shak --help\" for more infos."

#define ARG_HELP_SHORT      "-h"
#define ARG_HELP_LONG       "--help"
#define ARG_VERSION         "--version"
#define ARG_HASH            "--hash"
#define ARG_ALL             "-a"
#define ARG_VERBOSE_SHORT   "-v="
#define ARG_VERBOSE_LONG    "--verbose="

#define ARG_HELP_DESC       "Shows this help page then exit."
#define ARG_VERSION_DESC    "Shows the version and copyright and exit."
#define ARG_HASH_DESC_L1    "Specifies the type of hash to use. (default sha256). The"
#define ARG_HASH_DESC_L2    "valid <hash> values are sha1, sha224, sha256, sha384 and"
#define ARG_HASH_DESC_L3    "sha512."
#define ARG_ALL_DESC        "Hash the <message> with all hash algorithms available."
#define ARG_VERBOSE_DESC_L1 "Specifies the level of verbose. (default is 0)"
#define ARG_VERBOSE_DESC_L2 "0 (VERBOSE_NONE): Just the hash hex digest, preceded by its"
#define ARG_VERBOSE_DESC_L3 "    algorithm name if many or if --hash is unspecified."
#define ARG_VERBOSE_DESC_L4 "1 (VERBOSE_NORMAL): Specifies the algorithm name before the"
#define ARG_VERBOSE_DESC_L5 "    digest."
#define ARG_VERBOSE_DESC_L6 "2 (VERBOSE_MAX): Goes into the detail of everything the pro-"
#define ARG_VERBOSE_DESC_L7 "    gram does, display every computation step, might be a"
#define ARG_VERBOSE_DESC_L8 "    bunch of informations."

// crash(`const char *__format`, `...`) : Syntax of arguments is like `printf()`
// prints critical error to `stderr` and then exit the program
#define crash(...) fprintf(stderr,__VA_ARGS__); exit(EXIT_FAILURE)


typedef enum hash_type {
    //               Implementation Flag, 1 if not Implemented
    //               |Blocksize flag, 0 if blocksize is 512, 1 if blocksize is 1024
    //               ||
    //               ∨∨
    default_hash = 0b00000000,
    all          = 0b00000001,
    sha256       = 0b00000010,
    sha1         = 0b00000011,
    sha224       = 0b00000100,
    sha384       = 0b01000101,
    sha512       = 0b01000110,
    // sha3_224     = 0b10000111,
    // sha3_256     = 0b10001000,
    // sha3_384     = 0b11001001,
    // sha3_512     = 0b11001010
    // md4          = 0b10001011,
    // md5          = 0b10001100
} hash_type;


// displays help page
void display_help(void);
void display_version(void);
int argparse(int argc, char *argv[], hash_type* htype, verbose* vblevel);
char* get_algorithm(hash_type hash);
void display_hash(word32* H, hash_type htype, verbose vblevel);
void display_hash64(word64* H, hash_type htype, verbose vblevel);


int main(int argc, char *argv[]) {
    /* ARGUMENT PARSING */

    hash_type htype = default_hash; // default hash algorithm is sha256
    verbose vblevel = VERBOSE_NONE_DEFAULT; // default verbose level is equivalent to VERBOSE_NONE

    if (argc == 1) { // if there is no arguments, consider <message> as blank
        argv[1] = "\0";
    } else if (strcmp(argv[1], "-h")==0 || strcmp(argv[1], "--help")==0) {
        display_help();
        return EXIT_SUCCESS;
    } else if (strcmp(argv[1], "--version")==0) {
        display_version();
        return EXIT_SUCCESS;
    } else /* if (argc > 2)*/ { // If the command has arguments
        int retval = argparse(argc,argv,&htype,&vblevel);
        if (retval != EXIT_SUCCESS) {return EXIT_FAILURE;}
    }

    if (strcmp(argv[1], " ")==0) { // if the <message> argument is a space, consider it as a blank string
        argv[1] = "\0";
    }

    if ((htype & 0b10000000) == 0b10000000) { // test for the implementation flag.
        crash("WARNING: This hash algorithm is not supported yet. (\"%s\")\n" USAGE_HELP "\n", get_algorithm(htype));
    }


    /* MESSAGE PADDING */

    uint16 blocksize = 512;
    if ((htype & 0b01000000) == 0b01000000) { // test for the block size flag.
        blocksize = 1024;
    }

    word64 msglen = strlen(argv[1])*8;
    word64 block_count = get_block_count(msglen,blocksize);
    uint16 zbitcount = get_zbitcount(msglen,blocksize);

    if (vblevel == VERBOSE_MAX) {
        printf("l=%lld=(%lld*%d+%lld) k=%d\n",msglen,msglen/blocksize,blocksize,msglen%blocksize,zbitcount);
        printf("l+1+k = %lld = %lldmod%d\n",(msglen+1+zbitcount),(msglen+1+zbitcount)%blocksize,blocksize);
        printf("block_count=%lld\n",block_count);
        printf(SEP);
    }

    // puts the characters in the word8 message array
    word8 message[4096] = {0};
    int i;
    for (i = 0; zbitcount > 0; i++) {
        if (i < msglen/8) {
            message[i] = argv[1][i];
        } else if (i == msglen/8) {
            zbitcount -= 7;
            message[i] = 0b10000000;
        } else {
            zbitcount -= 8;
            message[i] = 0b00000000;
        }
    }

    // appends the message lenght to the end of the message blocks
    int j = i; // offset
    if (blocksize == 1024) {j += 8;}
    for (i = 0; i < 8; i++) {
        message[j+i] = (word8)(msglen>>56);
        msglen = msglen<<8;
    }

    /* ACTUAL HASH COMPUTATION */

    if (blocksize == 512 || htype == all) {
        block_count = get_block_count(msglen,512);
        
        BLOCK32 mblocks[block_count];
        sha256_parse(mblocks, block_count, message);
        word32 H[8];

        if (htype == sha1 || htype == all) {
            sha1_digest(H, mblocks, block_count, vblevel);
            display_hash(H, sha1, vblevel);
        }
        if (htype == sha224 || htype == all) {
            sha224_digest(H, mblocks, block_count, vblevel);
            display_hash(H, sha224, vblevel);
        }
        if (htype == sha256 || htype == default_hash || htype == all) {
            sha256_digest(H, mblocks, block_count, vblevel);
            if (htype == all) {
                display_hash(H, sha256, vblevel);
            } else {
                display_hash(H, htype, vblevel);
            }
        }
    }
    if (blocksize == 1024 || htype == all) {
        block_count = get_block_count(msglen,1024);

        BLOCK64 mblocks64[block_count];
        sha512_parse(mblocks64, block_count, message);
        word64 H[8];

        if (htype == sha384 || htype == all) {
            sha384_digest(H, mblocks64, block_count);
            display_hash64(H, sha384, vblevel);
        }
        if (htype == sha512 || htype == all) {
            sha512_digest(H, mblocks64, block_count);
            display_hash64(H, sha512, vblevel);
        }
    }

    return EXIT_SUCCESS;
}


void display_hash(word32* H, hash_type htype, verbose vblevel) {
    if (vblevel > VERBOSE_NONE || (htype == default_hash && vblevel == VERBOSE_NONE_DEFAULT)) {
        if (htype == default_hash) {htype = sha256;}
        printf("%s: 0x", get_algorithm(htype));
    }

    switch (htype) {
        case sha256:
            printf("%.8x%.8x%.8x%.8x%.8x%.8x%.8x%.8x",H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]);
            break;
        case sha224:
            printf("%.8x%.8x%.8x%.8x%.8x%.8x%.8x",H[0],H[1],H[2],H[3],H[4],H[5],H[6]);
            break;
        case sha1:
            printf("%.8x%.8x%.8x%.8x%.8x",H[0],H[1],H[2],H[3],H[4]);
            break;
        default: break;
    }

    printf("\n");
}

void display_hash64(word64* H, hash_type htype, verbose vblevel) {
    if (vblevel > VERBOSE_NONE) {
        printf("%s: 0x", get_algorithm(htype));
    }

    switch (htype) {
        case sha512:
            printf("%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx",H[0],H[1],H[2],H[3],H[4],H[5],H[6],H[7]);
            break;
        case sha384:
            printf("%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx",H[0],H[1],H[2],H[3],H[4],H[5]);
            break;
        default: break;
    }

    printf("\n");
}

char* get_algorithm(hash_type hash) {
    char* hashname;
    switch (hash) {
        case sha256:
            hashname = "sha256";
            break;
        case sha1:
            hashname = "sha1";
            break;
        case sha224:
            hashname = "sha224";
            break;
        case sha384:
            hashname = "sha384";
            break;
        case sha512:
            hashname = "sha512";
            break;
        default:
            hashname = "???\0";
            break;
    }
    return hashname;
}

void display_version(void) {
    printf("shak version %s",SHAKVERSION);
    #ifdef SHAK_RELEASE
    printf("\n");
    printf("Copyright (c) 2024 elfurioux\nMIT License, built with\n%s\n\n",GCCVERSION);
    printf("THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n");
    printf("IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n");
    printf("FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.\n");
    #else
    printf("-test\n");
    printf("WARNING: THIS IS A TEST BUILD.\nTHINGS MIGHT GET FUNKY SOMETIMES.\n(more than usual at least)\n");
    #endif
}

void display_help(void) {
    printf(USAGE "\n\n");
    printf("%5s%-20s%-60s\n", ARG_HELP_SHORT, ", " ARG_HELP_LONG, ARG_HELP_DESC);
    printf("%5s%-20s%-60s\n", "", "  " ARG_VERSION, ARG_VERSION_DESC);
    printf("%5s%-20s%-60s\n", "", "  " ARG_HASH " <hash>", ARG_HASH_DESC_L1);
    printf("%5s%-20s%-60s\n", "", "", ARG_HASH_DESC_L2);
    printf("%5s%-20s%-60s\n", "", "", ARG_HASH_DESC_L3);
    printf("%5s%-20s%-60s\n", ARG_ALL, "", ARG_ALL_DESC);
    printf("%5s%-20s%-60s\n", ARG_VERBOSE_SHORT, ", " ARG_VERBOSE_LONG "[0-2]", ARG_VERBOSE_DESC_L1);
    printf("%5s%-20s%-60s\n", "", "", ARG_VERBOSE_DESC_L2);
    printf("%5s%-20s%-60s\n", "", "", ARG_VERBOSE_DESC_L3);
    printf("%5s%-20s%-60s\n", "", "", ARG_VERBOSE_DESC_L4);
    printf("%5s%-20s%-60s\n", "", "", ARG_VERBOSE_DESC_L5);
    printf("%5s%-20s%-60s\n", "", "", ARG_VERBOSE_DESC_L6);
    printf("%5s%-20s%-60s\n", "", "", ARG_VERBOSE_DESC_L7);
    printf("%5s%-20s%-60s\n", "", "", ARG_VERBOSE_DESC_L8);
}

int argparse(int argc, char *argv[], hash_type* htype, verbose* vblevel) {
    int vbdef = 0;
    for (int o = 2; o < argc; o++) {
        // printf("option %d (argv[%d]): '%s'\n", o-2, o, argv[o]);

        if (strcmp(argv[o], "--hash")==0) {
            o++;
            if (o >= argc) {
                crash("ERROR: --hash needs to be followed by a hash type.\n" USAGE_HELP "\n");
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
            } else {
                crash("ERROR: hash type \"%s\" not recognised.\n" USAGE_HELP "\n", argv[o]);
            }
        } else if (strcmp(argv[o], "-a")==0) {
            *htype = all;
            *vblevel = VERBOSE_NORMAL;
            vbdef = 1;
        } else if (strncmp(argv[o], "-v=", 3)==0 || strncmp(argv[o], "--verbose=", 10)==0) {
            if (vbdef) {
                crash("ERROR: argument \"%s\" is invalid in this context.\n" USAGE_HELP "\n", argv[o]);
            }
            char chr = '\0';
            if (strlen(argv[o])==4) {
                chr = argv[o][3];
            } else if (strlen(argv[o])==11) {
                chr = argv[o][10];
            } else {
                crash("ERROR: argument \"%s\" is invalid.\n" USAGE_HELP "\n", argv[o]);
            }

            chr -= 48; // 48 is the decimal place of the 0 in the ASCII table
            if (chr < 0 || chr > 2) {
                crash("ERROR: argument \"%s\" is invalid.\n" USAGE_HELP "\n", argv[o]);
            }
            *vblevel = chr;
        } else {
            crash("ERROR: unrecognised argument \"%s\"\n" USAGE_HELP "\n", argv[o]);
        }
    }

    return EXIT_SUCCESS;
}
