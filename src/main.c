#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shacom.h"
#include "sha2-32.h"
#include "sha1.h"


#define MSGMAXLEN 1024

#define USAGE "USAGE: '%s' <message> [options]"
#define USAGE_HELP "See \"'%s' --help\" for more infos."


typedef enum hash_type {
    //               Implementation Flag, 1 if not Implemented
    //               ∨
    default_hash = 0b00000000,
    all          = 0b00000001,
    sha256       = 0b00000010,
    sha1         = 0b00000011,
    sha224       = 0b00000100,
    sha384       = 0b10000101,
    sha512       = 0b10000110,
    sha3_224     = 0b10000111,
    sha3_256     = 0b10001000,
    sha3_384     = 0b10001001,
    sha3_512     = 0b10001010,
    md4          = 0b10001011,
    md5          = 0b10001100
} hash_type;


// displays help page
void display_help(const char* command_argv0);
int argparse(int argc, char *argv[], hash_type* htype, verbose* vblevel);
char* get_algorithm(hash_type hash);
void display_hash(word32* H, hash_type htype, verbose vblevel);


int main(int argc, char *argv[]) {
    /* ARGUMENT PARSING */

    hash_type htype = default_hash; // default hash algorithm is sha256
    verbose vblevel = VERBOSE_NONE_DEFAULT; // default verbose level is equivalent to VERBOSE_NONE

    if (argc == 1) { // if there is no arguments, consider <message> as blank
        argv[1] = "\0";
    } else if (strcmp(argv[1], "-h")==0 || strcmp(argv[1], "--help")==0) {
        display_help(argv[0]);
        return EXIT_SUCCESS;
    } else /* if (argc > 2)*/ { // If the command has arguments
        int retval = argparse(argc,argv,&htype,&vblevel);
        if (retval != EXIT_SUCCESS) {return EXIT_FAILURE;}
    }

    if (strcmp(argv[1], " ")==0) { // if the <message> argument is a space, consider it as a blank string
        argv[1] = "\0";
    }

    if (strlen(argv[1]) > MSGMAXLEN) {
        fprintf(stderr, "ERROR: <message> IS OVER %d BYTES. NOT SUPPORTED AT THE MOMENT.", MSGMAXLEN);
        return EXIT_FAILURE;
    }
    if ((htype & 0b10000000) == 0b10000000) { // test for the implementation flag.
        fprintf(stderr, "WARNING: This hash algorithm is not supported yet. (\"%s\")\n" USAGE_HELP "\n", get_algorithm(htype), argv[0]);
        return EXIT_FAILURE;
    }


    /* MESSAGE PADDING */

    word64 msglen = strlen(argv[1])*8;
    word64 block_count = get_block_count(msglen,512);
    uint16 zbitcount = get_zbitcount(msglen,512);

    if (vblevel == VERBOSE_MAX) {
        printf("l=%lld=(%lld*512+%lld) k=%d\n",msglen,msglen/512,msglen%512,zbitcount);
        printf("l+1+k = %lld = %lldmod512\n",(msglen+1+zbitcount),(msglen+1+zbitcount)%512);
        printf("block_count=%lld\n",block_count);
        printf(SEP);
    }

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

    if (vblevel == VERBOSE_MAX) {
        printf("%-8s%-8s %-8s%-8s %-8s%-8s %-8s%-8s %-8s%-8s %-8s%-8s %-8s%-8s %-8s%-8s\n",
            "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
            "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15"
        );
        for (int i = 0; i < block_count; i++) {
            printf("%.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X %.8X%.8X\n",
                mblocks[i].w0,mblocks[i].w1,mblocks[i].w2,mblocks[i].w3,
                mblocks[i].w4,mblocks[i].w5,mblocks[i].w6,mblocks[i].w7,
                mblocks[i].w8,mblocks[i].w9,mblocks[i].w10,mblocks[i].w11,
                mblocks[i].w12,mblocks[i].w13,mblocks[i].w14,mblocks[i].w15
            );
        }
        printf(SEP);
    }


    /* ACTUAL HASH COMPUTATION */

    word32 H[8];
    
    switch (htype) {
        case default_hash:
        case sha256:
            sha256_digest(H, mblocks, block_count, vblevel);
            break;
        case sha224:
            sha224_digest(H, mblocks, block_count, vblevel);
            break;
        case sha1:
            sha1_digest(H, mblocks, block_count, vblevel);
            break;
        default: break;
    }

    display_hash(H, htype, vblevel);

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
        case sha3_224:
            hashname = "sha3-224";
            break;
        case sha3_256:
            hashname = "sha3-256";
            break;
        case sha3_384:
            hashname = "sha3-384";
            break;
        case sha3_512:
            hashname = "sha3-512";
            break;
        case md4:
            hashname = "md4";
            break;
        case md5:
            hashname = "md5";
            break;
        default:
            hashname = "\0";
            break;
    }
    return hashname;
}

void display_help(const char* command_argv0) {
    // printf("================================================================================\n");
    printf(USAGE "\n\n", command_argv0);
    printf("  --help            Shows this help page then exit.\n");
    printf("  -h                Equivalent of --help\n");
    printf("  --hash <hash>     Specifies the type of hash to use. (default sha256)\n");
    printf("         sha256     You can see the list of any valid <hash> value. The values\n");
    printf("         sha1       preceded by a \"[!]\" are not implemented yet, they will be\n");
    printf("         sha224     in the future but if you try to use them now it will throw a\n");
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
            } else if (strcmp(argv[o], "sha3-224")==0) {
                *htype = sha3_224;
            } else if (strcmp(argv[o], "sha3-256")==0) {
                *htype = sha3_256;
            } else if (strcmp(argv[o], "sha3-384")==0) {
                *htype = sha3_384;
            } else if (strcmp(argv[o], "sha3-512")==0) {
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
