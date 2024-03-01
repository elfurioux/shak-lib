.PHONY: sha-cli
.DEFAULT_GOAL: sha-cli

sha-cli: src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c \
           include/shacom.h include/sha1.h include/sha2-32.h include/sha2-64.h
	gcc -o bin/sha.exe src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c -Iinclude
