.PHONY: shak-cli win-shak-cli
.DEFAULT_GOAL = win-shak-cli

shak-cli: src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c \
           include/shacom.h include/sha1.h include/sha2-32.h include/sha2-64.h
	gcc -Wall -o bin/sha.out src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c -Iinclude

win-shak-cli: src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c \
           include/shacom.h include/sha1.h include/sha2-32.h include/sha2-64.h
	x86_64-w64-mingw32-gcc.exe -Wall -o bin/sha.exe src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c -Iinclude
