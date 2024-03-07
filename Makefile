.PHONY: shak-cli win-shak-cli
.DEFAULT_GOAL = win-shak-cli

VERSION = "0.9.042"

shak-cli: src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c \
           include/shacom.h include/sha1.h include/sha2-32.h include/sha2-64.h
	gcc -Wall -o bin/shak src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c \
		-Iinclude -DGCCVERSION='"gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"' -DSHAKVERSION='$(VERSION)'

win-shak-cli: src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c \
           include/shacom.h include/sha1.h include/sha2-32.h include/sha2-64.h
	x86_64-w64-mingw32-gcc.exe -Wall -o bin/shak.exe src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c \
		-Iinclude -DGCCVERSION='"x86_64-w64-mingw32-gcc.exe (x86_64-posix-seh-rev0, Built by MinGW-Builds project) 13.2.0"' -DSHAKVERSION='$(VERSION)'
