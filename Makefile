.PHONY: shak-cli win-shak-cli release
.SILENT:
.DEFAULT_GOAL = win-shak-cli

VMAJOR = 0# Not released yet
VMINOR = 9
COMMIT = $(shell git rev-list --count --all)
VPATCH = $(shell printf %03i `expr $(COMMIT) % 1000`)
VERSION = "$(VMAJOR).$(VMINOR).$(VPATCH)"

CFILES = src/main.c src/sha1.c src/sha2-32.c src/sha2-64.c src/shacom.c
HFILES = include/shacom.h include/sha1.h include/sha2-32.h include/sha2-64.h include/shaconstants.h

EXENAME = shak

gcc = gcc
wingcc = x86_64-w64-mingw32-gcc.exe

WINGCC_VERSION = "$(shell $(wingcc) --version | head -n 1)"
GCC_VERSION = "$(shell $(gcc) --version | head -n 1)"
WINGCC_MACHINE = "$(shell $(wingcc) -dumpmachine)"
GCC_MACHINE = "$(shell $(gcc) -dumpmachine)"

ifeq ($(MAKECMDGOALS),release)
RELEASEARGS = -DSHAK_RELEASE
else
RELEASEARGS =
endif


shak-cli: $(CFILES) $(HFILES)
	printf "building \033[33mshak-cli\033[0m... (\033[90mwith \033[3m$(gcc)\033[0m) ~ "
	$(gcc) -Wall -o bin/$(EXENAME) $(CFILES) -Iinclude -DGCCVERSION='$(GCC_VERSION)' -DSHAKVERSION='$(VERSION)' $(RELEASEARGS)
	echo done!

win-shak-cli: $(CFILES) $(HFILES)
	printf "building \033[33mwin-shak-cli\033[0m... (\033[90mwith \033[3m$(wingcc)\033[0m) ~ "
	$(wingcc) -Wall -o bin/$(EXENAME).exe $(CFILES) -Iinclude -DGCCVERSION='$(WINGCC_VERSION)' -DSHAKVERSION='$(VERSION)' $(RELEASEARGS)
	echo done!

release: win-shak-cli shak-cli
	printf "Creating archive \033[33m$(EXENAME)-$(VERSION)-$(GCC_MACHINE).tar.gz\033[0m... ~ "
	tar -C bin -cz -f releases/$(EXENAME)-$(VERSION)-$(GCC_MACHINE).tar.gz $(EXENAME)
	echo done!
	printf "Creating archive \033[33m$(EXENAME)-$(VERSION)-$(WINGCC_MACHINE).tar.gz\033[0m... ~ "
	tar -C bin -cz -f releases/$(EXENAME)-$(VERSION)-$(WINGCC_MACHINE).tar.gz $(EXENAME).exe
	echo done!
	printf "\033[32mrelease all done!\033[0m \n"
