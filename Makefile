# yt-adblock — build with ps5-payload-sdk + LLVM (lld)
#
#   make yt-adblock.elf PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
#
# fix_elf.py is REQUIRED as a post-link step: lld over-sizes PT_DYNAMIC
# (PS5 loader dies silently) and BIND_NOW kills unresolved imports.

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined — point it at ps5-payload-sdk)
endif

CFLAGS := -Wall -O2

all: yt-adblock.elf

yt-adblock.elf: yt-adblock.c
	$(CC) $(CFLAGS) -o $@ $^
	python3 fix_elf.py $@

clean:
	rm -f yt-adblock.elf

.PHONY: all clean
