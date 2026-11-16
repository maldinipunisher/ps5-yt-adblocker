#!/usr/bin/env python3
"""Post-link fixups for kstuff.elf built with the ps5-payload-sdk + lld:
   1. PT_DYNAMIC p_filesz/p_memsz: lld over-sizes it to the end of the segment
      (covers .dynsym/.rela.dyn) — the PS5 loader chokes on that. Clamp to
      the real SHT_DYNAMIC size.
   2. DT_FLAGS_1 DF_1_NOW: force lazy binding like the stock kstuff builds
      (BIND_NOW kills the process at load if any import is unresolvable)."""
import struct, sys

f = sys.argv[1] if len(sys.argv) > 1 else 'kstuff.elf'
b = bytearray(open(f, 'rb').read())
e_phoff = struct.unpack_from('<Q', b, 32)[0]
e_phnum = struct.unpack_from('<H', b, 56)[0]
e_phentsize = struct.unpack_from('<H', b, 54)[0]

for i in range(e_phnum):
    base = e_phoff + e_phentsize * i
    if struct.unpack_from('<I', b, base)[0] != 2:  # PT_DYNAMIC
        continue
    off = struct.unpack_from('<Q', b, base + 8)[0]
    va  = struct.unpack_from('<Q', b, base + 16)[0]
    n = struct.unpack_from('<Q', b, base + 32)[0] // 16
    # real size: scan for DT_NULL terminator
    real = 0
    while True:
        tag = struct.unpack_from('<Q', b, off + 16 * real)[0]
        real += 1
        if tag == 0:
            break
    sz = real * 16
    struct.pack_into('<QQ', b, base + 16, va, va)       # restore p_offset/p_vaddr
    struct.pack_into('<QQ', b, base + 32, sz, sz)       # p_filesz / p_memsz
    for j in range(real):
        tag, val = struct.unpack_from('<QQ', b, off + 16 * j)
        if tag == 30 and (val & 0x8):                   # DT_FLAGS_1 DF_1_NOW
            struct.pack_into('<QQ', b, off + 16 * j, 30, val & ~0x8)
            print('DT_FLAGS_1: cleared DF_1_NOW')
    print('PT_DYNAMIC clamped to 0x%x (%d entries)' % (sz, real))

open(f, 'wb').write(b)
