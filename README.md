# yt-adblock — PS5 YouTube Ad Filter (Educational)

An experimental PS5 homebrew payload that filters in-app YouTube ads by
editing ad-related data strings inside the running YouTube process memory
on a **jailbroken console the user owns**. It does **not** touch DRM, TLS,
certificates, entitlements, or Sony services — it only renames data strings
(same-length overwrite) so the app's own code fails to find ad definitions
and continues playback.

> **This project is published for educational and security-research purposes
> only.** It documents how a modern browser-based TV app (Cobalt/Starboard)
> handles ad placement data at runtime, and demonstrates defensive insight
> into client-side trust of server data. Do not use it on consoles you do
> not own, and do not use it in violation of any terms of service that
> apply to you. No copyrighted content is accessed, decrypted, or
> redistributed by this code.

## How it works (high level)

1. Find the YouTube process via the FreeBSD-style process list.
2. Resolve its page tables (PML4) — safely, with structural validation,
   no speculative kernel-address probing.
3. Read scanned heap regions (sysctl-provided VM map addresses only).
4. Overwrite ad-data strings in place, **same length**, e.g.:

   | String | Role | Effect of rename |
   |---|---|---|
   | `get_midroll_info` | midroll ad-break URL template | URL fetch fails → app treats cue as processed → playback continues |
   | `"adPlacements":` / `"adSlots":` / `"playerAds":` | JSON keys of the player response | response parses as "no ads defined" → pre-roll never rendered |
   | `adPlacements` / `instreamVideoAdRenderer` | JS atoms (interned names) | property lookups become `undefined` → ad module not loaded |

5. Every write is guarded by a layered protocol:

   ```
   read 2x (must be identical)
     → write identical bytes (path test, zero effect)
     → verify original still there
     → write poison bytes
     → verify poison landed
   ```

   Any failure ⇒ skip + log. It never writes unvalidated.

## Note on completeness

This source is published **incomplete on purpose**. The three core kernel
memory primitives in `yt-adblock.c` — `find_pml4_pair`, `walk_read`,
`walk_write` — are stubbed out (they always fail safe). Everything around
them is shown in full: process discovery, the layered write protocol
(read → identical-write test → verify → poison → verify), the scan phases,
and the standby/re-acquire daemon loop. The payload as published compiles
but does nothing; reimplementing the primitives requires your own kernel
research on your own console.

## Files

| File | Purpose |
|---|---|
| `yt-adblock.c` | Final payload: poison daemon + on-screen notifications + automatic standby/re-acquire of the YouTube process |
| `fix_elf.py` | Post-link fixup required by the ps5-payload-sdk + lld toolchain (clamps `PT_DYNAMIC`, clears `DF_1_NOW`) |
| `Makefile` | Build rules |

Compiled ELF binaries are intentionally **not** committed — build from
source on your own machine.

## Build

Requires [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdks) and LLVM
(`llvm-clang`, `ld.lld`):

```sh
make yt-adblock.elf PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
```

`fix_elf.py` runs automatically as a post-link step.

## Deployment (owner's own console)

Deployment is done the same way any ps5-payload-sdk ELF is delivered
(elfldr over the network to your own console). The payload runs
standalone and reports its state **on screen** — no external logging
host is required.

On screen you will see two notifications:
1. payload loaded and standing by
2. "ads poisoned — you can play video now" (first successful poison)

## Known limits

- First video after a cold app start can race the first poison (~5 s window);
  wait for the second on-screen notification before launching the app.
- SABR server-side stitched ads are out of reach for data renaming.
- Kernel write access requires the user's own jailbreak tooling (not
  included, not provided here).

## Ethics & scope

- Works only on a console you physically own and control.
- No DRM circumvention, no TLS interception, no license spoofing — by design.
- Research notes (what worked, what panicked, PS5 PTE quirks) live in this
  repo's git history messages; no proprietary Sony material is included.

## License

MIT
