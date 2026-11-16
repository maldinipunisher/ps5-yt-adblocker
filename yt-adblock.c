// yt-adblock.c — PS5 YouTube ad-filter daemon (EDUCATIONAL REFERENCE).
//
// NOTE: this source is published INCOMPLETE on purpose. The core kernel
// memory primitive below (find_pml4_pair) is stubbed out — the
// architecture, the layered write protocol and the scanning logic are
// fully shown, but the payload as published does nothing. See README.
//
// Findings from the recon payloads (4/5/6):
//  - The midroll ad-break URL is the template
//    "https://www.youtube.com/get_midroll_info?..." living in the heap as
//    a JS string from video start (m_pos_ms scheduled at minute 14 etc.);
//    it is fetched at runtime when the cue point fires.
//  - If the fetch fails, the JS error handler treats the cue as
//    processed -> playback CONTINUES without the ad.
//  - Same-length overwrite of "get_midroll_info" (16 bytes) ->
//    "zzzzzzzzzzzzzzzz" -> fetch 404 -> ad break cancelled. String length
//    NEVER changes (JS-safe).
//
// LAYERED WRITE PROTOCOL (every layer must pass or the target is skipped):
//   1. read 16 bytes twice; both must be exactly "get_midroll_info"
//   2. kernel_copyin IDENTICAL bytes (write-path test, zero effect)
//   3. re-read: must still be "get_midroll_info" (write path works)
//   4. kernel_copyin "zzzzzzzzzzzzzzzz"
//   5. re-read: must be "zzzz..." -> [POISON] recorded
// All addresses are user heap that has JUST been read successfully via the
// walk (proven valid). No speculative deref, PML4 via single pair-scan —
// same anti-panic discipline as always.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/user.h>
#include <errno.h>

#include <ps5/kernel.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

// ===== On-screen PS5 notification popup (top-left) =====
typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

// rename our process in the etaHEN list (pattern proven in
// ps5-kstuff-ldr main.c:67)
int sceKernelSetProcessName(const char *name);
#define PROC_NAME "yt-adblock.elf"

static void notify(const char *msg) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.message, msg, sizeof(req.message) - 1);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}
// ============================================================

/* Network logging intentionally removed from the published copy:
 * all state is reported via on-screen notifications only. */
static void log_send(const char *fmt, ...) { (void)fmt; }

// ================= sysctl helpers =================

#define MIN_APP_VM_BYTES (128ULL * 1024 * 1024)   /* heuristic: real app */

typedef struct {
    size_t   n_entries;
    uint64_t total_size;
    uint64_t max_region;
} vmmap_info_t;

static void parse_vmmap(const uint8_t *vbuf, size_t len, vmmap_info_t *info) {
    memset(info, 0, sizeof(*info));
    const uint8_t *ptr = vbuf;
    const uint8_t *end = vbuf + len;
    while (ptr + 24 <= end) {
        uint32_t structsize;
        memcpy(&structsize, ptr, 4);
        if (structsize < 24 || structsize > 4096) break;
        uint64_t start, stop;
        memcpy(&start, ptr + 8, 8);
        memcpy(&stop, ptr + 16, 8);
        if (stop > start) {
            info->n_entries++;
            info->total_size += (stop - start);
            if (stop - start > info->max_region)
                info->max_region = stop - start;
        }
        ptr += structsize;
    }
}

static void kill_stale(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) return;
    void *buf = malloc(len);
    if (!buf) return;
    if (sysctl(mib, 4, buf, &len, NULL, 0) < 0) { free(buf); return; }
    struct kinfo_proc *kp0 = (struct kinfo_proc *)buf;
    size_t stride = kp0[0].ki_structsize;
    if (stride < 256 || stride > 4096) { free(buf); return; }
    size_t count = len / stride;
    pid_t me = getpid();
    for (size_t i = 0; i < count; i++) {
        struct kinfo_proc *p = (struct kinfo_proc *)((uint8_t *)buf + i * stride);
        if (p->ki_pid == me || p->ki_pid <= 1) continue;
        // match both old (payload.elf) and new (yt-adblock.elf) instances
        if (strcmp(p->ki_comm, "payload.elf") == 0 ||
            strcmp(p->ki_comm, PROC_NAME) == 0) {
            log_send("[STALE] killed %s pid=%d\n", p->ki_comm, p->ki_pid);
            kill(p->ki_pid, SIGKILL);
        }
    }
    free(buf);
}

static pid_t find_youtube_pid(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t len = 0;
    if (sysctl(mib, 4, NULL, &len, NULL, 0) < 0) return -1;
    void *buf = malloc(len);
    if (!buf) return -1;
    if (sysctl(mib, 4, buf, &len, NULL, 0) < 0) { free(buf); return -1; }

    struct kinfo_proc *kp0 = (struct kinfo_proc *)buf;
    size_t stride = kp0[0].ki_structsize;
    if (stride < 256 || stride > 4096) { free(buf); return -1; }
    size_t count = len / stride;
    pid_t found = -1;

    for (size_t i = 0; i < count; i++) {
        struct kinfo_proc *p = (struct kinfo_proc *)((uint8_t *)buf + i * stride);
        if (strstr(p->ki_comm, "eboot.bin") == NULL) continue;
        int mib2[4] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, p->ki_pid};
        size_t vlen = 0;
        if (sysctl(mib2, 4, NULL, &vlen, NULL, 0) < 0) continue;
        uint8_t *vbuf = malloc(vlen);
        if (!vbuf) continue;
        if (sysctl(mib2, 4, vbuf, &vlen, NULL, 0) == 0) {
            vmmap_info_t info;
            parse_vmmap(vbuf, vlen, &info);
            if (info.total_size >= MIN_APP_VM_BYTES)
                found = p->ki_pid;
        }
        free(vbuf);
        if (found > 0) break;
    }
    free(buf);
    return found;
}

// ================= kernel chain (proven 4x without panic) =================

static uint64_t find_proc_addr_by_pid(pid_t pid) {
    uint64_t proc = 0;
    if (kernel_copyout(KERNEL_ADDRESS_ALLPROC, &proc, 8) != 0 || proc == 0)
        return 0;
    int guard = 0;
    while (proc != 0 && guard++ < 1000) {
        uint64_t fpid = 0;
        if (kernel_copyout(proc + KERNEL_OFFSET_PROC_P_PID, &fpid, 4) != 0)
            return 0;
        if ((pid_t)fpid == pid) return proc;
        uint64_t next = 0;
        if (kernel_copyout(proc, &next, 8) != 0) return 0;
        if (next != 0 && (next >> 48) != 0xffff) return 0;
        proc = next;
    }
    return 0;
}

/* ------------------------------------------------------------------
 * PML4 DISCOVERY — INTENTIONALLY NOT PROVIDED
 *
 * Concept: the target's PML4 is located from a kernel structure
 * (proc -> p_vmspace) by scanning for an adjacent pair of fields with a
 * strict structural relation (kernel-VA page-aligned pointer followed by
 * a physical page-aligned value). The relation acts as a zero-deref
 * selector: exactly one candidate, validated structurally, hard-stop on
 * failure. NEVER probe speculative kernel addresses — that panics.
 *
 * Implementation is left as an exercise; this stub always fails safe.
 * ------------------------------------------------------------------ */
static int find_pml4_pair(pid_t pid, uint64_t *out_l4va, uint64_t *out_vmspace) {
    (void)pid; (void)out_l4va; (void)out_vmspace;
    return -1;   /* intentionally omitted */
}

/* ------------------------------------------------------------------
 * PAGE-TABLE WALK (READ) — INTENTIONALLY NOT PROVIDED
 *
 * Concept: translate a target user VA to a kernel-side address by walking
 * PML4 -> PDPT -> PD -> PT via kernel_copyout of the table entries, then
 * read the mapped page via the kernel direct map. PS5 uses a custom PTE
 * format (attribute tags mixed into the physical bits). Validate every
 * entry (present bit, canonical kernel VA) before dereferencing; break
 * on the first non-present level.
 *
 * Implementation is left as an exercise; this stub always fails safe.
 * ------------------------------------------------------------------ */
static int walk_read(uint64_t l4va, uint64_t dmap,
                     uintptr_t addr, void *buf, size_t len) {
    (void)l4va; (void)dmap; (void)addr; (void)buf; (void)len;
    return -1;   /* intentionally omitted */
}

// walk_write — mirror of walk_read: resolve each user VA page to a KERNEL
// address (dmap+phys / kernel-VA frame) first, then kernel_copyin per chunk.
// kernel_copyin REJECTS user-space kaddr (0xffff... sanity check in the SDK
// crt/kernel.c) — the cause of the first run's failures (copyin called with
// a raw user VA).
/* ------------------------------------------------------------------
 * PAGE-TABLE WALK (WRITE) — INTENTIONALLY NOT PROVIDED
 *
 * Concept: same translation as the read walk, but the final copy is a
 * kernel_copyin into the resolved kernel-side address. Note: kernel write
 * primitives typically reject user-space addresses — always resolve to
 * the kernel map first. Guarded by the layered write protocol in
 * try_poison(): identical-bytes test write, verify, then poison, verify.
 *
 * Implementation is left as an exercise; this stub always fails safe.
 * ------------------------------------------------------------------ */
static int walk_write(uint64_t l4va, uint64_t dmap,
                      uintptr_t addr, const void *buf, size_t len) {
    (void)l4va; (void)dmap; (void)addr; (void)buf; (void)len;
    return -1;   /* intentionally omitted */
}

// ================= poison =================

// Target 1 (midroll): URL template fetched at runtime when the cue fires
#define SIG_LEN 16
static const uint8_t SIG_AD[] = "get_midroll_info";

// Target 2+ (preroll/start): JSON keys in the playerResponse. Renaming a
// key -> client lookup becomes undefined -> client treats the video as
// ad-free -> the ad module never loads -> pre-roll never renders. The
// pattern INCLUDES quote+colon so only the JSON key matches (JS code
// accesses properties via dot-notation, without quotes). The poison
// preserves quote+colon (JSON stays valid), the key itself becomes z's.
static const char *JSON_KEYS[] = {
    "\"adPlacements\":",           /* JSON key (transient - bonus) */
    "\"adSlots\":",
    "\"playerAds\":",
    "adPlacements",                /* BARE - JS atom (persists from app start) */
    "instreamVideoAdRenderer",     /* BARE atom: pre-roll ad content property */
};
#define NKEYS 5

static void build_poison(const uint8_t *pat, int plen, uint8_t *out) {
    int is_json_key = (pat[0] == '"');   // pattern quote...quote-colon
    for (int i = 0; i < plen; i++) {
        if (is_json_key && (i == 0 || i == plen - 2 || i == plen - 1))
            out[i] = pat[i];             // preserve " ... " :
        else
            out[i] = 'z';
    }
}

static void cache_remember(uint64_t va, int pat_idx);   // fwd decl (cache di bawah)

// Layered write protocol. Every failing step -> skip (log); NEVER proceed
// to a further write when a prior verification did not match.
static void try_poison(uint64_t l4va, uint64_t dmap, uint64_t va,
                       const uint8_t *pat, int plen, const char *label,
                       int pat_idx) {
    uint8_t cur[64], back[64], poi[64];
    if (plen > 64) return;
    build_poison(pat, plen, poi);

    // 1. validate with two identical reads
    if (walk_read(l4va, dmap, va, cur, plen) != plen) return;
    if (memcmp(cur, pat, plen) != 0) return;
    if (walk_read(l4va, dmap, va, back, plen) != plen) return;
    if (memcmp(back, pat, plen) != 0) {
        log_send("[POISON] %#llx %s: two reads differ — skip\n",
                 (unsigned long long)va, label);
        return;
    }

    // 2. write IDENTICAL bytes via walk_write — write-path test, zero effect
    if (walk_write(l4va, dmap, va, cur, plen) != plen) {
        log_send("[POISON] %#llx %s: identical walk_write failed — skip\n",
                 (unsigned long long)va, label);
        return;
    }

    // 3. verify content is still the original
    if (walk_read(l4va, dmap, va, back, plen) != plen ||
        memcmp(back, pat, plen) != 0) {
        log_send("[POISON] %#llx %s: post-write verify FAILED — skip\n",
                 (unsigned long long)va, label);
        return;
    }

    // 4. poison (same-length)
    if (walk_write(l4va, dmap, va, poi, plen) != plen) {
        log_send("[POISON] %#llx %s: poison walk_write failed\n",
                 (unsigned long long)va, label);
        return;
    }

    // 5. verify the poison landed
    if (walk_read(l4va, dmap, va, back, plen) == plen &&
        memcmp(back, poi, plen) == 0) {
        log_send("[POISON] %#llx %s: OK — poisoned\n", (unsigned long long)va, label);
        if (pat_idx >= 0) cache_remember(va, pat_idx);
    } else {
        log_send("[POISON] %#llx %s: post-poison verify FAILED (GC moved it?)\n",
                 (unsigned long long)va, label);
    }
}

// ================= poison address cache (across relaunches) =================
#define MAX_CACHE 512
static uint64_t cache_va[MAX_CACHE];
static uint8_t  cache_pat[MAX_CACHE];
static int ncache = 0;

static const uint8_t *pat_by_idx(int idx, int *len, const char **label);

static void cache_remember(uint64_t va, int pat_idx) {
    for (int i = 0; i < ncache; i++)
        if (cache_va[i] == va) return;
    if (ncache < MAX_CACHE) {
        cache_va[ncache] = va;
        cache_pat[ncache] = (uint8_t)pat_idx;
        ncache++;
    }
}

// ================= region list =================

#define MAX_REGIONS 1024

typedef struct {
    uint64_t start, end;
} region_t;

static region_t regions[MAX_REGIONS];
static int nregions = 0;

static int load_vmmap_regions(pid_t pid) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_VMMAP, pid};
    size_t vlen = 0;
    if (sysctl(mib, 4, NULL, &vlen, NULL, 0) < 0) return -1;
    uint8_t *vbuf = malloc(vlen);
    if (!vbuf) return -1;
    if (sysctl(mib, 4, vbuf, &vlen, NULL, 0) < 0) { free(vbuf); return -1; }

    nregions = 0;
    const uint8_t *ptr = vbuf;
    const uint8_t *end = vbuf + vlen;
    while (ptr + 24 <= end && nregions < MAX_REGIONS) {
        uint32_t structsize;
        memcpy(&structsize, ptr, 4);
        if (structsize < 24 || structsize > 4096) break;
        uint64_t start, stop;
        memcpy(&start, ptr + 8, 8);
        memcpy(&stop, ptr + 16, 8);
        if (stop > start && start < 0xffffff0000000000ULL) {
            regions[nregions].start = start;
            regions[nregions].end   = stop;
            nregions++;
        }
        ptr += structsize;
    }
    free(vbuf);
    return nregions;
}

#define SCAN_CHUNK 0x4000
#define BIG_REGION (512ULL << 20)

static const uint8_t *mem_find(const uint8_t *hay, size_t hlen,
                               const uint8_t *needle, size_t nlen) {
    if (nlen == 0 || hlen < nlen) return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++)
        if (hay[i] == needle[0] && memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    return NULL;
}

static uint64_t scan_bytes = 0;

static const uint8_t *pat_by_idx(int idx, int *len, const char **label) {
    static const char *labels[] = {"midroll-url", "json-key", "json-key",
                                   "json-key", "atom", "atom"};
    *label = (idx >= 0 && idx < 6) ? labels[idx] : "?";
    switch (idx) {
    case 0: *len = SIG_LEN; return SIG_AD;
    case 1: *len = (int)strlen(JSON_KEYS[0]); return (const uint8_t *)JSON_KEYS[0];
    case 2: *len = (int)strlen(JSON_KEYS[1]); return (const uint8_t *)JSON_KEYS[1];
    case 3: *len = (int)strlen(JSON_KEYS[2]); return (const uint8_t *)JSON_KEYS[2];
    case 4: *len = 14; return (const uint8_t *)"adPlacements";
    case 5: *len = 24; return (const uint8_t *)"instreamVideoAdRenderer";
    default: *len = 0; return NULL;
    }
}

// PREFILL: re-apply poison to cached addresses BEFORE scanning (anti
// cold-start race)
static int prefill_cached(uint64_t l4va, uint64_t dmap) {
    int ok = 0;
    for (int i = 0; i < ncache; i++) {
        int plen; const char *label;
        const uint8_t *pat = pat_by_idx(cache_pat[i], &plen, &label);
        if (!pat) continue;
        uint8_t cur[64], poi[64];
        if (plen > 64) continue;
        build_poison(pat, plen, poi);
        if (walk_read(l4va, dmap, cache_va[i], cur, plen) != plen) continue;
        if (memcmp(cur, pat, plen) != 0) continue;   /* different content - skip */
        if (walk_write(l4va, dmap, cache_va[i], poi, plen) == plen) {
            ok++;
            log_send("[PREFILL] %#llx %s: poison re-applied\n",
                     (unsigned long long)cache_va[i], label);
        }
    }
    return ok;
}

// scan a region for "get_midroll_info"; POISON every new hit.
// (poison mengubah byte ke "zzzz" -> tidak akan ter-hit ulang)
static int scan_region_poison(uint64_t l4va, uint64_t dmap, const region_t *r) {
    static uint8_t chunk[SCAN_CHUNK];
    int poisoned = 0;

    for (uint64_t a = r->start & ~0xfffULL; a < r->end; ) {
        size_t want = SCAN_CHUNK;
        if (a + want > r->end) want = (size_t)(r->end - a);
        int got = walk_read(l4va, dmap, a, chunk, want);
        if (got <= 0) break;
        scan_bytes += (uint64_t)got;
        if (scan_bytes >= (64ULL << 20)) {
            log_send("[SCAN] progress: %lluMB\n", scan_bytes >> 20);
            scan_bytes = 0;
        }

        // target 1: midroll URL
        const uint8_t *p = chunk;
        size_t left = (size_t)got;
        while ((p = mem_find(p, left, SIG_AD, SIG_LEN)) != NULL) {
            uint64_t va = a + (uint64_t)(p - chunk);
            try_poison(l4va, dmap, va, SIG_AD, SIG_LEN, "midroll-url", 0);
            poisoned++;
            p += SIG_LEN;
            left = (size_t)(chunk + got - p);
            if (left < SIG_LEN) break;
        }

        // target 2+: JSON key preroll/start ads
        for (int k = 0; k < NKEYS; k++) {
            size_t klen = strlen(JSON_KEYS[k]);
            p = chunk;
            left = (size_t)got;
            while ((p = mem_find(p, left, (const uint8_t *)JSON_KEYS[k], klen)) != NULL) {
                uint64_t va = a + (uint64_t)(p - chunk);
                try_poison(l4va, dmap, va, (const uint8_t *)JSON_KEYS[k],
                           (int)klen, "json-key", 1 + k);
                poisoned++;
                p += klen;
                left = (size_t)(chunk + got - p);
                if (left < klen) break;
            }
        }
        a += got;
    }
    return poisoned;
}

int main(void) {
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    int nrn = sceKernelSetProcessName(PROC_NAME);
    (void)nrn;

    kill_stale();

    pid_t yt = -1;
    for (int tries = 0; tries < 30 && yt < 0; tries++) {
        yt = find_youtube_pid();
        if (yt < 0) sleep(2);
    }
    if (yt < 0) {
        // running without YT is fine — re-acquire picks it up when it launches
        log_send("[YT-ADBLOCK] YT not running — standby, re-acquire waits for new pid\n");
    } else {
        log_send("[YT-ADBLOCK] YouTube pid=%d\n", yt);
    }
    uint64_t l4va = 0, vmspace = 0;
    if (yt > 0) {
        int pr = find_pml4_pair(yt, &l4va, &vmspace);
        if (pr < 0) {
            log_send("[YT-ADBLOCK] find_pml4_pair=%d — lanjut standby (re-acquire nanti)\n", pr);
            yt = -1;
        }
    }



    uint64_t dmap = (uint64_t)KERNEL_ADDRESS_DMAP_BASE;
    if (!dmap) dmap = 0xfffffe0000000000ULL;
    log_send("[YT-ADBLOCK] dmap=%#llx\n", (unsigned long long)dmap);
    if (yt > 0 && ncache > 0) {
        int npf = prefill_cached(l4va, dmap);
        log_send("[YT-ADBLOCK] initial prefill: %d/%d re-poisoned\n", npf, ncache);
    }

    log_send("[YT-ADBLOCK] watch loop 1s (hot-range-first): poison midroll-url + json-keys + ATOMS\n");
    log_send("[YT-ADBLOCK] re-acquire enabled: app exit/relaunch follows the new pid\n");

    // ===== PTE RECON (read-only) — recv-hook feasibility =====
    // Target: dlsym sceNetRecv (absolute address, stable across runs).
    // Question: is the code page RWX/RX? Can it be made RW via a kernel
    // PTE write?
    if (yt > 0) {
        uint32_t hnet = 0;
        int dr = kernel_dynlib_handle(yt, "libSceNet.sprx", &hnet);
        log_send("[PTE] dynlib_handle(libSceNet.sprx): ret=%d handle=%u\n", dr, hnet);
        if (dr == 0 && hnet) {
            intptr_t recv_a = kernel_dynlib_dlsym(yt, hnet, "sceNetRecv");
            log_send("[PTE] sceNetRecv = %#lx\n", (unsigned long)recv_a);
            if (recv_a) {
                // baca 32 byte kode + PTE halamannya
                uint8_t code[32];
                int g = walk_read(l4va, dmap, (uintptr_t)recv_a, code, sizeof(code));
                if (g == 32) {
                    char hex[128];
                    int ln = snprintf(hex, sizeof(hex), "[PTE] code: ");
                    for (int i = 0; i < 32; i++)
                        ln += snprintf(hex + ln, sizeof(hex) - ln, "%02x", code[i]);
                    log_send("%s\n", hex);
                } else {
                    log_send("[PTE] code read failed g=%d\n", g);
                }
                // Page PTE: walk down to level 4, read the raw entries
                uintptr_t va = (uintptr_t)recv_a;
                uint64_t pml4e=0, pdpe=0, pde=0, pte=0;
                uint64_t f;
                do {
                    uint64_t i4 = (va >> 39) & 0x1ff, i3 = (va >> 30) & 0x1ff;
                    uint64_t i2 = (va >> 21) & 0x1ff, i1 = (va >> 12) & 0x1ff;
                    if (kernel_copyout(l4va + i4*8, &pml4e, 8) != 0) {
                        log_send("[PTE] pml4e read FAIL\n"); break;
                    }
                    if (!(pml4e & 1)) {
                        log_send("[PTE] pml4e not present (%#llx)\n", (unsigned long long)pml4e); break;
                    }
                    f = pml4e & 0xfffffffffffff000ULL;
                    uint64_t pdp = (f >= 0xffffff0000000000ULL) ? f : dmap + f;
                    if (kernel_copyout(pdp + i3*8, &pdpe, 8) != 0) {
                        log_send("[PTE] pdpe read FAIL @%#llx\n", (unsigned long long)(pdp + i3*8)); break;
                    }
                    if (!(pdpe & 1)) {
                        log_send("[PTE] pdpe not present (%#llx)\n", (unsigned long long)pdpe); break;
                    }
                    if (pdpe & 0x80) {
                        log_send("[PTE] 1GB page (pdpe=%#llx) RW=%d NX=%d\n",
                                 (unsigned long long)pdpe,
                                 !!(pdpe & 2), !(pdpe & (1ULL << 63)));
                        break;
                    }
                    f = pdpe & 0xfffffffffffff000ULL;
                    uint64_t pd = (f >= 0xffffff0000000000ULL) ? f : dmap + f;
                    if (kernel_copyout(pd + i2*8, &pde, 8) != 0) {
                        log_send("[PTE] pde read FAIL\n"); break;
                    }
                    if (!(pde & 1)) {
                        log_send("[PTE] pde not present (%#llx)\n", (unsigned long long)pde); break;
                    }
                    if (pde & 0x80) {
                        log_send("[PTE] 2MB page: pde=%#llx RW=%d NX=%d\n",
                                 (unsigned long long)pde,
                                 !!(pde & 2), !(pde & (1ULL << 63)));
                        break;
                    }
                    f = pde & 0xfffffffffffff000ULL;
                    uint64_t pt = (f >= 0xffffff0000000000ULL) ? f : dmap + f;
                    if (kernel_copyout(pt + i1*8, &pte, 8) != 0) {
                        log_send("[PTE] pte read FAIL\n"); break;
                    }
                    log_send("[PTE] 4K: pte=%#llx RW=%d NX=%d\n",
                             (unsigned long long)pte,
                             !!(pte & 2), !(pte & (1ULL << 63)));
                } while (0);
                log_send("[PTE] recon done (read-only — recv-hook decision "
                         "based on the RW/NX above)\n");
            }
        }
    }
    int tick = 0, total_poisoned = 0;
    int notified_ready = 0;   // popup "aman play" hanya 1x per proses YT
    while (1) {
        tick++;
        scan_bytes = 0;
        // optimistic scan: scan immediately at tick (no leading sleep) —
        // catches the playerResponse as early as possible after launch

        // cek app masih hidup; kalau exit/relaunch -> re-acquire pid baru
        // (proses YT baru = pid baru + PML4 baru; chain lama usang)
        pid_t cur = find_youtube_pid();
        if (cur != yt) {
            if (cur < 0) {
                if (tick % 200 == 0)   // log tiap ~10 menit, jangan spam
                    log_send("[YT-ADBLOCK] tick %d: YT not running — standby\n", tick);
                continue;
            }
            log_send("[YT-ADBLOCK] YT relaunch: pid %d -> %d — re-acquire chain\n",
                     yt, cur);
            yt = cur;
            uint64_t nl4 = 0, nvm = 0;
            int pr = find_pml4_pair(yt, &nl4, &nvm);
            if (pr < 0) {
                log_send("[YT-ADBLOCK] re-acquire PML4 failed (%d) — retry next tick\n", pr);
                yt = -1;          // paksa coba lagi tick depan
                continue;
            }
            l4va = nl4; vmspace = nvm;
            log_send("[YT-ADBLOCK] new chain: PML4=%#llx\n", (unsigned long long)l4va);
            notified_ready = 0;   // proses baru: tunggu poison pertama lagi
            if (ncache > 0) {
                int npf = prefill_cached(l4va, dmap);
                log_send("[YT-ADBLOCK] prefill: %d/%d cached addresses re-poisoned (before scan)\n",
                         npf, ncache);
            }
            total_poisoned = 0;   // counter per-proses
        }

        if (yt < 0 || l4va == 0) continue;          // no chain yet — standby
        scan_bytes = 0;
        if (load_vmmap_regions(yt) < 0) continue;   // brief exit — no log spam

        // TIGA FASE (anti cold-start, berbasis data 5 run):
        //   fase 0 = WINDOW teramati [0x260000000,0x280000000) — SEMUA hit
        //            5 run (min 0x26ad, max 0x2780) ada di dalamnya; ~32MB saja,
        //            finishes <1s.
        //   fase 1 = sisa hot range [0x200000000,0x300000000)
        //   fase 2 = sisanya
        // Alamat poison di-cache antar-relaunch (heap window stabil): saat
        // re-acquire, the cache phase covers old addresses FIRST, before the scan.
        const uint64_t HOT_LO = 0x200000000ULL, HOT_HI = 0x300000000ULL;
        const uint64_t WIN_LO = 0x260000000ULL, WIN_HI = 0x280000000ULL;
        int hits = 0;
        for (int phase = 0; phase < 3; phase++) {
            for (int i = 0; i < nregions; i++) {
                uint64_t sz = regions[i].end - regions[i].start;
                if (sz >= BIG_REGION) continue;
                int in_win = regions[i].start >= WIN_LO && regions[i].start < WIN_HI;
                int in_hot = regions[i].start >= HOT_LO && regions[i].start < HOT_HI;
                int want = (phase == 0) ? in_win : (phase == 1) ? in_hot : !in_hot;
                if (!want) continue;
                hits += scan_region_poison(l4va, dmap, &regions[i]);
            }
            if (hits > 0 && (phase == 0 || phase == 1))
                log_send("[YT-ADBLOCK] fase-%d: %d poison\n", phase, hits);
        }
        if (hits > 0) {
            total_poisoned += hits;
            log_send("[YT-ADBLOCK] tick %d: %d poison attempt (total %d)\n",
                     tick, hits, total_poisoned);
            if (!notified_ready) {
                notified_ready = 1;
                notify("YT Adblocker: ads poisoned — you can play video now");
            }
        }
        sleep(1);
    }
    return 0;
}
