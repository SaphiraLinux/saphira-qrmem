/* Saphira Memory - qrmem aperture: create, attach, refuse, ownership.
 *
 * This file is the security boundary of the tile fabric. Everything it refuses
 * to do, it refuses loudly: a segment that does not match what this build
 * expects is an error, never something to be reinterpreted.
 */
#include "qrmem.h"

#include <errno.h>
#include <stddef.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void set_err(char *err, size_t errlen, const char *fmt, ...) {
    if (!err || !errlen)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* Native byte order, probed rather than assumed. The tag is written into the
 * header once and compared on every attach. */
void qrmem_ap_path_of(const char *name, char *out, size_t out_len) {
    if (!out || !out_len)
        return;
    if (name && name[0] == '/')
        snprintf(out, out_len, "%s%s", QRMEM_SHM_DIR, name);
    else
        snprintf(out, out_len, "%s/%s", QRMEM_SHM_DIR, name ? name : "");
}

int qrmem_ap_name_of(const char *given, char *out, size_t out_len) {
    size_t dlen = sizeof(QRMEM_SHM_DIR) - 1u;
    if (!given || !given[0] || !out || !out_len)
        return -1;
    if (!strncmp(given, QRMEM_SHM_DIR "/", dlen + 1u)) {
        snprintf(out, out_len, "%s", given + dlen);
    } else if (given[0] == '/') {
        snprintf(out, out_len, "%s", given);
    } else {
        snprintf(out, out_len, "/%s", given);
    }
    /* One leading slash, and no other slash anywhere: that is the whole POSIX
     * shm name grammar, and enforcing it here turns a confusing EINVAL from
     * deep inside libc into a clear refusal at the edge. */
    if (out[0] != '/' || strchr(out + 1, '/') != NULL || !out[1])
        return -1;
    return 0;
}

static uint16_t native_order(void) {
    /* Ask the machine, do not infer it. The obvious-looking version of this
     * probe -- memcpy a 0x0102 u16 out and read the bytes back -- is INVERTED:
     * on a little-endian host that yields 0x0201, so the fabric would label
     * itself big-endian and the byte-order refusal would never fire. Which is
     * exactly what it did until this test caught it. */
    const uint32_t one = 1u;
    return (*(const unsigned char *)(const void *)&one == 1u)
               ? QRMEM_ORDER_LE
               : QRMEM_ORDER_BE;
}

/* The atomics in the aperture must be genuinely lock-free. A shared image
 * whose publication words are lock-based would be correct-but-serialised, and
 * a lock implementation whose lifetime differs per process is not correct at
 * all. Refuse rather than run degraded. */
static int atomics_usable(char *err, size_t errlen) {
    _Atomic uint64_t probe64 = 0;
    _Atomic uint32_t probe32 = 0;
    if (!atomic_is_lock_free(&probe64) || !atomic_is_lock_free(&probe32)) {
        set_err(err, errlen,
                "shared-memory publication words are not lock-free on this "
                "platform; refusing to create a fabric that would serialise "
                "or, worse, lock per process");
        return 0;
    }
    return 1;
}

static int layout_sane(char *err, size_t errlen) {
    /* The header must be exactly one page, and the agent array must land on an
     * 8-byte boundary for its uint64 heartbeat. Both are asserted here rather
     * than trusted: adding three geometry fields silently broke the first, and
     * a header that is 8 bytes too big is an aperture whose padding arithmetic
     * nobody has checked. */
    if (sizeof(qrmem_hdr_t) != QRMEM_HDR_BYTES) {
        set_err(err, errlen,
                "aperture header is %zu bytes, layout requires %u; rebuild",
                sizeof(qrmem_hdr_t), QRMEM_HDR_BYTES);
        return 0;
    }
    if (offsetof(qrmem_hdr_t, agents) % 8u != 0u) {
        set_err(err, errlen,
                "agent registry starts at offset %zu, which is not 8-byte "
                "aligned for its heartbeat field",
                offsetof(qrmem_hdr_t, agents));
        return 0;
    }
    if (sizeof(((qrmem_hdr_t *)0)->agents[0]) != 64u) {
        set_err(err, errlen,
                "agent slot is %zu bytes, the header padding assumes 64; rebuild",
                sizeof(((qrmem_hdr_t *)0)->agents[0]));
        return 0;
    }
    if (sizeof(qrmem_screen_ctl_t) != QRMEM_SCREEN_CTL_BYTES) {
        set_err(err, errlen,
                "screen control block is %zu bytes, layout requires %u; rebuild",
                sizeof(qrmem_screen_ctl_t), QRMEM_SCREEN_CTL_BYTES);
        return 0;
    }
    if (sizeof(qrmem_cell_t) > QRMEM_CELL_BYTES) {
        set_err(err, errlen,
                "cell grew to %zu bytes, the padded stride is %u; the cell "
                "region arithmetic would overrun the aperture",
                sizeof(qrmem_cell_t), (unsigned)QRMEM_CELL_BYTES);
        return 0;
    }
    /* A record handed to publish must fit the body it will be written into. */
    if (sizeof(qrmem_rec_t) < QRMEM_CELL_BODY) {
        set_err(err, errlen, "record is smaller than the cell body it feeds");
        return 0;
    }
    /* Regions must not overlap, and the plane must sit clear of the records:
     * a record store written over its own visual encoding would be a data
     * loss, not a rendering glitch. */
    if (QRMEM_PLANE_REGION_OFF <
        QRMEM_RECORDS_REGION_OFF + QRMEM_RECORDS_BYTES) {
        set_err(err, errlen, "code plane region overlaps the record store");
        return 0;
    }
    if (QRMEM_INDEX_REGION_OFF <
        QRMEM_PLANE_REGION_OFF +
            (size_t)QRMEM_SCREENS * QRMEM_PLANES_SCREEN_BYTES) {
        set_err(err, errlen, "index region overlaps the bitplane stack");
        return 0;
    }
    return 1;
}

static void ap_bind(qrmem_ap_t *ap) {
    ap->hdr = (qrmem_hdr_t *)(void *)ap->base;
    ap->screens =
        (qrmem_screen_ctl_t *)(void *)(ap->base + QRMEM_HDR_BYTES);
    ap->cells =
        (qrmem_cell_t *)(void *)(ap->base + QRMEM_RECORDS_REGION_OFF);
    ap->plane = (_Atomic unsigned char *)(void *)(ap->base +
                                                  QRMEM_PLANE_REGION_OFF);
    ap->index = (qrmem_index_ent_t *)(void *)(ap->base +
                                               QRMEM_INDEX_REGION_OFF);
}

static qrmem_index_ent_t *index_table(const qrmem_ap_t *ap, uint32_t screen) {
    return ap->index + (size_t)screen * QRMEM_INDEX_ENTRIES;
}

/* Validate a mapped header. Every refusal names the field and the observed
 * value, because "attach failed" without a reason is the failure shape that
 * costs an afternoon. */
static int hdr_validate(const qrmem_ap_t *ap, char *err, size_t errlen) {
    const qrmem_hdr_t *h = ap->hdr;
    if (h->magic != QRMEM_MAGIC) {
        set_err(err, errlen,
                "not a tile fabric: magic 0x%08x, expected 0x%08x", h->magic,
                QRMEM_MAGIC);
        return -1;
    }
    if (h->abi_major != QRMEM_ABI_MAJOR) {
        set_err(err, errlen,
                "fabric ABI major %u, this build speaks %u; refusing to attach",
                h->abi_major, QRMEM_ABI_MAJOR);
        return -1;
    }
    /* A fabric with no identity is refused, never adopted.
     *
     * Minting an id at attach time would be the convenient choice and the wrong
     * one: attach is exactly what a SECOND agent does while the fabric is live,
     * so two attachers could each mint a different id for one fabric and
     * neither would be wrong on its own terms. Fabric identity has to be decided
     * once, by the creator, before anyone else can see the fabric - which is why
     * it is minted in create and only ever READ here.
     *
     * An aperture predating this field therefore cannot be upgraded in place.
     * The operator action is a --recreate, which is honest: it produces a NEW
     * fabric with a new identity, and records come back from the snapshot. */
    if (qrmem_uuid_is_nil(&h->fabric_id)) {
        set_err(err, errlen,
                "this fabric has no identity: it was created before fabric ids "
                "(ABI %u.%u, this build speaks %u.%u) and its id cannot be "
                "minted now, because attach is what every other agent does "
                "while a fabric is live and two attachers would each invent a "
                "different identity for the same namespace. Restart the daemon "
                "with --recreate to make a new fabric with a real identity; "
                "record content and project labels are restored from the "
                "snapshot, and the new identity is deliberately different",
                (unsigned)h->abi_major, (unsigned)h->abi_minor,
                (unsigned)QRMEM_ABI_MAJOR, (unsigned)QRMEM_ABI_MINOR);
        return -1;
    }
    if (h->hdr_bytes != QRMEM_HDR_BYTES) {
        set_err(err, errlen,
                "fabric header %u bytes, this build expects %u; refusing to "
                "attach rather than misread the layout",
                h->hdr_bytes, QRMEM_HDR_BYTES);
        return -1;
    }
    if (h->byte_order != native_order()) {
        set_err(err, errlen,
                "fabric byte order 0x%04x, this host is 0x%04x; a shared image "
                "with mismatched participant byte orders is refused at attach",
                h->byte_order, native_order());
        return -1;
    }
    if (h->screen_count != QRMEM_SCREENS ||
        h->plane_dim != QRMEM_PLANE_DIM || h->block_dim != QRMEM_BLOCK_DIM ||
        h->slots_per_block != QRMEM_SLOTS_PER_BLOCK ||
        h->plane_count != QRMEM_PLANE_COUNT) {
        set_err(err, errlen,
                "fabric geometry %ux%u plane, %ux%u blocks, %u slots per "
                "block, %u planes, %u screens; this build expects %ux%u, %ux%u, %u, %u, %u; "
                "refusing",
                h->plane_dim, h->plane_dim, h->block_dim, h->block_dim,
                h->slots_per_block, h->plane_count, h->screen_count, QRMEM_PLANE_DIM,
                QRMEM_PLANE_DIM, QRMEM_BLOCK_DIM, QRMEM_BLOCK_DIM,
                QRMEM_SLOTS_PER_BLOCK, QRMEM_PLANE_COUNT, QRMEM_SCREENS);
        return -1;
    }
    if (h->total_bytes != (uint64_t)QRMEM_APERTURE_BYTES ||
        ap->bytes != (size_t)h->total_bytes) {
        set_err(err, errlen,
                "fabric size %llu does not match mapped %zu; refusing",
                (unsigned long long)h->total_bytes, ap->bytes);
        return -1;
    }
    return 0;
}

int qrmem_aperture_create(qrmem_ap_t *ap, const char *path, char *err,
                          size_t errlen) {
    int fd;
    void *base;
    if (!ap || !path || !path[0]) {
        set_err(err, errlen, "aperture create needs a path");
        return -1;
    }
    if (!layout_sane(err, errlen) || !atomics_usable(err, errlen))
        return -1;
    memset(ap, 0, sizeof *ap);
    ap->fd = -1;
    snprintf(ap->path, sizeof ap->path, "%s", path);

    fd = shm_open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) {
        /* An existing segment is a live fabric, not an error to overwrite. The
         * caller decides: attach to it, or stop and remove it deliberately. */
        set_err(err, errlen, "cannot create %s: %s%s", path, strerror(errno),
                errno == EEXIST ? " (a fabric already exists there; attach to it "
                                  "or remove it deliberately)"
                                : "");
        return -1;
    }
    if (ftruncate(fd, (off_t)QRMEM_APERTURE_BYTES) != 0) {
        set_err(err, errlen, "cannot size %s to %zu bytes: %s", path,
                (size_t)QRMEM_APERTURE_BYTES, strerror(errno));
        close(fd);
        shm_unlink(path);
        return -1;
    }
    base = mmap(NULL, QRMEM_APERTURE_BYTES, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        set_err(err, errlen, "cannot map %s: %s", path, strerror(errno));
        close(fd);
        shm_unlink(path);
        return -1;
    }
    ap->base = (unsigned char *)base;
    ap->bytes = QRMEM_APERTURE_BYTES;
    ap->fd = fd;
    ap->creator = 1;
    ap_bind(ap);

    memset(ap->base, 0, ap->bytes);
    ap->hdr->magic = QRMEM_MAGIC;
    ap->hdr->abi_major = QRMEM_ABI_MAJOR;
    ap->hdr->abi_minor = QRMEM_ABI_MINOR;
    ap->hdr->hdr_bytes = QRMEM_HDR_BYTES;
    ap->hdr->byte_order = native_order();
    ap->hdr->screen_count = QRMEM_SCREENS;
    ap->hdr->plane_dim = QRMEM_PLANE_DIM;
    ap->hdr->block_dim = QRMEM_BLOCK_DIM;
    ap->hdr->slots_per_block = QRMEM_SLOTS_PER_BLOCK;
    ap->hdr->plane_count = QRMEM_PLANE_COUNT;
    ap->hdr->total_bytes = (uint64_t)QRMEM_APERTURE_BYTES;
    /* Mint the fabric identity exactly once, here, while the fabric is still
     * private to this process and there is no possibility of a second writer
     * observing a half-initialised id.
     *
     * The source is getrandom(2) via qrmem_uuid_mint. Nothing local is mixed in
     * and nothing local is derived from: the aperture pathname is IDENTICAL on
     * every host, so an id derived from it would hand three different fabrics
     * the same name; the hostname is descriptive and renameable; the uid is
     * shared by every process on the machine; and screen contents change as
     * people write, so an identity derived from them would move whenever the
     * thing it identifies moved. A random UUID is the only source actually
     * independent of all four. */
    if (qrmem_uuid_mint(&ap->hdr->fabric_id, err, errlen) != 0) {
        close(fd);
        shm_unlink(path);
        return -1;
    }
    /* Draw the code plane's structure now, while the fabric is still private to
     * the creating process. Doing it here rather than lazily means no reader
     * ever sees a half-drawn surface, and an empty screen still looks like
     * memory rather than like a blank rectangle. */
    if (qrmem_plane_init(ap) != 0) {
        set_err(err, errlen, "could not draw the code plane");
        return -1;
    }
    /* Epoch and era start at 1: zero is reserved to mean "never issued", so a
     * participant that reads 0 knows it is looking at uninitialised shared
     * memory rather than a real state. */
    atomic_store_explicit(&ap->hdr->fabric_epoch, 1u, memory_order_release);
    atomic_store_explicit(&ap->hdr->heartbeat_seq, 1u, memory_order_release);
    atomic_store_explicit(&ap->hdr->handle_era, 1u, memory_order_release);
    /* Authority generation starts at 1 for the same reason era does: zero means
     * "never issued". It has to be non-zero from the moment the fabric exists,
     * not only after the first restart, because a client that leases from a
     * daemon which has never restarted still gets a real fence. A freshly
     * created fabric that reported authority_gen 0 would have every one of its
     * own leases rejected as stale. */
    atomic_store_explicit(&ap->hdr->authority_gen, 1u, memory_order_release);
    atomic_store_explicit(&ap->hdr->handle_seq, 0u, memory_order_release);
    atomic_store_explicit(&ap->hdr->agent_count, 0u, memory_order_release);
    for (uint32_t s = 0; s < QRMEM_SCREENS; s++) {
        atomic_store_explicit(&ap->screens[s].generation, 0u,
                              memory_order_release);
        atomic_store_explicit(&ap->screens[s].owner, 0u, memory_order_release);
        atomic_store_explicit(&ap->screens[s].owner_era,
                              atomic_load_explicit(&ap->hdr->handle_era,
                                                   memory_order_acquire),
                              memory_order_release);
    }
    return 0;
}

int qrmem_aperture_attach(qrmem_ap_t *ap, const char *path, char *err,
                          size_t errlen) {
    struct stat st;
    int fd;
    void *base;
    if (!ap || !path || !path[0]) {
        set_err(err, errlen, "aperture attach needs a path");
        return -1;
    }
    if (!layout_sane(err, errlen))
        return -1;
    memset(ap, 0, sizeof *ap);
    ap->fd = -1;
    snprintf(ap->path, sizeof ap->path, "%s", path);

    fd = shm_open(path, O_RDWR, 0600);
    if (fd < 0) {
        set_err(err, errlen, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0) {
        set_err(err, errlen, "cannot stat %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    if ((uint64_t)st.st_size != (uint64_t)QRMEM_APERTURE_BYTES) {
        set_err(err, errlen,
                "%s is %llu bytes, this build requires %zu; refusing to map a "
                "segment it cannot describe",
                path, (unsigned long long)st.st_size,
                (size_t)QRMEM_APERTURE_BYTES);
        close(fd);
        return -1;
    }
    base = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                fd, 0);
    if (base == MAP_FAILED) {
        set_err(err, errlen, "cannot map %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    ap->base = (unsigned char *)base;
    ap->bytes = (size_t)st.st_size;
    ap->fd = fd;
    ap_bind(ap);
    if (hdr_validate(ap, err, errlen) != 0) {
        munmap(ap->base, ap->bytes);
        close(fd);
        memset(ap, 0, sizeof *ap);
        ap->fd = -1;
        return -1;
    }
    if (!atomics_usable(err, errlen)) {
        munmap(ap->base, ap->bytes);
        close(fd);
        memset(ap, 0, sizeof *ap);
        ap->fd = -1;
        return -1;
    }
    atomic_fetch_add_explicit(&ap->hdr->heartbeat_seq, 1u,
                              memory_order_release);
    return 0;
}

int qrmem_aperture_detach(qrmem_ap_t *ap) {
    if (!ap)
        return -1;
    if (ap->base)
        munmap(ap->base, ap->bytes);
    if (ap->fd >= 0)
        close(ap->fd);
    memset(ap, 0, sizeof *ap);
    ap->fd = -1;
    return 0;
}

void qrmem_aperture_unlink(const char *path) {
    if (path && path[0])
        shm_unlink(path);
}

void qrmem_aperture_bump_epoch(qrmem_ap_t *ap) {
    uint32_t era;
    /* NOT gated on `creator`.
     *
     * This used to be, and that was correct only while the daemon deleted its
     * own aperture on exit: every start was a first start, so creator was always
     * true. Now the segment deliberately outlives the process and a restarting
     * daemon ATTACHES, so the creator flag is false - and gating on it skipped
     * the authority bump AND the lease_hold zeroing below, on every restart.
     *
     * The zeroing is the dangerous part: those are phantom counts inherited from
     * a daemon whose socket is gone, and leaving them in place is exactly what
     * wedges a fabric into screens with owners and a registry with nobody. It
     * was previously unreachable only because attach never reached here.
     *
     * SAFETY: only the DAEMON may call this, from its bind. Clients attach
     * without calling it, because a client bumping authority_gen would retire
     * every other agent's lease - which would make the fabric unusable the
     * moment a second agent connected. */
    if (!ap || !ap->hdr)
        return;
    atomic_fetch_add_explicit(&ap->hdr->fabric_epoch, 1u, memory_order_acq_rel);
    /* A restart is a new era. Advancing it invalidates every outstanding
     * handle at once: validity is era EQUALITY, not a comparison against a
     * floor, so nothing minted earlier can be mistaken for something minted
     * now. */
    era = atomic_fetch_add_explicit(&ap->hdr->handle_era, 1u,
                                    memory_order_acq_rel) +
          1u;
    atomic_store_explicit(&ap->hdr->handle_seq, 0u, memory_order_release);
    /* A restart is also a new authority incarnation. Every lease, screen
     * claim and client triple from a previous daemon is stale by
     * definition: no connection counted by that daemon can still be open,
     * because the socket it was connected to died with it. Inherited
     * lease_hold values are therefore phantom counts, not live leases,
     * and are zeroed rather than trusted - trusting them is what wedged
     * the fabric into screens with owners and a registry with nobody. */
    atomic_fetch_add_explicit(&ap->hdr->authority_gen, 1u,
                              memory_order_acq_rel);
    for (uint32_t i = 0; i < QRMEM_AGENT_MAX; i++) {
        atomic_store_explicit(&ap->hdr->agents[i].lease_hold, 0u,
                              memory_order_release);
        /* Presence timestamps are lease-scoped, so they die with the leases. */
        atomic_store_explicit(&ap->hdr->agents[i].connected_since, 0u,
                              memory_order_release);
    }
    for (uint32_t s = 0; s < QRMEM_SCREENS; s++)
        atomic_store_explicit(&ap->screens[s].owner_era, era,
                              memory_order_release);
}

/* Ownership. One writer per screen, chosen first-come. A claim by the current
 * owner is idempotent so a reconnecting agent does not have to remember
 * whether it already held the tile. */
/* Load the full ownership triple. Caller validates. */
static void owner_load(const qrmem_ap_t *ap, uint32_t screen, uint32_t *slot,
                       uint64_t *authority_gen, uint32_t *agent_gen) {
    *slot = atomic_load_explicit(&ap->screens[screen].owner,
                                 memory_order_acquire);
    *agent_gen = atomic_load_explicit(&ap->screens[screen].owner_agent_gen,
                                      memory_order_acquire);
    *authority_gen = atomic_load_explicit(
        &ap->screens[screen].owner_authority_gen, memory_order_acquire);
}

/* A pause, not a yield: the holder is doing a handful of stores, so
 * scheduling would cost more than spinning. */
static void cpu_relax(void) {
#if defined(__i386__) || defined(__x86_64__)
    __builtin_ia32_pause();
#elif defined(__aarch64__) || defined(__arm__)
    __asm__ __volatile__("yield" ::: "memory");
#endif
}

/* Serialise claims on one screen. Rare enough that a spin lock is the right
 * trade against the alternative, which is torn ownership metadata. A lock
 * word left stuck by a process killed mid-claim would wedge the screen, so
 * the wait is bounded and then refused rather than hung. */
#define QRMEM_CLAIM_LOCK_SPINS 200000u

static int screen_claim_lock(qrmem_ap_t *ap, uint32_t screen, char *err,
                             size_t errlen) {
    uint32_t spins = 0;
    while (atomic_compare_exchange_weak_explicit(
        &ap->screens[screen].claim_lock, &(uint32_t){0}, 1u,
        memory_order_acquire, memory_order_relaxed)) {
        return 0;
    }
    while (atomic_load_explicit(&ap->screens[screen].claim_lock,
                                memory_order_relaxed) != 0u) {
        if (++spins > QRMEM_CLAIM_LOCK_SPINS) {
            set_err(err, errlen,
                    "screen %u is mid-claim by another agent and did not settle; "
                    "retry once it has finished",
                    screen);
            return -1;
        }
        cpu_relax();
    }
    while (!atomic_compare_exchange_weak_explicit(
        &ap->screens[screen].claim_lock, &(uint32_t){0}, 1u,
        memory_order_acquire, memory_order_relaxed)) {
        if (++spins > QRMEM_CLAIM_LOCK_SPINS) {
            set_err(err, errlen,
                    "screen %u is mid-claim by another agent and did not settle",
                    screen);
            return -1;
        }
        cpu_relax();
    }
    return 0;
}

static void screen_claim_unlock(qrmem_ap_t *ap, uint32_t screen) {
    atomic_store_explicit(&ap->screens[screen].claim_lock, 0u,
                          memory_order_release);
}

int qrmem_screen_claim(qrmem_ap_t *ap, uint32_t screen, qrmem_id_t id,
                       const char *project, char *err, size_t errlen) {
    uint32_t expect = 0;
    uint32_t cur, cur_gen;
    uint64_t cur_auth;
    size_t plen = 0;
    if (!ap || !ap->hdr) {
        set_err(err, errlen, "no fabric attached");
        return -1;
    }
    if (!qrmem_screen_valid(screen)) {
        set_err(err, errlen, "screen %u does not exist (0..%u)", screen,
                QRMEM_SCREENS - 1u);
        return -1;
    }
    if (id.slot == 0 || id.slot > QRMEM_AGENT_MAX) {
        set_err(err, errlen, "an agent slot is required to own a screen");
        return -1;
    }
    if (project && project[0]) {
        plen = strlen(project);
        if (plen > QRMEM_PROJECT_MAX) {
            set_err(err, errlen,
                    "project label is %zu bytes, limit is %u; refused, never "
                    "truncated",
                    plen, QRMEM_PROJECT_MAX);
            return -1;
        }
    }
    if (screen_claim_lock(ap, screen, err, errlen) != 0)
        return -1;
    owner_load(ap, screen, &cur, &cur_auth, &cur_gen);
    if (cur != 0) {
        /* Owned. Idempotent iff the FULL triple matches: same slot with a
         * different generation is a different agent and inherits nothing. */
        if (cur != id.slot || cur_auth != id.authority_gen ||
            cur_gen != id.agent_gen) {
            set_err(err, errlen,
                    "screen %u already has a writer; a tile belongs to one "
                    "writer",
                    screen);
            screen_claim_unlock(ap, screen);
            return -1;
        }
        /* Already mine. A different project label is a correction while
         * the screen is empty, and history-rewriting once work exists. */
        if (plen > 0) {
            uint32_t have_len = atomic_load_explicit(
                &ap->screens[screen].project_len, memory_order_acquire);
            int same = have_len == (uint32_t)plen &&
                       memcmp(ap->screens[screen].project, project,
                              plen) == 0;
            if (!same) {
                uint64_t published = atomic_load_explicit(
                    &ap->screens[screen].write_count, memory_order_acquire);
                if (published > 0) {
                    set_err(err, errlen,
                            "screen %u already belongs to a page with "
                            "published records; open a new page instead of "
                            "rewriting what it was about",
                            screen);
                    screen_claim_unlock(ap, screen);
                    return -1;
                }
                memcpy(ap->screens[screen].project, project, plen);
                atomic_store_explicit(&ap->screens[screen].project_len,
                                      (uint32_t)plen, memory_order_release);
            }
        }
        screen_claim_unlock(ap, screen);
        return 0;
    }
    /* Free: no live owner. Under the claim lock, so no other claimer can
     * interleave its metadata with ours. Publish project and generation BEFORE
     * the owner, so any reader that sees our slot also sees the triple that
     * makes it ours. The compare-and-swap below is now a backstop rather than
     * the arbiter: it cannot lose, because the only writer that could take the
     * screen has to hold this lock and we hold it.
     *
     * FREE DOES NOT MEAN EMPTY, and that distinction is the bug this comment
     * exists to prevent.
     *
     * A restored page arrives with records and a project label but NO OWNER,
     * because restoring an owner would hand write authority to whoever claimed
     * it next. So the first post-restore join lands HERE rather than in the
     * branch above, and this branch used to write the label unconditionally.
     * The immutability guard lived only in the already-owned branch, which
     * meant the ONE claim that mattered most - the one that takes over a
     * populated page - was the one claim that could relabel it freely.
     *
     * Observed, on a live host: a restored screen carrying 11 records labelled
     * `saphira-expanderllm` was relabelled to `relabel-probe` by its first
     * post-restore join, and the normal guard then refused to change it back
     * because the page had published records. One-directional metadata damage
     * with no agent-level repair path.
     *
     * So the same guard runs here. The predicate is RESTORED CONTENT - the
     * write count the snapshot carried - not whether a post-restart writer has
     * touched the screen, which is what made the live case look fine. */
    if (plen > 0) {
        uint32_t have_len = atomic_load_explicit(
            &ap->screens[screen].project_len, memory_order_acquire);
        int same = have_len == (uint32_t)plen &&
                   memcmp(ap->screens[screen].project, project, plen) == 0;
        if (!same) {
            uint64_t published = atomic_load_explicit(
                &ap->screens[screen].write_count, memory_order_acquire);
            if (published > 0) {
                char have[QRMEM_PROJECT_MAX + 1];
                uint32_t hl = have_len > QRMEM_PROJECT_MAX ? QRMEM_PROJECT_MAX
                                                            : have_len;
                memcpy(have, ap->screens[screen].project, hl);
                have[hl] = '\0';
                /* Two REAL doors, or none.
                 *
                 * The previous wording here interpolated the CALLER'S label:
                 * "Claim it with project X", where X was the project they had
                 * just passed. A client that had already done exactly that was
                 * told to retry the call that had just failed, and since
                 * qrmem_join exposes no force or relabel parameter, the only
                 * actionable half was "open a new screen".
                 *
                 * A refusal that points at a door the API does not have is worse
                 * than a bare refusal, because it costs the caller a round trip
                 * to learn the same thing twice. So: state the immutable label,
                 * say the page can still be claimed under it, and name the ONE
                 * path that can change a label at all.
                 *
                 * Recovery stays operator-only by decision. An agent given a way
                 * back would be a second, softer label-mutation path competing
                 * with the audited one - and the whole reason the audited path
                 * exists is that a wrong label was otherwise irreversible. */
                set_err(err, errlen,
                        "screen %u carries %llu published record%s, so its "
                        "project label is now fixed at \"%s\". It is unclaimed, "
                        "not empty: you may take it, but only under that same "
                        "label. If the label is believed wrong, no agent can "
                        "change it - an operator can, audited, with "
                        "saphira-qrmem --repair-project %u --project LABEL.",
                        screen, (unsigned long long)published,
                        published == 1u ? "" : "s", have, screen);
                screen_claim_unlock(ap, screen);
                return -1;
            }
            memcpy(ap->screens[screen].project, project, plen);
            atomic_store_explicit(&ap->screens[screen].project_len,
                                  (uint32_t)plen, memory_order_release);
        }
    }
    atomic_store_explicit(&ap->screens[screen].owner_authority_gen,
                          id.authority_gen, memory_order_release);
    atomic_store_explicit(&ap->screens[screen].owner_agent_gen, id.agent_gen,
                          memory_order_release);
    if (!atomic_compare_exchange_strong_explicit(
            &ap->screens[screen].owner, &expect, id.slot,
            memory_order_acq_rel, memory_order_acquire)) {
        set_err(err, errlen,
                "screen %u was claimed first; a tile belongs to one writer",
                screen);
        screen_claim_unlock(ap, screen);
        return -1;
    }
    atomic_store_explicit(&ap->screens[screen].owner_authority_gen,
                          id.authority_gen, memory_order_release);
    atomic_store_explicit(&ap->screens[screen].owner_agent_gen, id.agent_gen,
                          memory_order_release);
    atomic_store_explicit(&ap->screens[screen].owner_era,
                          atomic_load_explicit(&ap->hdr->handle_era,
                                               memory_order_acquire),
                          memory_order_release);
    screen_claim_unlock(ap, screen);
    qrmem_op_end(ap, screen);
    return 0;
}

/* The single-writer gate, validated twice: owner, then generations, then
 * owner again. A stale triple can never grant authority, and a torn read
 * can only refuse, never wrongly succeed: the generations in the cell
 * belong to whoever last claimed it, and only a live claim by this exact
 * triple writes this triple. Returns 1 when `id` may write, 0 otherwise. */
static int triple_owns(const qrmem_ap_t *ap, uint32_t screen, qrmem_id_t id) {
    uint32_t o1, gen;
    uint64_t auth;
    if (id.slot == 0)
        return 0;
    o1 = atomic_load_explicit(&ap->screens[screen].owner,
                              memory_order_acquire);
    if (o1 != id.slot)
        return 0;
    gen = atomic_load_explicit(&ap->screens[screen].owner_agent_gen,
                               memory_order_acquire);
    auth = atomic_load_explicit(&ap->screens[screen].owner_authority_gen,
                                memory_order_acquire);
    if (atomic_load_explicit(&ap->screens[screen].owner,
                             memory_order_acquire) != id.slot)
        return 0;
    return gen == id.agent_gen && auth == id.authority_gen;
}

int qrmem_screen_release(qrmem_ap_t *ap, uint32_t screen, qrmem_id_t id,
                         char *err, size_t errlen) {
    uint32_t expect;
    if (!ap || !ap->hdr) {
        set_err(err, errlen, "no fabric attached");
        return -1;
    }
    if (!qrmem_screen_valid(screen)) {
        set_err(err, errlen, "screen %u does not exist (0..%u)", screen,
                QRMEM_SCREENS - 1u);
        return -1;
    }
    /* Exact triple first: releasing what a predecessor owned would free a
     * screen that is no longer yours. Then CAS on the slot: if the owner
     * moved under us, the release fails rather than freeing another's tile. */
    if (!triple_owns(ap, screen, id)) {
        set_err(err, errlen, "screen %u is not yours to release", screen);
        return -1;
    }
    expect = id.slot;
    if (!atomic_compare_exchange_strong_explicit(
            &ap->screens[screen].owner, &expect, 0u, memory_order_acq_rel,
            memory_order_acquire)) {
        set_err(err, errlen, "screen %u is not yours to release", screen);
        return -1;
    }
    qrmem_op_end(ap, screen);
    return 0;
}

int qrmem_screen_writable(const qrmem_ap_t *ap, uint32_t screen,
                          qrmem_id_t id) {
    if (!ap || !ap->hdr || !qrmem_screen_valid(screen))
        return 0;
    return triple_owns(ap, screen, id);
}

int qrmem_require_owner(const qrmem_ap_t *ap, uint32_t screen, qrmem_id_t id,
                        char *err, size_t errlen) {
    if (!ap || !ap->hdr) {
        set_err(err, errlen, "no fabric attached");
        return -1;
    }
    if (!qrmem_screen_valid(screen)) {
        set_err(err, errlen, "screen %u does not exist (0..%u)", screen,
                QRMEM_SCREENS - 1u);
        return -1;
    }
    if (id.slot == 0) {
        set_err(err, errlen,
                "no agent identity: join the fabric before writing a tile");
        return -1;
    }
    if (!triple_owns(ap, screen, id)) {
        set_err(err, errlen, "screen %u is not yours to write", screen);
        return -1;
    }
    return 0;
}

/* Agent registry.
 *
 * Find-or-allocate by EXACT name. Never by hash: a hashed slot merges two
 * colliding identities into one, and the loser then passes the idempotent
 * "already mine" claim check and writes the winner's tile. That is precisely
 * the bug this table exists to make impossible.
 *
 * The name is written before in_use is published, so a slot that reads as in use
 * always has its name visible to whoever reads it next. */
int qrmem_agent_claim(qrmem_ap_t *ap, const char *agent_id, uint32_t *slot_out,
                      uint32_t *gen_out, char *err, size_t errlen) {
    uint32_t free_slot = QRMEM_AGENT_MAX;
    size_t nlen;
    if (!ap || !ap->hdr || !agent_id || !slot_out) {
        set_err(err, errlen, "agent claim needs a fabric, a name and a slot");
        return -1;
    }
    nlen = strlen(agent_id);
    if (nlen == 0 || nlen >= QRMEM_AGENT_NAME_MAX) {
        set_err(err, errlen, "agent name length %zu is out of range (1..%u)",
                nlen, QRMEM_AGENT_NAME_MAX - 1u);
        return -1;
    }
    for (uint32_t i = 0; i < QRMEM_AGENT_MAX; i++) {
        if (atomic_load_explicit(&ap->hdr->agents[i].in_use,
                                 memory_order_acquire) == 0u) {
            if (free_slot == QRMEM_AGENT_MAX)
                free_slot = i;
            continue;
        }
        if (!strcmp(ap->hdr->agents[i].name, agent_id)) {
            *slot_out = i + 1u;
            /* A reconnecting identity gets a NEW generation, even though
             * the slot and name are the same. Its old screens, if any
             * survived, will not match the new triple, so it must claim
             * explicitly rather than inheriting silently. */
            if (gen_out) {
                *gen_out = atomic_fetch_add_explicit(
                    &ap->hdr->agents[i].alloc_gen, 1u,
                    memory_order_acq_rel) + 1u;
            }
            /* Origin is re-stamped on every claim, including reconnects: the
             * only claim path in this build is the daemon's own control
             * socket, so LOCAL is a fact about how we got here, not a string
             * anyone supplied. A slot reused across builds never inherits a
             * previous occupant's source. */
            ap->hdr->agent_origin_kind[i] = QRMEM_ORIGIN_LOCAL;
            qrmem_agent_touch(ap, *slot_out);
            return 0;
        }
    }
    if (free_slot == QRMEM_AGENT_MAX) {
        set_err(err, errlen,
                "the fabric already has %u agents; refusing to merge another "
                "identity into an existing one",
                QRMEM_AGENT_MAX);
        return -1;
    }
    snprintf(ap->hdr->agents[free_slot].name, QRMEM_AGENT_NAME_MAX, "%s",
             agent_id);
    /* A fresh allocation has never been leased. Set BEFORE in_use so a reader
     * that sees the slot in use also sees a meaningful connected_since. */
    atomic_store_explicit(&ap->hdr->agents[free_slot].connected_since, 0u,
                          memory_order_release);
    /* First allocation of this slot in this aperture lifetime starts at 1;
     * every later allocation increments. 0 means never allocated, so no
     * occupant can share a generation with a predecessor by accident. */
    if (gen_out) {
        *gen_out = atomic_fetch_add_explicit(
            &ap->hdr->agents[free_slot].alloc_gen, 1u,
            memory_order_acq_rel) + 1u;
        if (*gen_out == 0u)
            *gen_out = atomic_fetch_add_explicit(
                &ap->hdr->agents[free_slot].alloc_gen, 1u,
                memory_order_acq_rel) + 1u;
    }
    /* Release, and last: the name above is visible to anyone who sees this. */
    ap->hdr->agent_origin_kind[free_slot] = QRMEM_ORIGIN_LOCAL;
    atomic_store_explicit(&ap->hdr->agents[free_slot].in_use, 1u,
                          memory_order_release);
    atomic_fetch_add_explicit(&ap->hdr->agent_count, 1u, memory_order_acq_rel);
    *slot_out = free_slot + 1u;
    qrmem_agent_touch(ap, *slot_out);
    return 0;
}

int qrmem_agent_name(const qrmem_ap_t *ap, uint32_t slot, char *out,
                     size_t out_len) {
    if (!ap || !ap->hdr || !out || !out_len || slot == 0 ||
        slot > QRMEM_AGENT_MAX)
        return -1;
    if (atomic_load_explicit(&ap->hdr->agents[slot - 1u].in_use,
                             memory_order_acquire) == 0u)
        return -1;
    snprintf(out, out_len, "%s", ap->hdr->agents[slot - 1u].name);
    return 0;
}

void qrmem_agent_touch(qrmem_ap_t *ap, uint32_t slot) {
    struct timespec ts;
    if (!ap || !ap->hdr || slot == 0 || slot > QRMEM_AGENT_MAX)
        return;
    if (atomic_load_explicit(&ap->hdr->agents[slot - 1u].in_use,
                             memory_order_acquire) == 0u)
        return;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    atomic_store_explicit(&ap->hdr->agents[slot - 1u].last_seen_ns,
                          (uint64_t)ts.tv_sec * 1000000000ull +
                              (uint64_t)ts.tv_nsec,
                          memory_order_release);
}

/* Drop every screen held by EXACTLY this identity, then free the slot.
 *
 * Order is the whole point and the sweep already got it right while this
 * function got it wrong: a slot number is reused by the next allocation, so
 * freeing the slot while a screen still names it would hand that agent's WRITE
 * AUTHORITY to whoever drew the number next. The one-writer guarantee would
 * then belong to nobody.
 *
 * Matching is on the full triple, not the slot: a screen naming this slot
 * under a different generation belongs to someone else (or to nobody) and is
 * left alone here. The sweep's screen walk handles those.
 *
 * The cells themselves stay readable; only the right to write goes away. */
static void drop_screens_of(qrmem_ap_t *ap, qrmem_id_t id) {
    for (uint32_t s = 0; s < QRMEM_SCREENS; s++) {
        uint32_t o1, gen;
        uint64_t auth;
        o1 = atomic_load_explicit(&ap->screens[s].owner,
                                  memory_order_acquire);
        if (o1 != id.slot)
            continue;
        gen = atomic_load_explicit(&ap->screens[s].owner_agent_gen,
                                   memory_order_acquire);
        auth = atomic_load_explicit(&ap->screens[s].owner_authority_gen,
                                    memory_order_acquire);
        if (gen != id.agent_gen || auth != id.authority_gen)
            continue;
        if (atomic_load_explicit(&ap->screens[s].owner,
                                 memory_order_acquire) != id.slot)
            continue;
        uint32_t expect = id.slot;
        if (atomic_compare_exchange_strong_explicit(
                &ap->screens[s].owner, &expect, 0u, memory_order_acq_rel,
                memory_order_acquire)) {
            qrmem_op_end(ap, s);
        }
    }
}

/* Reapable means UNLEASED and long unseen.
 *
 * The lease is checked first and it is absolute: a slot holding a live
 * connection is never reapable, however old its heartbeat, because the open
 * connection is the proof of life. Only once the lease is gone does the
 * heartbeat decide whether what is left is abandoned or merely young - a slot
 * can be unleased because its owner has not connected yet, and freeing that on
 * sight would make claiming a tile a race. */
static int agent_is_stale(const qrmem_ap_t *ap, uint32_t i, uint64_t now,
                          uint64_t max_age_ns) {
    uint64_t seen;
    if (atomic_load_explicit(&ap->hdr->agents[i].lease_hold,
                             memory_order_acquire) != 0u)
        return 0; /* leased: alive, full stop */
    seen = atomic_load_explicit(&ap->hdr->agents[i].last_seen_ns,
                                memory_order_acquire);
    if (seen == 0u)
        return 1; /* predates heartbeats: stale rather than immortal */
    return now > seen && now - seen > max_age_ns;
}

static uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* The identity this slot holds RIGHT NOW. Any screen naming a different
 * triple names a different agent - or nobody - even if the slot matches. */
static qrmem_id_t slot_triple(const qrmem_ap_t *ap, uint32_t slot) {
    qrmem_id_t id;
    id.authority_gen = atomic_load_explicit(&ap->hdr->authority_gen,
                                            memory_order_acquire);
    id.slot = slot;
    id.agent_gen = (slot == 0 || slot > QRMEM_AGENT_MAX) ? 0u :
        atomic_load_explicit(&ap->hdr->agents[slot - 1u].alloc_gen,
                             memory_order_acquire);
    return id;
}

/* The allocation generation this slot currently holds. Exposed because presence
 * has to report it and deriving it from the slot number is exactly the mistake
 * the fence exists to prevent. 0 means the slot is not allocated. */
uint32_t qrmem_agent_generation_of(const qrmem_ap_t *ap, uint32_t slot) {
    if (!ap || !ap->hdr || slot == 0 || slot > QRMEM_AGENT_MAX)
        return 0u;
    if (atomic_load_explicit(&ap->hdr->agents[slot - 1u].in_use,
                             memory_order_acquire) == 0u)
        return 0u;
    return atomic_load_explicit(&ap->hdr->agents[slot - 1u].alloc_gen,
                                memory_order_acquire);
}

uint32_t qrmem_agent_sweep(qrmem_ap_t *ap, uint64_t max_age_ns) {
    uint32_t reclaimed = 0;
    uint64_t now;
    if (!ap || !ap->hdr)
        return 0;
    now = monotonic_ns();
    for (uint32_t i = 0; i < QRMEM_AGENT_MAX; i++) {
        if (atomic_load_explicit(&ap->hdr->agents[i].in_use,
                                 memory_order_acquire) == 0u)
            continue;
        if (!agent_is_stale(ap, i, now, max_age_ns))
            continue;
        drop_screens_of(ap, slot_triple(ap, i + 1u));
        atomic_store_explicit(&ap->hdr->agents[i].in_use, 0u,
                              memory_order_release);
        atomic_fetch_sub_explicit(&ap->hdr->agent_count, 1u,
                                  memory_order_acq_rel);
        reclaimed++;
    }
    /* Screen walk: ownership the slot walk cannot see. A screen whose
     * triple matches no live allocation is an orphan by definition -
     * previous daemon, freed slot, or reallocated slot - and is freed
     * directly instead of waiting for its number to come up again.
     * Content stays readable; only the dangling write authority goes. */
    for (uint32_t s = 0; s < QRMEM_SCREENS; s++) {
        uint32_t owner, gen, cur_gen;
        uint64_t auth, cur_auth;
        uint32_t expect;
        owner_load(ap, s, &owner, &auth, &gen);
        if (owner == 0)
            continue;
        cur_auth = atomic_load_explicit(&ap->hdr->authority_gen,
                                        memory_order_acquire);
        if (auth == cur_auth && owner <= QRMEM_AGENT_MAX &&
            atomic_load_explicit(&ap->hdr->agents[owner - 1u].in_use,
                                 memory_order_acquire) != 0u) {
            cur_gen = atomic_load_explicit(
                &ap->hdr->agents[owner - 1u].alloc_gen,
                memory_order_acquire);
            if (cur_gen == gen)
                continue;
        }
        expect = owner;
        if (atomic_compare_exchange_strong_explicit(
                &ap->screens[s].owner, &expect, 0u, memory_order_acq_rel,
                memory_order_acquire)) {
            qrmem_op_end(ap, s);
            reclaimed++;
        }
    }
    return reclaimed;
}

uint32_t qrmem_agent_reclaimable(const qrmem_ap_t *ap, uint64_t max_age_ns) {
    uint64_t now;
    uint32_t n = 0;
    if (!ap || !ap->hdr)
        return 0;
    now = monotonic_ns();
    for (uint32_t i = 0; i < QRMEM_AGENT_MAX; i++) {
        if (atomic_load_explicit(&ap->hdr->agents[i].in_use,
                                 memory_order_acquire) == 0u)
            continue;
        if (agent_is_stale(ap, i, now, max_age_ns))
            n++;
    }
    return n;
}

uint32_t qrmem_agent_count(const qrmem_ap_t *ap) {
    if (!ap || !ap->hdr)
        return 0;
    return atomic_load_explicit(&ap->hdr->agent_count, memory_order_acquire);
}

void qrmem_agent_release(qrmem_ap_t *ap, uint32_t slot) {
    if (!ap || !ap->hdr || slot == 0 || slot > QRMEM_AGENT_MAX)
        return;
    if (atomic_load_explicit(&ap->hdr->agents[slot - 1u].in_use,
                             memory_order_acquire) == 0u)
        return;
    /* Screens first. See drop_screens_of for why the order is not cosmetic. */
    drop_screens_of(ap, slot_triple(ap, slot));
    /* Unpublish the name last, so a concurrent lookup cannot read a half-freed
     * slot. The bytes stay in place: a stale name is harmless, a torn one is
     * not. */
    atomic_store_explicit(&ap->hdr->agents[slot - 1u].in_use, 0u,
                          memory_order_release);
    /* Origin goes back to unknown with the slot: the next occupant must earn
     * its own source stamp at claim time rather than inheriting this one. */
    ap->hdr->agent_origin_kind[slot - 1u] = QRMEM_ORIGIN_UNKNOWN;
    atomic_store_explicit(&ap->hdr->agents[slot - 1u].connected_since, 0u,
                          memory_order_release);
    atomic_store_explicit(&ap->hdr->agents[slot - 1u].lease_hold, 0u,
                          memory_order_release);
    atomic_fetch_sub_explicit(&ap->hdr->agent_count, 1u, memory_order_acq_rel);
}

/* Lease accounting. See qrmem.h for why a connection is the authority on
 * liveness and a heartbeat is not. */
void qrmem_agent_lease(qrmem_ap_t *ap, uint32_t slot) {
    uint32_t was;
    if (!ap || !ap->hdr || slot == 0 || slot > QRMEM_AGENT_MAX)
        return;
    if (atomic_load_explicit(&ap->hdr->agents[slot - 1u].in_use,
                             memory_order_acquire) == 0u)
        return;
    was = atomic_fetch_add_explicit(&ap->hdr->agents[slot - 1u].lease_hold, 1u,
                                    memory_order_acq_rel);
    /* connected_since records the FIRST lease of this allocation, so a second
     * connection for the same identity does not reset it and make presence read
     * as though the agent had just arrived. The compare-and-swap rather than a
     * read-then-write: two connections racing on a new slot must not both set
     * it, or the recorded time would be whichever lost the store. */
    if (was == 0u) {
        uint32_t expect = 0u;
        (void)atomic_compare_exchange_strong_explicit(
            &ap->hdr->agents[slot - 1u].connected_since, &expect,
            (uint32_t)(monotonic_ns() / 1000000000ull), memory_order_acq_rel,
            memory_order_relaxed);
    }
    qrmem_agent_touch(ap, slot);
}

void qrmem_agent_unlease(qrmem_ap_t *ap, uint32_t slot) {
    uint32_t held;
    if (!ap || !ap->hdr || slot == 0 || slot > QRMEM_AGENT_MAX)
        return;
    held = atomic_load_explicit(&ap->hdr->agents[slot - 1u].lease_hold,
                                memory_order_acquire);
    if (held == 0u)
        return;
    /* The LAST connection to go takes the agent with it, screens and all. A
     * second connection for the same identity keeps the lease alive on its own,
     * which is what lets a tool open a control socket without disturbing an
     * agent that already holds one. */
    if (held > 1u) {
        atomic_fetch_sub_explicit(&ap->hdr->agents[slot - 1u].lease_hold, 1u,
                                  memory_order_acq_rel);
        return;
    }
    qrmem_agent_release(ap, slot);
}

/* This fabric's identity, as minted by whoever created the aperture.
 *
 * Valid for the life of the aperture: unchanged by a daemon restart, unchanged
 * by authority_gen, and different for every fabric - including fabrics on
 * different machines whose aperture pathname is character-for-character
 * identical. A screen number is meaningless without it, which is why this is
 * READ from the fabric rather than computed from anything local. */
int qrmem_fabric_id(const qrmem_ap_t *ap, qrmem_uuid_t *out) {
    if (!ap || !ap->hdr || !out)
        return -1;
    *out = ap->hdr->fabric_id;
    return qrmem_uuid_is_nil(out) ? -1 : 0;
}

uint32_t qrmem_agent_origin_kind(const qrmem_ap_t *ap, uint32_t slot) {
    uint32_t k;
    if (!ap || !ap->hdr || slot == 0 || slot > QRMEM_AGENT_MAX)
        return QRMEM_ORIGIN_UNKNOWN;
    k = ap->hdr->agent_origin_kind[slot - 1u];
    return k == QRMEM_ORIGIN_LOCAL ? QRMEM_ORIGIN_LOCAL : QRMEM_ORIGIN_UNKNOWN;
}

int qrmem_authority_host(const qrmem_ap_t *ap, char *out, size_t cap) {
    if (!ap || !ap->hdr || !out || !cap)
        return -1;
    if (!ap->hdr->authority_host[0])
        return -1;
    snprintf(out, cap, "%s", ap->hdr->authority_host);
    out[cap - 1u] = '\0';
    return 0;
}

/* Is a fenced triple still recognised by this fabric?
 *
 * EXISTS BECAUSE `agent_slot` IS A CLIENT-LOCAL INTEGER. It is captured once
 * from the hello reply and never revalidated, so after an aperture is replaced
 * under a running client - which `--recreate`, an upgrade, or an operator does
 * legitimately - it refers to a registry that no longer exists, and a newly
 * joined agent can be issued the same number. Status reporting `agent_slot` and
 * `agents` side by side in that state is a self-contradiction the caller has to
 * spot unaided.
 *
 * So the fabric is asked directly, on the FULL triple rather than the slot.
 * The three results are reported separately because the remedy differs and the
 * caller cannot tell them apart from a single boolean:
 *
 *   authority_ok  the lease predates the current daemon incarnation. Every
 *                 fenced write is refused until the client re-leases.
 *   slot_ok       that slot is not allocated in this fabric at all. The
 *                 aperture was replaced, or the registry was swept.
 *   generation_ok the slot is allocated but carries a different allocation
 *                 generation: a different agent, reusing the number.
 *
 * generation_ok is only meaningful when slot_ok is true.
 *
 * This lives here rather than in the MCP layer so it can be tested against
 * forged stale state. An `enrolled` field that only ever reports true is worse
 * than none, and the first version of this check was exactly that.
 */
void qrmem_agent_enrollment_check(const qrmem_ap_t *ap, uint32_t slot,
                                  uint64_t authority_gen, uint32_t agent_gen,
                                  int *authority_ok, int *slot_ok,
                                  int *generation_ok, uint32_t *live_gen) {
    uint64_t live_auth = 0;
    uint32_t gen = 0;
    int a_ok = 0, s_ok = 0, g_ok = 0;
    if (ap && ap->hdr) {
        live_auth = atomic_load_explicit(&ap->hdr->authority_gen,
                                         memory_order_acquire);
        gen = qrmem_agent_generation_of(ap, slot);
    }
    a_ok = (authority_gen != 0u && authority_gen == live_auth);
    s_ok = (slot != 0u && gen != 0u);
    g_ok = s_ok && gen == agent_gen;
    if (authority_ok)
        *authority_ok = a_ok;
    if (slot_ok)
        *slot_ok = s_ok;
    if (generation_ok)
        *generation_ok = g_ok;
    if (live_gen)
        *live_gen = gen;
}

/* How long this agent has been continuously connected, in seconds, against the
 * READER's own monotonic clock. 0 when the agent holds no lease, because an
 * unleased agent is not present and reporting a duration for it would be a
 * number with no referent.
 *
 * Local-host only, for the same reason last_seen_ns is: CLOCK_MONOTONIC means
 * nothing across machines. If the remote leg lands, this field becomes invalid
 * and presence has to come from the authority's own arrival timestamps. */
uint32_t qrmem_agent_connected_seconds(const qrmem_ap_t *ap, uint32_t slot) {
    uint32_t since;
    uint64_t now;
    if (!ap || !ap->hdr || slot == 0 || slot > QRMEM_AGENT_MAX)
        return 0u;
    if (atomic_load_explicit(&ap->hdr->agents[slot - 1u].lease_hold,
                             memory_order_acquire) == 0u)
        return 0u;
    since = atomic_load_explicit(&ap->hdr->agents[slot - 1u].connected_since,
                                 memory_order_acquire);
    if (since == 0u)
        return 0u;
    now = monotonic_ns() / 1000000000ull;
    /* Monotonic cannot go backwards within a boot, but the subtraction is
     * written so a clock that somehow did would report 0 rather than a huge
     * unsigned age. */
    return (now > (uint64_t)since) ? (uint32_t)(now - (uint64_t)since) : 0u;
}

uint32_t qrmem_agent_lease_held(const qrmem_ap_t *ap, uint32_t slot) {
    if (!ap || !ap->hdr || slot == 0 || slot > QRMEM_AGENT_MAX)
        return 0;
    return atomic_load_explicit(&ap->hdr->agents[slot - 1u].lease_hold,
                                memory_order_acquire);
}

/* Occupied index slots, for diagnostics and for the capacity refusal message.
 * A relaxed load is correct here: this is a count for an operator, not a
 * correctness decision, and a stale count cannot make a wrong write happen. */
uint32_t qrmem_index_used(const qrmem_ap_t *ap, uint32_t screen) {
    const qrmem_index_ent_t *t;
    uint32_t n = 0;
    if (!ap || !ap->hdr || !qrmem_screen_valid(screen))
        return 0;
    t = index_table(ap, screen);
    for (uint32_t i = 0; i < QRMEM_INDEX_ENTRIES; i++)
        if (atomic_load_explicit(&t[i].key_hash, memory_order_acquire) != 0u)
            n++;
    return n;
}

uint64_t qrmem_generation(const qrmem_ap_t *ap, uint32_t screen) {
    if (!ap || !ap->hdr || !qrmem_screen_valid(screen))
        return 0;
    return atomic_load_explicit(&ap->screens[screen].generation,
                                memory_order_acquire);
}

uint64_t qrmem_epoch(const qrmem_ap_t *ap) {
    if (!ap || !ap->hdr)
        return 0;
    return atomic_load_explicit(&ap->hdr->fabric_epoch, memory_order_acquire);
}

uint64_t qrmem_write_count(const qrmem_ap_t *ap, uint32_t screen) {
    if (!ap || !ap->hdr || !qrmem_screen_valid(screen))
        return 0;
    return atomic_load_explicit(&ap->screens[screen].write_count,
                                memory_order_acquire);
}

uint32_t qrmem_screen_owner(const qrmem_ap_t *ap, uint32_t screen) {
    if (!ap || !ap->hdr || !qrmem_screen_valid(screen))
        return 0;
    return atomic_load_explicit(&ap->screens[screen].owner, memory_order_acquire);
}

uint32_t qrmem_era(const qrmem_ap_t *ap) {
    if (!ap || !ap->hdr)
        return 0;
    return atomic_load_explicit(&ap->hdr->handle_era, memory_order_acquire);
}

int qrmem_op_begin(qrmem_ap_t *ap, uint32_t screen, uint32_t *gen_out) {
    uint64_t g;
    if (gen_out)
        *gen_out = 0;
    if (!ap || !ap->hdr || !qrmem_screen_valid(screen))
        return -1;
    g = atomic_load_explicit(&ap->screens[screen].generation,
                             memory_order_acquire);
    if (gen_out)
        *gen_out = (uint32_t)(g & 0xFFFFFFFFu);
    return 0;
}

void qrmem_op_end(qrmem_ap_t *ap, uint32_t screen) {
    if (!ap || !ap->hdr || !qrmem_screen_valid(screen))
        return;
    /* Release: every cell this operation published is visible before the
     * generation that claims they are. A reader that trusts the generation has
     * already acquired it, so it cannot read a generation and then miss a cell. */
    atomic_fetch_add_explicit(&ap->screens[screen].generation, 1u,
                              memory_order_release);
    /* The doorbell is written AFTER the generation. A reader that trusts the
     * doorbell must already have acquired the generation; that ordering is the
     * whole point of doing it in this order. */
    atomic_fetch_add_explicit(&ap->screens[screen].notify, 1u,
                              memory_order_release);
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        atomic_store_explicit(
            &ap->screens[screen].heartbeat_ns,
            (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec,
            memory_order_release);
    }
}

/* Handle minting. Era in the high half, sequence in the low; the tokens carry
 * no resource index on purpose, because the fabric already knows the resource
 * and spending half the token on it would halve the space in which tokens must
 * stay unique. */
uint64_t qrmem_handle_mint(qrmem_ap_t *ap) {
    uint32_t seq;
    uint32_t era;
    if (!ap || !ap->hdr)
        return 0;
    seq = atomic_fetch_add_explicit(&ap->hdr->handle_seq, 1u,
                                    memory_order_acq_rel) +
          1u;
    if (seq == 0u) {
        /* The ABA boundary. On its lap, recycling a sequence counter IS a new
         * era: the era advances, which invalidates every handle minted before
         * the lap, and the epoch advances with it, so anything in flight is
         * stale by name too. A pre-lap handle stays invalid for ever even after
         * the low half of its value has been handed out again. */
        era = atomic_fetch_add_explicit(&ap->hdr->handle_era, 1u,
                                        memory_order_acq_rel) +
              1u;
        atomic_store_explicit(&ap->hdr->handle_seq, 1u, memory_order_release);
        atomic_fetch_add_explicit(&ap->hdr->fabric_epoch, 1u,
                                  memory_order_acq_rel);
        for (uint32_t s = 0; s < QRMEM_SCREENS; s++)
            atomic_store_explicit(&ap->screens[s].owner_era, era,
                                  memory_order_release);
        seq = 1u;
    }
    era = atomic_load_explicit(&ap->hdr->handle_era, memory_order_acquire);
    return ((uint64_t)era << 32) | (uint64_t)seq;
}

void qrmem_handle_split(uint64_t h, uint32_t *era, uint32_t *seq) {
    if (era)
        *era = (uint32_t)(h >> 32);
    if (seq)
        *seq = (uint32_t)(h & 0xFFFFFFFFu);
}

int qrmem_handle_valid(const qrmem_ap_t *ap, uint64_t h) {
    uint32_t era, seq;
    if (!ap || !ap->hdr)
        return 0;
    qrmem_handle_split(h, &era, &seq);
    if (era == 0u || seq == 0u)
        return 0; /* never issued */
    return era == atomic_load_explicit(&ap->hdr->handle_era,
                                       memory_order_acquire);
}
