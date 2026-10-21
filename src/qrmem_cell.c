/* Saphira Memory - qrmem cell codec: TLV bodies, publish, read.
 *
 * The publication word is the only synchronisation in this file. A writer
 * fills the whole cell and then release-stores the state; a reader
 * acquire-loads the state before touching anything else. That is the whole
 * rule, and it is why `volatile` appears nowhere.
 *
 * Every decode REJECTS. Nothing here repairs a malformed record, because a
 * silently repaired cell makes a fabric bug look like a working system.
 */
#include "qrmem.h"

#include <stdarg.h>
#include <sched.h>
#include <stdio.h>
#include <sched.h>
#include <string.h>

static void set_err(char *err, size_t errlen, const char *fmt, ...) {
    if (!err || !errlen)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* FNV-1a, incremental. An integrity witness against a torn or scribbled cell,
 * NOT a security hash: it detects accident, not an adversary who already has
 * write access to the aperture. */
static uint32_t fnv_step(uint32_t h, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint32_t)p[i];
        h *= 0x01000193u;
    }
    return h;
}

uint32_t qrmem_fnv1a32(const void *data, size_t len) {
    return fnv_step(0x811Cu, data, len);
}

void qrmem_rec_init(qrmem_rec_t *r, uint16_t type, qrmem_uuid_t id) {
    if (!r)
        return;
    memset(r, 0, sizeof *r);
    r->type = type;
    r->id = id;
}

static void put_u64(unsigned char *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++)
        p[i] = (unsigned char)((v >> (8 * i)) & 0xFFu);
}

static void put_u32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)((v >> 24) & 0xFFu);
    p[1] = (unsigned char)((v >> 16) & 0xFFu);
    p[2] = (unsigned char)((v >> 8) & 0xFFu);
    p[3] = (unsigned char)(v & 0xFFu);
}

static uint32_t get_u32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

/* Append one TLV. `bytes` counts its own 4-byte header, and a TLV that would
 * overrun the body is refused rather than clamped. */
static int tlv_append(qrmem_rec_t *r, uint16_t tag, const unsigned char *val,
                      size_t vlen) {
    unsigned char *p;
    size_t need;
    if (!r || vlen + QRMEM_TLV_HDR > QRMEM_CELL_BODY)
        return -1;
    need = (size_t)r->body_len + QRMEM_TLV_HDR + vlen;
    if (need > QRMEM_CELL_BODY)
        return -1;
    p = r->body + r->body_len;
    p[0] = (unsigned char)((tag >> 8) & 0xFFu);
    p[1] = (unsigned char)(tag & 0xFFu);
    p[2] = (unsigned char)(((QRMEM_TLV_HDR + vlen) >> 8) & 0xFFu);
    p[3] = (unsigned char)((QRMEM_TLV_HDR + vlen) & 0xFFu);
    if (vlen && val)
        memcpy(p + QRMEM_TLV_HDR, val, vlen);
    r->body_len = (uint16_t)need;
    return 0;
}

int qrmem_rec_add_text(qrmem_rec_t *r, const char *s, size_t len) {
    if (!r || (!s && len))
        return -1;
    return tlv_append(r, QRMEM_TLV_TEXT, (const unsigned char *)s, len);
}

/* Text under an arbitrary tag. qrmem_rec_add_text is QRMEM_TLV_TEXT
 * specifically; a second string-valued field needs its own tag rather than
 * overwriting the payload. */
int qrmem_rec_add_text_tag(qrmem_rec_t *r, uint16_t tag, const char *s,
                           size_t len) {
    if (!r || (!s && len))
        return -1;
    return tlv_append(r, tag, (const unsigned char *)s, len);
}

/* Stamp a record with its publication time.
 *
 * Wall-clock REALTIME, deliberately: see QRMEM_TLV_WRITTEN_NS for why monotonic
 * is the wrong clock here. Returns -1 only if the body has no room, which the
 * write path prevents by reserving space first - a caller that hits this has
 * constructed a full record by hand rather than through qrmem_write.
 *
 * Set by the WRITE PATH, not by the caller, so a caller cannot backdate a
 * record or forge its freshness. There is no argument to override it. */
int qrmem_rec_stamp_written(qrmem_rec_t *r, uint64_t unix_ns) {
    unsigned char b[8];
    put_u64(b, unix_ns);
    return tlv_append(r, QRMEM_TLV_WRITTEN_NS, b, sizeof b);
}

int qrmem_rec_add_u32(qrmem_rec_t *r, uint16_t tag, uint32_t v) {
    unsigned char b[4];
    put_u32(b, v);
    return tlv_append(r, tag, b, 4u);
}

int qrmem_rec_add_u8(qrmem_rec_t *r, uint16_t tag, uint8_t v) {
    return tlv_append(r, tag, &v, 1u);
}

int qrmem_rec_add_u32_array(qrmem_rec_t *r, uint16_t tag, const uint32_t *v,
                            size_t n) {
    unsigned char b[QRMEM_CELL_BODY];
    if (n * 4u > sizeof b)
        return -1;
    for (size_t i = 0; i < n; i++)
        put_u32(b + i * 4u, v[i]);
    return tlv_append(r, tag, b, n * 4u);
}

int qrmem_rec_link(qrmem_rec_t *r, qrmem_uuid_t id) {
    if (!r)
        return -1;
    if (r->n_links >= QRMEM_CELL_LINKS)
        return -1; /* a full link set is a refusal, not a silent drop */
    r->links[r->n_links++] = id;
    return 0;
}

/* Find a TLV. Returns the payload offset, -1 when absent, -2 when malformed.
 * Absent and malformed are deliberately different answers: conflating them
 * turns a corrupt cell into a field that quietly reads as zero. */
static long tlv_find(const qrmem_rec_t *r, uint16_t tag, size_t *out_len) {
    size_t off = 0;
    while (off < r->body_len) {
        uint16_t t;
        size_t bytes;
        if (r->body_len - off < QRMEM_TLV_HDR)
            return -2;
        t = (uint16_t)(((uint16_t)r->body[off] << 8) | r->body[off + 1]);
        bytes =
            (size_t)(((uint16_t)r->body[off + 2] << 8) | r->body[off + 3]);
        if (bytes < QRMEM_TLV_HDR || bytes > r->body_len - off)
            return -2;
        if (t == tag) {
            if (out_len)
                *out_len = bytes - QRMEM_TLV_HDR;
            return (long)(off + QRMEM_TLV_HDR);
        }
        off += bytes;
    }
    return (off == r->body_len) ? -1 : -2;
}

/* When this record was published, or 0 for a record with no timestamp - which
 * means a legacy record from a build that predated the field. */
uint64_t qrmem_rec_written_ns(const qrmem_rec_t *r) {
    size_t len = 0;
    long at;
    if (!r)
        return 0u;
    at = tlv_find(r, QRMEM_TLV_WRITTEN_NS, &len);
    if (at < 0 || len != 8u)
        return 0u;
    return (uint64_t)r->body[at] | ((uint64_t)r->body[at + 1] << 8) |
           ((uint64_t)r->body[at + 2] << 16) |
           ((uint64_t)r->body[at + 3] << 24) |
           ((uint64_t)r->body[at + 4] << 32) |
           ((uint64_t)r->body[at + 5] << 40) |
           ((uint64_t)r->body[at + 6] << 48) |
           ((uint64_t)r->body[at + 7] << 56);
}


int qrmem_rec_add_bytes(qrmem_rec_t *r, uint16_t tag, const unsigned char *v,
                        size_t n) {
    return tlv_append(r, tag, v, n);
}

/* Copy out a raw value of a known length.
 *
 * tlv_find reports the length of the tag it found, so a stored length that
 * disagrees with the caller's buffer is an error, never a short read. A reader
 * that quietly accepted 15 of 16 identity bytes would go on to compare a UUID
 * against a truncated one and find it unequal for entirely the wrong reason. */
int qrmem_rec_get_bytes(const qrmem_rec_t *r, uint16_t tag,
                        unsigned char *out, size_t cap, size_t *n_out) {
    size_t len = 0;
    long at;
    if (!r || !out)
        return -1;
    at = tlv_find(r, tag, &len);
    if (at < 0)
        return -1;
    if (n_out)
        *n_out = len;
    if (len > cap)
        return -1;
    memcpy(out, r->body + (size_t)at, len);
    return 0;
}

int qrmem_rec_get_u32(const qrmem_rec_t *r, uint16_t tag, uint32_t *out) {
    size_t len = 0;
    long at;
    if (!r || !out)
        return -1;
    at = tlv_find(r, tag, &len);
    if (at < 0 || len != 4u)
        return -1; /* present but wrong shape is an error, not a short read */
    *out = get_u32(r->body + at);
    return 0;
}

int qrmem_rec_get_u8(const qrmem_rec_t *r, uint16_t tag, uint8_t *out) {
    size_t len = 0;
    long at;
    if (!r || !out)
        return -1;
    at = tlv_find(r, tag, &len);
    if (at < 0 || len != 1u)
        return -1;
    *out = r->body[at];
    return 0;
}

/* Text under an ARBITRARY tag. qrmem_rec_get_text is QRMEM_TLV_TEXT specifically,
 * which is right for the payload and useless for any other string-valued field -
 * the index key being the one that needed it. */
int qrmem_rec_get_text_tag(const qrmem_rec_t *r, uint16_t tag,
                           const char **out, size_t *out_len) {
    size_t len = 0;
    long at;
    if (!r || !out || !out_len)
        return -1;
    at = tlv_find(r, tag, &len);
    if (at < 0)
        return -1;
    *out = (const char *)(const void *)(r->body + at);
    *out_len = len;
    return 0;
}

int qrmem_rec_get_text(const qrmem_rec_t *r, const char **out, size_t *out_len) {
    size_t len = 0;
    long at;
    if (!r || !out || !out_len)
        return -1;
    at = tlv_find(r, QRMEM_TLV_TEXT, &len);
    if (at < 0)
        return -1;
    *out = (const char *)(const void *)(r->body + at);
    *out_len = len;
    return 0;
}

int qrmem_rec_get_u32_array(const qrmem_rec_t *r, uint16_t tag, uint32_t *out,
                            size_t cap, size_t *n_out) {
    size_t len = 0, n, i;
    long at;
    if (!r || !out || !n_out)
        return -1;
    at = tlv_find(r, tag, &len);
    if (at < 0 || len % 4u)
        return -1;
    n = len / 4u;
    if (n > cap)
        return -1; /* the caller sized its buffer; refuse, never truncate */
    for (i = 0; i < n; i++)
        out[i] = get_u32(r->body + at + i * 4u);
    *n_out = n;
    return 0;
}

/* Structural validation of a body: the TLV walk must land exactly on the end.
 * The only ways it cannot are corruption or wrap, and both are refusals. */
int qrmem_cell_validate(const unsigned char *body, size_t len) {
    size_t off = 0;
    if (!body || len > QRMEM_CELL_BODY)
        return -1;
    while (off < len) {
        size_t bytes;
        if (len - off < QRMEM_TLV_HDR)
            return -1;
        bytes = (size_t)(((uint16_t)body[off + 2] << 8) | body[off + 3]);
        if (bytes < QRMEM_TLV_HDR || bytes > len - off)
            return -1;
        off += bytes;
    }
    return off == len ? 0 : -1;
}

/* Enter and leave a cell as a reader.
 *
 * Increment BEFORE reading the publication word, so a writer that has already
 * unpublished still sees this reader in its drain count. The acquire on the
 * increment stops the field loads below from being hoisted above it. */
/* These take a const cell on purpose. A reader legitimately mutates the shared
 * `readers` word of a cell reached through a const aperture: the aperture is
 * const to the CALLER, not to the fabric. MAP_SHARED memory is mutable by every
 * attacher, and pretending otherwise in the signature would just move the cast
 * to the caller while hiding why it is sound. */
static void cell_reader_enter(const qrmem_cell_t *c) {
    atomic_fetch_add_explicit(
        &((qrmem_cell_t *)(uintptr_t)(const void *)c)->readers, 1u,
        memory_order_acquire);
}

static void cell_reader_leave(const qrmem_cell_t *c) {
    /* Release: the field reads above must complete before the writer that is
     * spinning on this counter is allowed to proceed. */
    atomic_fetch_sub_explicit(
        &((qrmem_cell_t *)(uintptr_t)(const void *)c)->readers, 1u,
        memory_order_release);
}

/* Take a cell for writing: unpublish it, then wait until no reader is inside.
 *
 * The acquire on the drain pairs with the reader's release decrement, so
 * observing zero means every field read that reader performed has finished.
 * That is the whole synchronisation. */
static void cell_begin_write(qrmem_cell_t *c) {
    atomic_store_explicit(&c->state, QRMEM_CELL_FREE, QRMEM_PUBLISH_ORDER);
#ifndef QRMEM_WEAKEN_DRAIN
    while (atomic_load_explicit(&c->readers, QRMEM_DRAIN_ORDER) != 0u)
        sched_yield();
#endif
    /* Odd: a write is in flight. Acquire-release so the odd mark cannot sink
     * below the field stores that follow it. */
#ifndef QRMEM_WEAKEN_SEQLOCK
    atomic_fetch_add_explicit(&c->version, 1u, memory_order_acq_rel);
#endif
}

static void cell_end_write(qrmem_cell_t *c, uint32_t next_state) {
    /* Even: the write is complete. This release pairs with the reader's
     * acquire on the closing version sample, which is what makes the reader's
     * field reads ordered before its verdict. */
    atomic_fetch_add_explicit(&c->version, 1u, QRMEM_SEQLOCK_ORDER);
    atomic_store_explicit(&c->state, next_state, QRMEM_PUBLISH_ORDER);
}


uint32_t qrmem_rec_witness(const qrmem_rec_t *r) {
    unsigned char body[QRMEM_CELL_BODY];
    uint32_t h;
    if (!r)
        return 0;
    memset(body, 0, sizeof body);
    if (r->body_len <= QRMEM_CELL_BODY)
        memcpy(body, r->body, r->body_len);
    h = 0x811Cu;
    h = fnv_step(h, &r->type, sizeof r->type);
    h = fnv_step(h, &r->body_len, sizeof r->body_len);
    h = fnv_step(h, &r->id, sizeof r->id);
    h = fnv_step(h, r->links, sizeof r->links);
    h = fnv_step(h, &r->n_links, sizeof r->n_links);
    h = fnv_step(h, &r->generation, sizeof r->generation);
    h = fnv_step(h, body, sizeof body);
    return h;
}

/* A canonical byte image of one record, safe to take while other threads are
 * pinning and republishing it.
 *
 * EVERY field of qrmem_cell_t is _Atomic, so byte-copying a record is a data race
 * by construction - and ThreadSanitizer says so, correctly, the first time a
 * second thread touches a cell while the code plane is being drawn. Each field is
 * therefore loaded atomically, and the copy is taken under the sequence lock so
 * the image is of a settled record rather than one halfway through a write.
 *
 * The `readers` field is written as zero on purpose. It counts readers inside the
 * cell at this instant, so encoding it would mean the surface changed every time
 * anyone merely LOOKED at a record. A memory that redraws itself when read is not
 * a memory. It is the one field the picture must not carry.
 *
 * The stride's trailing bytes are zero for the same reason: nothing stores
 * anything there, and a decoder that recovered "whatever was in the padding"
 * could not be compared against anything.
 *
 * Returns 0 on a settled image, -1 if the record never settled. */
int qrmem_cell_snapshot(const qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                        uint32_t slot, unsigned char *out, size_t cap) {
    const qrmem_cell_t *c;
    size_t o = 0;
    int attempt;
    if (!ap || !ap->hdr || !out || cap < QRMEM_CELL_BYTES)
        return -1;
    if (!qrmem_screen_valid(screen) || !qrmem_block_valid(block) ||
        !qrmem_slot_valid(slot))
        return -1;
    c = qrmem_cell_at(ap, screen, block, slot);
    for (attempt = 0; attempt < 64; attempt++) {
        uint32_t v1, v2;
        uint32_t u32;
        uint16_t u16;
        o = 0;
        v1 = atomic_load_explicit(&c->version, memory_order_acquire);
        if (v1 & 1u) {
            sched_yield();
            continue;
        }
        u32 = atomic_load_explicit(&c->state, memory_order_relaxed);
        memcpy(out + o, &u32, 4);
        o += 4;
        memset(out + o, 0, 4); /* readers: excluded on purpose */
        o += 4;
        u32 = v1;
        memcpy(out + o, &u32, 4);
        o += 4;
        u16 = atomic_load_explicit(&c->type, memory_order_relaxed);
        memcpy(out + o, &u16, 2);
        o += 2;
        u16 = atomic_load_explicit(&c->body_len, memory_order_relaxed);
        memcpy(out + o, &u16, 2);
        o += 2;
        /* Identity is 16 raw bytes and links are 4 x 16. Each element is its
         * own _Atomic unsigned char, so they are loaded one byte at a time:
         * a memcpy of the whole array would be a data race by construction. */
        for (size_t i = 0; i < QRMEM_UUID_BYTES; i++)
            out[o + i] = (unsigned char)atomic_load_explicit(
                &c->id[i], memory_order_relaxed);
        o += QRMEM_UUID_BYTES;
        for (uint32_t l = 0; l < QRMEM_CELL_LINKS; l++) {
            for (size_t i = 0; i < QRMEM_UUID_BYTES; i++)
                out[o + i] = (unsigned char)atomic_load_explicit(
                    &c->links[l][i], memory_order_relaxed);
            o += QRMEM_UUID_BYTES;
        }
        u16 = atomic_load_explicit(&c->n_links, memory_order_relaxed);
        memcpy(out + o, &u16, 2);
        o += 2;
        u16 = atomic_load_explicit(&c->generation, memory_order_relaxed);
        memcpy(out + o, &u16, 2);
        o += 2;
        u32 = atomic_load_explicit(&c->witness, memory_order_relaxed);
        memcpy(out + o, &u32, 4);
        o += 4;
        for (size_t i = 0; i < QRMEM_CELL_BODY; i++)
            out[o + i] = atomic_load_explicit(&c->body[i],
                                             memory_order_relaxed);
        o += QRMEM_CELL_BODY;
        while (o < QRMEM_CELL_BYTES)
            out[o++] = 0u;
        v2 = atomic_load_explicit(&c->version, memory_order_acquire);
        if (v1 == v2)
            return 0;
    }
    return -1;
}

int qrmem_cell_publish(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                       uint32_t slot, const qrmem_rec_t *r, char *err,
                       size_t errlen) {
    qrmem_cell_t *c;
    uint32_t gen;
    uint16_t r_gen = 0;
    if (!ap || !ap->hdr || !r) {
        set_err(err, errlen, "publish needs a fabric and a record");
        return -1;
    }
    if (!qrmem_screen_valid(screen) || !qrmem_block_valid(block) ||
        !qrmem_slot_valid(slot)) {
        set_err(err, errlen,
                "record (screen %u, block %u, slot %u) is outside the fabric "
                "(screen 0..%u, block 0..%u, slot 0..%u)",
                screen, block, slot, QRMEM_SCREENS - 1u,
                QRMEM_BLOCKS_PER_SCREEN - 1u, QRMEM_SLOTS_PER_BLOCK - 1u);
        return -1;
    }
    if (r->body_len > QRMEM_CELL_BODY || r->n_links > QRMEM_CELL_LINKS) {
        set_err(err, errlen, "record does not fit a cell");
        return -1;
    }
    if (qrmem_cell_validate(r->body, r->body_len) != 0) {
        set_err(err, errlen, "record body is not a well-formed TLV chain");
        return -1;
    }
    gen = (uint32_t)(qrmem_generation(ap, screen) & 0xFFFFFFFFu);
    c = qrmem_cell_at(ap, screen, block, slot);
    /* Any index entry naming this cell is now stale. Drop it BEFORE the new
     * record is published, so no reader can follow an old entry to a cell that
     * is about to hold something else. */
    qrmem_index_drop_cell(ap, screen, block, slot);

    /* Unpublish, drain, and mark the sequence odd BEFORE touching a field. */
    cell_begin_write(c);

    atomic_store_explicit(&c->type, r->type, memory_order_relaxed);
    atomic_store_explicit(&c->body_len, r->body_len, memory_order_relaxed);
    for (size_t i = 0; i < QRMEM_UUID_BYTES; i++)
        atomic_store_explicit(&c->id[i], r->id.b[i], memory_order_relaxed);
    for (uint32_t i = 0; i < QRMEM_CELL_LINKS; i++)
        for (size_t k = 0; k < QRMEM_UUID_BYTES; k++)
            atomic_store_explicit(&c->links[i][k], r->links[i].b[k],
                                  memory_order_relaxed);
    atomic_store_explicit(&c->n_links, r->n_links, memory_order_relaxed);
    atomic_store_explicit(&c->generation, (uint16_t)(gen & 0xFFFFu),
                          memory_order_relaxed);
    r_gen = (uint16_t)(gen & 0xFFFFu);
    for (uint32_t i = 0; i < QRMEM_CELL_BODY; i++)
        atomic_store_explicit(&c->body[i],
                              i < r->body_len ? r->body[i] : 0u,
                              memory_order_relaxed);
    {
        qrmem_rec_t snap = *r;
        snap.generation = r_gen;
        atomic_store_explicit(&c->witness, qrmem_rec_witness(&snap),
                              memory_order_relaxed);
    }

    /* Even, then published. A reader that sees LIVE also sees a complete
     * record, because this release is ordered after every field store. */
    cell_end_write(c, QRMEM_CELL_LIVE);
    atomic_fetch_add_explicit(&ap->screens[screen].write_count, 1u,
                              memory_order_relaxed);
    return 0;
}

/* Read one cell.
 *
 * The version sequence lock is the correctness mechanism here, and the drain is
 * only an optimisation. The reader:
 *
 *   1. enters the drain window,
 *   2. samples `version` (must be even),
 *   3. samples `state` and reads the fields with relaxed atomic loads,
 *   4. leaves the drain window,
 *   5. re-samples `version` and rejects the record if it moved.
 *
 * Step 5 is what makes step 3 safe. Without it, a reader that latched a stale
 * LIVE would happily return a mixture of two publishes - which is exactly what
 * the previous version of this function did, about three times per 200k writes.
 *
 * A rejected read is retried rather than reported, because "the cell changed
 * under me" is not a useful answer to a caller. After the retry budget is
 * spent the cell is reported as empty, which is the truth at that instant: the
 * writer is mid-publish and there is no complete record to hand back. */
#define QRMEM_READ_RETRIES 64

/* True in a fault-injected build, where the odd-version guard is also removed
 * so that a read can proceed against a cell that is actively being rewritten. */
static int qrmem_read_is_weak(void) {
#ifdef QRMEM_WEAKEN_SEQLOCK
    return 1;
#else
    return 0;
#endif
}

int qrmem_cell_read(const qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                    uint32_t slot, qrmem_rec_t *out, char *err,
                    size_t errlen) {
    const qrmem_cell_t *c;
    if (!ap || !ap->hdr || !out) {
        set_err(err, errlen, "read needs a fabric and a destination");
        return -1;
    }
    if (!qrmem_screen_valid(screen) || !qrmem_block_valid(block) ||
        !qrmem_slot_valid(slot)) {
        set_err(err, errlen,
                "record (screen %u, block %u, slot %u) is outside the fabric",
                screen, block, slot);
        return -1;
    }
    c = qrmem_cell_at(ap, screen, block, slot);

    for (int attempt = 0; attempt < QRMEM_READ_RETRIES; attempt++) {
        uint32_t v1, v2, state, want, have;

        cell_reader_enter(c);
        /* Acquire: paired with the writer's closing release on `version`, so
         * the field stores before it are visible to the loads after it. */
        v1 = atomic_load_explicit(&c->version, memory_order_acquire);
        if ((v1 & 1u) && !qrmem_read_is_weak()) {
            /* A write is in flight. Nothing complete to read yet. */
            cell_reader_leave(c);
            continue;
        }
        state = atomic_load_explicit(&c->state, memory_order_acquire);
        if (state == QRMEM_CELL_FREE) {
            cell_reader_leave(c);
            set_err(err, errlen, "record (screen %u, block %u, slot %u) is empty", screen, block, slot);
            return -1;
        }
        if (state == QRMEM_CELL_TOMB) {
            /* A tomb still answers with its id AND its body. Returning only the
             * id made everything recorded at supersession time unreachable, so
             * "pass successor_id to record what replaced it" was a promise the
             * reader could never collect. */
            unsigned char tid[QRMEM_UUID_BYTES];
            uint16_t blen = atomic_load_explicit(&c->body_len,
                                                 memory_order_relaxed);
            if (blen > QRMEM_CELL_BODY)
                blen = QRMEM_CELL_BODY;
            /* Load the identity while the reader pin still holds. Leaving first
             * and reading after would load it from a cell another thread may
             * already be reusing. */
            for (size_t i = 0; i < QRMEM_UUID_BYTES; i++)
                tid[i] = (unsigned char)atomic_load_explicit(
                    &c->id[i], memory_order_relaxed);
            cell_reader_leave(c);
            memset(out, 0, sizeof *out);
            out->type = QRMEM_CT_TOMB;
            memcpy(out->id.b, tid, QRMEM_UUID_BYTES);
            out->generation = atomic_load_explicit(&c->generation,
                                                   memory_order_relaxed);
            out->body_len = blen;
            for (uint32_t i = 0; i < blen; i++)
                out->body[i] = atomic_load_explicit(&c->body[i],
                                                    memory_order_relaxed);
            return 0;
        }
        if (state != QRMEM_CELL_LIVE) {
            cell_reader_leave(c);
            set_err(err, errlen,
                    "record (screen %u, block %u, slot %u) carries unknown "
                    "state 0x%x; the fabric is corrupt",
                    screen, block, slot, state);
            return -1;
        }
        memset(out, 0, sizeof *out);
        out->type = atomic_load_explicit(&c->type, memory_order_relaxed);
        for (size_t i = 0; i < QRMEM_UUID_BYTES; i++)
            out->id.b[i] = (unsigned char)atomic_load_explicit(
                &c->id[i], memory_order_relaxed);
        out->n_links = atomic_load_explicit(&c->n_links, memory_order_relaxed);
        for (uint32_t i = 0; i < QRMEM_CELL_LINKS; i++)
            for (size_t k = 0; k < QRMEM_UUID_BYTES; k++)
              out->links[i].b[k] = (unsigned char)atomic_load_explicit(
                  &c->links[i][k],
                                                memory_order_relaxed);
        out->body_len = atomic_load_explicit(&c->body_len,
                                             memory_order_relaxed);
        out->generation = atomic_load_explicit(&c->generation,
                                               memory_order_relaxed);
        if (out->body_len > QRMEM_CELL_BODY) {
            cell_reader_leave(c);
            set_err(err, errlen,
                    "record (screen %u, block %u, slot %u) claims a %u byte "
                    "body, which cannot exist",
                    screen, block, slot, out->body_len);
            memset(out, 0, sizeof *out);
            return -1;
        }
        for (uint32_t i = 0; i < out->body_len; i++)
            out->body[i] = atomic_load_explicit(&c->body[i],
                                                memory_order_relaxed);
        cell_reader_leave(c);

        /* The closing sample. The acquire fence keeps the field loads above
         * from being hooked past it, so if `version` moved, we know it moved
         * after the reads and the record must be discarded. */
#ifndef QRMEM_WEAKEN_SEQLOCK
        atomic_thread_fence(memory_order_acquire);
        v2 = atomic_load_explicit(&c->version, memory_order_relaxed);
        if (v2 != v1)
            continue; /* the record changed under us; take it again */
#else
        /* TEST-ONLY fault injection: drop the closing re-check entirely. This
         * is the gate that can actually fail on x86-64, where weakening
         * release to relaxed changes no instruction and is therefore
         * unobservable. Removing the check removes the correctness mechanism,
         * and the threaded stress sees torn records within a few thousand
         * writes. See tests/test_qrmem.sh. */
        (void)v2;
#endif

        have = atomic_load_explicit(&c->witness, memory_order_relaxed);
        want = qrmem_rec_witness(out);
        if (have != want) {
            set_err(err, errlen,
                    "record (screen %u, block %u, slot %u) failed its integrity "
                    "witness (stored 0x%08x, computed 0x%08x); refusing to hand "
                    "back a record nobody can trust",
                    screen, block, slot, have, want);
            memset(out, 0, sizeof *out);
            return -1;
        }
        if (qrmem_cell_validate(out->body, out->body_len) != 0) {
            set_err(err, errlen,
                    "record (screen %u, block %u, slot %u) holds a malformed "
                    "TLV chain",
                    screen, block, slot);
            memset(out, 0, sizeof *out);
            return -1;
        }
        return 0;
    }
    memset(out, 0, sizeof *out);
    set_err(err, errlen,
            "record (screen %u, block %u, slot %u) did not settle after %d "
            "attempts; its writer is still publishing",
            screen, block, slot, QRMEM_READ_RETRIES);
    return -1;
}

int qrmem_cell_clear(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                     uint32_t slot, char *err, size_t errlen) {
    qrmem_cell_t *c;
    if (!ap || !ap->hdr) {
        set_err(err, errlen, "no fabric attached");
        return -1;
    }
    if (!qrmem_screen_valid(screen) || !qrmem_block_valid(block) ||
        !qrmem_slot_valid(slot)) {
        set_err(err, errlen,
                "record (screen %u, block %u, slot %u) is outside the fabric",
                screen, block, slot);
        return -1;
    }
    c = qrmem_cell_at(ap, screen, block, slot);
    cell_begin_write(c);
    atomic_store_explicit(&c->type, QRMEM_CT_EMPTY, memory_order_relaxed);
    atomic_store_explicit(&c->body_len, 0, memory_order_relaxed);
    /* Identity is cleared too: a cleared cell that kept its old UUID would let
     * a later write mint a record whose id looks pre-existing, and a reader
     * holding a stale id would resolve to a cell that no longer holds it. */
    for (size_t i = 0; i < QRMEM_UUID_BYTES; i++)
        atomic_store_explicit(&c->id[i], 0, memory_order_relaxed);
    atomic_store_explicit(&c->n_links, 0, memory_order_relaxed);
    atomic_store_explicit(&c->generation, 0, memory_order_relaxed);
    for (uint32_t l = 0; l < QRMEM_CELL_LINKS; l++)
        for (size_t i = 0; i < QRMEM_UUID_BYTES; i++)
            atomic_store_explicit(&c->links[l][i], 0, memory_order_relaxed);
    for (uint32_t i = 0; i < QRMEM_CELL_BODY; i++)
        atomic_store_explicit(&c->body[i], 0, memory_order_relaxed);
    atomic_store_explicit(&c->witness, 0, memory_order_relaxed);
    cell_end_write(c, QRMEM_CELL_FREE);
    qrmem_index_drop_cell(ap, screen, block, slot);
    return 0;
}

int qrmem_cell_tomb(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                    uint32_t slot, char *err, size_t errlen) {
    qrmem_cell_t *c;
    if (!ap || !ap->hdr) {
        set_err(err, errlen, "no fabric attached");
        return -1;
    }
    if (!qrmem_screen_valid(screen) || !qrmem_block_valid(block) ||
        !qrmem_slot_valid(slot)) {
        set_err(err, errlen,
                "record (screen %u, block %u, slot %u) is outside the fabric",
                screen, block, slot);
        return -1;
    }
    c = qrmem_cell_at(ap, screen, block, slot);
    /* The record is retained: a tomb still answers with its id so a reader can
     * tell "superseded" from "never existed". Only the state word changes, and
     * it changes after the drain. The index stops pointing at it, because a
     * superseded record must not be what a fresh lookup finds. */
    cell_begin_write(c);
    cell_end_write(c, QRMEM_CELL_TOMB);
    qrmem_index_drop_cell(ap, screen, block, slot);
    return 0;
}
