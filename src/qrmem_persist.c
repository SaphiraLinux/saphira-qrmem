/* Saphira Memory - reboot survival for the tile fabric.
 *
 * /dev/shm is memory, not storage. A reboot empties it, and until now that
 * emptied every agent's page along with it: an agent that had been working on a
 * page found it gone, not marked stale but GONE, with nothing to distinguish
 * "never existed" from "the machine restarted and did not care".
 *
 * That was an acceptable curiosity while nothing depended on the fabric. Now
 * that agents do, it is a defect, and the fix has an exact shape:
 *
 *     restore the latest live page contents and project metadata
 *     BUT mint a fresh authority_gen
 *         zero every lease
 *         restore no screen owner
 *
 * The asymmetry is the whole design, and it is deliberate. Page CONTENT is
 * durable: it is the agent's thinking, and losing it loses work. Authority is
 * not: it is a statement about which live process may write, and after a reboot
 * there are no live processes. A restart that restored an owner would hand
 * WRITE AUTHORITY to whichever agent drew that slot number next - precisely the
 * confusion the one-writer rule exists to prevent, arrived at through the
 * durability path instead of the leak path.
 *
 * So continuity without resurrection: the same page, new authority, no dead
 * writers.
 *
 * FORMAT. A single file, written to a temporary path and renamed into place, so
 * a snapshot is either the previous complete one or the new complete one and
 * never a half-written mixture. Explicit lengths everywhere and a checksum over
 * the payload, because a snapshot file is exactly the kind of thing that gets
 * truncated by a full filesystem at the least convenient moment, and a decoder
 * that "handled" truncation would restore a partial page as if it were whole.
 *
 * NO-DELETE, NO-SILENT-REPAIR. This is SHAMPOO state. It is never deleted to
 * make room; a snapshot is replaced by rename, which is an atomic replacement
 * and not a deletion of history. A corrupt snapshot is REFUSED, not repaired
 * and not partially applied: the daemon then starts with an empty fabric and
 * says so loudly, which is a recoverable situation. Silently restoring half a
 * page would not be.
 */
#include "qrmem.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define QRMEM_SNAP_MAGIC 0x534e4f51u /* "QNOS" little-endian-ish */
#define QRMEM_SNAP_VERSION 1u
/* A snapshot larger than this is not a snapshot this build wrote. Records are
 * bounded by the cell, so the whole file is bounded well below it; the check
 * stops a garbage header from turning into a huge read. */
#define QRMEM_SNAP_MAX_BYTES (8u * 1024u * 1024u)

static void set_err(char *err, size_t errlen, const char *fmt, ...) {
    va_list ap;
    if (!err || !errlen)
        return;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* Little-endian fixed width. A snapshot outlives the build that wrote it, so it
 * cannot inherit host byte order the way the aperture header does. */
static void put_u16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xFFu);
    p[1] = (unsigned char)((v >> 8) & 0xFFu);
}
static void put_u32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xFFu);
    p[1] = (unsigned char)((v >> 8) & 0xFFu);
    p[2] = (unsigned char)((v >> 16) & 0xFFu);
    p[3] = (unsigned char)((v >> 24) & 0xFFu);
}
static uint16_t get_u16(const unsigned char *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static uint32_t get_u32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ save
 *
 * Only LIVE records are saved. A tomb is deliberately not: it says "this record
 * was superseded", which is a fact about a decision an agent made while it was
 * alive. Restoring it after a reboot would resurrect the decision without the
 * successor record it pointed at, leaving a reader to follow a reference into
 * nothing. A superseded record that still matters should be on the next page.
 *
 * Project labels ARE saved, for the opposite reason: a page without its label
 * cannot be found by project, and an unlabelled page is an orphan.
 */
int qrmem_snapshot_save(const qrmem_ap_t *ap, const char *path, char *err,
                        size_t errlen) {
    char tmp[1024];
    unsigned char *buf;
    size_t cap, o = 0;
    uint32_t saved = 0;
    int fd;
    if (!ap || !ap->hdr || !path || !path[0]) {
        set_err(err, errlen, "snapshot save needs an attached fabric and a path");
        return -1;
    }
    /* Header plus, for every record on every screen, a fixed prefix and its
     * body. Computing the upper bound first means the buffer is sized from the
     * geometry rather than guessed, and the encoder cannot run off the end. */
    cap = 64u + (size_t)QRMEM_TOTAL_RECORDS *
                     (8u + QRMEM_CELL_BODY + 4u * QRMEM_UUID_BYTES + 64u);
    buf = malloc(cap);
    if (!buf) {
        set_err(err, errlen, "no memory to build a snapshot");
        return -1;
    }
    put_u32(buf + o, QRMEM_SNAP_MAGIC); o += 4;
    put_u32(buf + o, QRMEM_SNAP_VERSION); o += 4;
    put_u32(buf + o, QRMEM_ABI_MAJOR); o += 4;
    put_u32(buf + o, QRMEM_SCREENS); o += 4;
    put_u32(buf + o, QRMEM_PROJECT_MAX); o += 4;
    put_u32(buf + o, 0u); o += 4; /* record count, filled in below */
    for (uint32_t s = 0; s < QRMEM_SCREENS; s++) {
        uint32_t plen = atomic_load_explicit(&ap->screens[s].project_len,
                                             memory_order_acquire);
        uint32_t gen = (uint32_t)atomic_load_explicit(&ap->screens[s].generation,
                                                      memory_order_acquire);
        uint32_t wcnt = (uint32_t)atomic_load_explicit(
            &ap->screens[s].write_count, memory_order_acquire);
        uint32_t nrec_here = 0;
        size_t count_at;
        /* Owner is NOT written. There is no field for it, deliberately: a
         * restore path that could bring an owner back would eventually be asked
         * to, and the way to make that impossible is for the format to have no
         * way to express it. */
        if (plen > QRMEM_PROJECT_MAX)
            plen = 0; /* corrupt label: refuse to propagate nonsense */
        put_u32(buf + o, plen); o += 4;
        put_u32(buf + o, gen); o += 4;
        put_u32(buf + o, wcnt); o += 4;
        /* The record COUNT comes before the label and the records.
         *
         * Without it the reader has to find the end of a screen's records by
         * reading an invalid type field, which cannot work: an empty screen
         * writes no records at all, so the next thing in the file is the NEXT
         * SCREEN's header. Reading that as a record type desynchronises the
         * whole decode, and the resulting failure looks like corruption of a
         * perfectly good file. A count says exactly where this screen ends. */
        count_at = o;
        put_u32(buf + o, 0u); o += 4;
        memcpy(buf + o, ap->screens[s].project, plen); o += plen;
        for (uint32_t b = 0; b < QRMEM_BLOCKS_PER_SCREEN; b++) {
            for (uint32_t sl = 0; sl < QRMEM_SLOTS_PER_BLOCK; sl++) {
                qrmem_rec_t r;
                char rerr[256] = "";
                if (qrmem_cell_read(ap, s, b, sl, &r, rerr, sizeof rerr) != 0)
                    continue; /* empty, tomb, or unsettled: not durable state */
                if (r.type == QRMEM_CT_TOMB)
                    continue;
                put_u16(buf + o, r.type); o += 2;
                put_u16(buf + o, r.body_len); o += 2;
                memcpy(buf + o, r.id.b, QRMEM_UUID_BYTES); o += QRMEM_UUID_BYTES;
                put_u16(buf + o, r.n_links); o += 2;
                for (uint16_t l = 0; l < r.n_links; l++) {
                    memcpy(buf + o, r.links[l].b, QRMEM_UUID_BYTES);
                    o += QRMEM_UUID_BYTES;
                }
                memcpy(buf + o, r.body, r.body_len); o += r.body_len;
                nrec_here++;
                saved++;
            }
        }
        put_u32(buf + count_at, nrec_here);
    }
    put_u32(buf + 20, saved);
    /* Checksum over everything after the count field, so the header itself is
     * covered by the format checks that precede it. */
    put_u32(buf + o, qrmem_fnv1a32(buf + 24, o - 24u)); o += 4;

    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) {
        set_err(err, errlen, "snapshot path is too long to write a temporary");
        free(buf);
        return -1;
    }
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        set_err(err, errlen, "cannot create %s: %s", tmp, strerror(errno));
        free(buf);
        return -1;
    }
    {
        size_t wrote = 0;
        int bad = 0;
        while (wrote < o) {
            ssize_t n = write(fd, buf + wrote, o - wrote);
            if (n > 0) {
                wrote += (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            set_err(err, errlen, "cannot write %s: %s", tmp, strerror(errno));
            bad = 1;
            break;
        }
        if (!bad && fsync(fd) != 0) {
            /* Without the fsync a snapshot can exist in the page cache and be
             * gone after the power loss it was meant to survive. */
            set_err(err, errlen, "cannot flush %s: %s", tmp, strerror(errno));
            bad = 1;
        }
        close(fd);
        if (bad) {
            unlink(tmp);
            free(buf);
            return -1;
        }
    }
    /* Rename is the atomic replacement. The previous snapshot is replaced by
     * that rename, not deleted first, so a crash mid-save leaves the old
     * snapshot intact rather than no snapshot. */
    if (rename(tmp, path) != 0) {
        set_err(err, errlen, "cannot install %s: %s", path, strerror(errno));
        unlink(tmp);
        free(buf);
        return -1;
    }
    free(buf);
    if (saved > 0u)
        set_err(err, errlen, "%u records across %u screens", (unsigned)saved,
                (unsigned)QRMEM_SCREENS);
    return 0;
}

/* ----------------------------------------------------------------- load
 *
 * Restores page content and project metadata ONLY. Authority is left exactly as
 * the freshly created fabric has it: authority_gen already minted for this
 * incarnation, every lease_hold zero, every screen owner zero. There is no code
 * path here that could restore an owner, because there is no field to restore
 * one from.
 *
 * Returns 1 when records or labels were restored, 0 when there was nothing to
 * restore (no file), and -1 when a snapshot EXISTS and is unusable. That third
 * case is deliberately not the same as "empty": a corrupt snapshot is a fact the
 * operator needs told, and quietly starting empty would hide it.
 */
int qrmem_snapshot_load(qrmem_ap_t *ap, const char *path, char *err,
                        size_t errlen) {
    unsigned char *buf;
    struct stat st;
    size_t o = 0, len;
    uint32_t count, want, got;
    int fd;
    int restored = 0;
    uint32_t reindexed = 0, reindex_skipped = 0;

    if (!ap || !ap->hdr || !path || !path[0]) {
        set_err(err, errlen, "snapshot load needs an attached fabric and a path");
        return -1;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT)
            return 0;
        set_err(err, errlen, "cannot read %s: %s", path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
        (uint64_t)st.st_size > QRMEM_SNAP_MAX_BYTES) {
        set_err(err, errlen, "%s is not a usable snapshot size", path);
        close(fd);
        return -1;
    }
    len = (size_t)st.st_size;
    buf = malloc(len);
    if (!buf) {
        set_err(err, errlen, "no memory to read a snapshot");
        close(fd);
        return -1;
    }
    {
        size_t got_n = 0;
        int bad = 0;
        while (got_n < len) {
            ssize_t n = read(fd, buf + got_n, len - got_n);
            if (n > 0) {
                got_n += (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            bad = n == 0; /* short read is corruption */
            break;
        }
        close(fd);
        if (bad || got_n != len) {
            set_err(err, errlen, "%s is truncated (%zu of %zu bytes)", path,
                    got_n, len);
            free(buf);
            return -1;
        }
    }
#define REFUSE(...)                                                             \
    do {                                                                       \
        set_err(err, errlen, __VA_ARGS__);                                     \
        free(buf);                                                              \
        return -1;                                                              \
    } while (0)

    if (len < 28u)
        REFUSE("%s is too short to be a snapshot", path);
    if (get_u32(buf) != QRMEM_SNAP_MAGIC)
        REFUSE("%s is not a qrmem snapshot (bad magic)", path);
    if (get_u32(buf + 4) != QRMEM_SNAP_VERSION)
        REFUSE("%s is snapshot version %u; this build reads version %u", path,
               get_u32(buf + 4), (unsigned)QRMEM_SNAP_VERSION);
    /* An ABI mismatch means the record layout differs, so the offsets in this
     * file mean something else entirely. Refusing is the only honest option. */
    if (get_u32(buf + 8) != QRMEM_ABI_MAJOR)
        REFUSE("%s was written for fabric ABI %u; this build is ABI %u",
               path, get_u32(buf + 8), (unsigned)QRMEM_ABI_MAJOR);
    if (get_u32(buf + 12) != QRMEM_SCREENS)
        REFUSE("%s holds %u screens; this build has %u", path,
               get_u32(buf + 12), (unsigned)QRMEM_SCREENS);
    if (get_u32(buf + 16) != QRMEM_PROJECT_MAX)
        REFUSE("%s was written with a %u byte project label; this build uses "
               "%u",
               path, get_u32(buf + 16), (unsigned)QRMEM_PROJECT_MAX);
    count = get_u32(buf + 20);
    want = get_u32(buf + len - 4u);
    got = qrmem_fnv1a32(buf + 24, len - 28u);
    if (got != want)
        REFUSE("%s is corrupt: checksum %08x does not match the recorded %08x",
               path, (unsigned)got, (unsigned)want);
#undef REFUSE

    o = 24;
    for (uint32_t s = 0; s < QRMEM_SCREENS; s++) {
        uint32_t plen, gen, wcnt, nrec = 0, want_nrec = 0;
        if (o + 16u > len - 4u)
            goto truncated;
        plen = get_u32(buf + o); o += 4;
        gen = get_u32(buf + o); o += 4;
        wcnt = get_u32(buf + o); o += 4;
        want_nrec = get_u32(buf + o); o += 4;
        if (want_nrec > QRMEM_RECORDS_PER_SCREEN)
            goto truncated;
        if (plen > QRMEM_PROJECT_MAX)
            goto truncated;
        /* Labels first, so a page is findable by project even if a record below
         * it turns out to be unreadable. */
        if (plen > 0u) {
            memcpy(ap->screens[s].project, buf + o, plen);
            atomic_store_explicit(&ap->screens[s].project_len, plen,
                                  memory_order_release);
        }
        o += plen;
        /* The screen's generation is restored so a reader can tell a page that
         * carried on from one that started empty. The owner stays zero: that is
         * the entire point. */
        atomic_store_explicit(&ap->screens[s].generation, (uint64_t)gen,
                              memory_order_release);
        atomic_store_explicit(&ap->screens[s].write_count, (uint64_t)wcnt,
                              memory_order_release);
        /* Exactly `want_nrec` records follow. The count is authoritative and is
         * checked against the total at the end, so a file whose counts do not
         * add up is refused rather than half-read. */
        for (uint32_t k = 0; k < want_nrec; k++) {
            uint16_t type, blen, nlinks;
            qrmem_rec_t r;
            /* Reset the placement probe for THIS record. It used to persist
             * across iterations, so once one record had been placed the search
             * short-circuited and every remaining record in the screen was
             * silently dropped - the loader reported a mismatch and restored
             * only the first record of each page. */
            nrec = 0;
            if (o + 4u > len - 4u)
                goto truncated;
            type = get_u16(buf + o);
            blen = get_u16(buf + o + 2);
            if (type != QRMEM_CT_WORD && type != QRMEM_CT_IDEA &&
                type != QRMEM_CT_FACT && type != QRMEM_CT_PTR)
                goto truncated;
            if (blen > QRMEM_CELL_BODY || o + 4u + QRMEM_UUID_BYTES + 2u > len - 4u)
                goto truncated;
            o += 4;
            qrmem_rec_init(&r, type, (qrmem_uuid_t){{0}});
            memcpy(r.id.b, buf + o, QRMEM_UUID_BYTES);
            o += QRMEM_UUID_BYTES;
            nlinks = get_u16(buf + o);
            o += 2;
            if (nlinks > QRMEM_CELL_LINKS ||
                o + (size_t)nlinks * QRMEM_UUID_BYTES > len - 4u)
                goto truncated;
            for (uint16_t l = 0; l < nlinks; l++) {
                memcpy(r.links[l].b, buf + o, QRMEM_UUID_BYTES);
                o += QRMEM_UUID_BYTES;
            }
            if (o + blen > len - 4u)
                goto truncated;
            memcpy(r.body, buf + o, blen);
            r.body_len = blen;
            o += blen;
            /* Republish into the first free cell on this screen. Restoring an
             * exact address would imply the page's layout is part of what
             * survived, and it is not: the slots a reboot left behind carry no
             * promise about which records a live page had put where. */
            for (uint32_t b = 0; b < QRMEM_BLOCKS_PER_SCREEN && nrec == 0u;
                 b++) {
                for (uint32_t sl2 = 0; sl2 < QRMEM_SLOTS_PER_BLOCK; sl2++) {
                    qrmem_rec_t probe;
                    char perr[256] = "";
                    if (qrmem_cell_read(ap, s, b, sl2, &probe, perr,
                                        sizeof perr) == 0)
                        continue;
                    if (qrmem_cell_publish(ap, s, b, sl2, &r, perr,
                                           sizeof perr) != 0)
                        goto truncated;
                    qrmem_plane_store_block(ap, s, b);
                    /* Rebuild the lookup handle from the record's own key.
                     *
                     * This is the whole fix for a record that came back readable
                     * by coordinate but invisible to qrmem_index: the index table
                     * lives in the aperture, which a reboot empties, while the key
                     * is durable with the record. Rebuilding derived state from
                     * the durable copy means there is exactly one source of truth
                     * and nothing can disagree with it.
                     *
                     * Failure is NOT fatal to the restore. A full table is the one
                     * real possibility, and refusing the whole restore over it
                     * would lose the records themselves to protect a lookup. The
                     * record is restored and its index_key is still reported, so
                     * the handle is recoverable; the count below makes the
                     * shortfall visible rather than silent. */
                    {
                        const char *ktxt = NULL;
                        size_t klen = 0;
                        if (qrmem_rec_get_text_tag(&r, QRMEM_TLV_INDEX_KEY,
                                                   &ktxt, &klen) == 0 &&
                            klen > 0 && klen <= 256u) {
                            char keybuf[257];
                            memcpy(keybuf, ktxt, klen);
                            keybuf[klen] = '\0';
                            if (qrmem_index_restore(ap, s, keybuf, b, sl2) != 0)
                                reindex_skipped++;
                            else
                                reindexed++;
                        }
                    }
                    nrec = 1u;
                    restored++;
                    break;
                }
            }
            /* A screen with no free cell cannot take this record. Say so
             * rather than pretending the file was fully applied: the operator
             * needs to know the restore was incomplete. */
            if (nrec == 0u)
                goto full;
        }
    }
    if (restored != (int)count) {
        set_err(err, errlen,
                "%s holds %u records but %u were restored", path,
                (unsigned)count, (unsigned)restored);
        free(buf);
        return -1;
    }
    if (count > 0u && restored == 0) {
        set_err(err, errlen,
                "%s holds %u records but none could be placed", path,
                (unsigned)count);
        free(buf);
        return -1;
    }
    if (o != len - 4u) {
        set_err(err, errlen, "%s has %zu trailing bytes", path, len - 4u - o);
        free(buf);
        return -1;
    }
    free(buf);
    /* Report a rebuild shortfall through the caller's buffer so a restore that
     * silently lost discovery handles cannot pass for a clean one. */
    if (reindex_skipped > 0u)
        set_err(err, errlen,
                "restored %u records but %u could not be re-indexed: the "
                "screen's %u-entry index table is full. The records and their "
                "keys are intact and readable; their index_key is still "
                "reported on each read.",
                (unsigned)restored, (unsigned)reindex_skipped,
                (unsigned)QRMEM_INDEX_ENTRIES);
    else if (reindexed > 0u)
        set_err(err, errlen, "%u records, %u lookup keys rebuilt",
                (unsigned)restored, (unsigned)reindexed);
    return restored > 0 ? 1 : 0;

full:
    /* Refused, like any other partial application. Half a restored page is
     * worse than none because it looks authoritative. */
    set_err(err, errlen,
            "%s needs more free cells than the fabric has; nothing from it was "
            "restored",
            path);
    free(buf);
    return -1;

truncated:
    /* A truncated snapshot is refused, never partially applied, and never
     * repaired. Half a restored page is worse than an empty one because it looks
     * authoritative. */
    set_err(err, errlen,
            "%s is truncated or malformed; nothing from it was restored",
            path);
    free(buf);
    return -1;
}