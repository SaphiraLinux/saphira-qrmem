/* Saphira Memory - qrmem tile operations: the six verbs and the index.
 *
 * Every mutating verb opens an operation scope (qrmem_op_begin /
 * qrmem_op_end) so the screen generation is bumped exactly once, after every
 * cell that verb touched is published. A reader that watches the generation
 * therefore never sees a half-applied operation.
 *
 * Ownership is checked first, always. A verb that mutates a screen the caller
 * does not own is refused before any address is computed.
 */
#include "qrmem.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void set_err(char *err, size_t errlen, const char *fmt, ...) {
    if (!err || !errlen)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* READ. Every agent may read every screen; that is the whole autoconference
 * premise. No ownership check here, deliberately. */
int qrmem_tile_read(const qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                    uint32_t slot, qrmem_rec_t *out, char *err, size_t errlen) {
    return qrmem_cell_read(ap, screen, block, slot, out, err, errlen);
}

/* WRITE. Publishes one record at one coordinate. */
int qrmem_tile_write(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                     uint32_t slot, qrmem_id_t id, const qrmem_rec_t *r,
                     char *err, size_t errlen) {
    int rc;
    if (qrmem_require_owner(ap, screen, id, err, errlen) != 0)
        return -1;
    if (qrmem_op_begin(ap, screen, NULL) != 0) {
        set_err(err, errlen, "screen %u is not a fabric screen", screen);
        return -1;
    }
    rc = qrmem_cell_publish(ap, screen, block, slot, r, err, errlen);
    if (rc == 0) {
        /* Redraw the block BEFORE the generation bump. A reader that sees the
         * new generation must be able to see the pattern that goes with it;
         * publishing the generation first would advertise a change the plane
         * has not caught up with yet. */
        qrmem_plane_store_block(ap, screen, block);
        qrmem_op_end(ap, screen);
        qrmem_plane_mark_changed(ap, screen, block, slot);
    }
    return rc;
}

/* LINK. Adds a link to a live record in place. The record is rewritten whole,
 * because a cell is published as a unit and a partially-updated one would be a
 * record whose links and body disagree. */
int qrmem_tile_link(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                    uint32_t slot, qrmem_id_t id, qrmem_uuid_t target_id,
                    char *err, size_t errlen) {
    char self_txt[QRMEM_UUID_TEXT_LEN + 1];
    char tgt_txt[QRMEM_UUID_TEXT_LEN + 1];
    qrmem_rec_t r;
    int rc;
    if (qrmem_require_owner(ap, screen, id, err, errlen) != 0)
        return -1;
    if (qrmem_cell_read(ap, screen, block, slot, &r, err, errlen) != 0)
        return -1;
    if (r.type == QRMEM_CT_TOMB) {
        set_err(err, errlen,
                "record (screen %u, block %u, slot %u) is a tomb; relink its "
                "successor instead of the superseded record",
                screen, block, slot);
        return -1;
    }
    qrmem_uuid_text(&r.id, self_txt, sizeof self_txt);
    qrmem_uuid_text(&target_id, tgt_txt, sizeof tgt_txt);
    for (uint16_t i = 0; i < r.n_links; i++) {
        if (qrmem_uuid_equal(&r.links[i], &target_id)) {
            set_err(err, errlen, "record %s already links to %s", self_txt,
                    tgt_txt);
            return -1;
        }
    }
    if (qrmem_rec_link(&r, target_id) != 0) {
        set_err(err, errlen,
                "record %s already carries %u links; a cell holds at most %u",
                self_txt, (unsigned)r.n_links, (unsigned)QRMEM_CELL_LINKS);
        return -1;
    }
    qrmem_op_begin(ap, screen, NULL);
    rc = qrmem_cell_publish(ap, screen, block, slot, &r, err, errlen);
    if (rc == 0) {
        qrmem_plane_store_block(ap, screen, block);
        qrmem_op_end(ap, screen);
    }
    return rc;
}

/* COPY. Source and destination must both be on a screen the caller owns: a
 * copy that read another agent's tile would let one agent's memory land in
 * another agent's tile under that agent's authorship, which is exactly the
 * confusion the ownership rule exists to prevent.
 *
 * A COPY MINTS A NEW IDENTITY and links back to what it was copied from.
 *
 * This is a deliberate choice, not an accident of copying the record struct.
 * A copy is a new record that happens to have the same content: if it kept the
 * source's UUID then two live cells would answer to one identity, "which record
 * is this" would have two answers, and a link to either would be ambiguous. The
 * link is what makes the derivation followable - the copy says which record it
 * came from, and the source keeps its own identity - so nothing is lost by
 * minting.
 *
 * A MOVE, by contrast, PRESERVES identity: it is the same record at a new
 * address. See qrmem_tile_move. */
int qrmem_tile_copy(qrmem_ap_t *ap, uint32_t src_screen, uint32_t src_block,
                    uint32_t src_slot, uint32_t dst_screen, uint32_t dst_block,
                    uint32_t dst_slot, qrmem_id_t id, char *err, size_t errlen) {
    qrmem_rec_t r;
    qrmem_uuid_t fresh;
    int rc;
    if (qrmem_require_owner(ap, src_screen, id, err, errlen) != 0)
        return -1;
    if (qrmem_require_owner(ap, dst_screen, id, err, errlen) != 0)
        return -1;
    if (qrmem_cell_read(ap, src_screen, src_block, src_slot, &r, err, errlen) != 0)
        return -1;
    /* A full link set is refused rather than quietly dropped: the link is how
     * the copy records its provenance, and a copy whose provenance is missing
     * is worse than a copy that did not happen. */
    if (r.n_links >= QRMEM_CELL_LINKS) {
        set_err(err, errlen,
                "record (screen %u, block %u, slot %u) already has %u links; a "
                "copy must be able to record the record it came from",
                src_screen, src_block, src_slot, (unsigned)QRMEM_CELL_LINKS);
        return -1;
    }
    if (qrmem_uuid_mint(&fresh, err, errlen) != 0)
        return -1;
    /* Keep the source's identity in the link, then take the minted one. */
    if (qrmem_rec_link(&r, r.id) != 0) {
        set_err(err, errlen, "cannot record the copy's source in its links");
        return -1;
    }
    r.id = fresh;
    qrmem_op_begin(ap, dst_screen, NULL);
    rc = qrmem_cell_publish(ap, dst_screen, dst_block, dst_slot, &r, err,
                            errlen);
    if (rc == 0) {
        qrmem_plane_store_block(ap, dst_screen, dst_block);
        qrmem_op_end(ap, dst_screen);
    }
    return rc;
}

/* MOVE. A move is a tomb at the source plus a publish at the destination, in
 * one operation scope, so a reader never sees the record in two places or in
 * none. Both cells are on screens the caller owns.
 *
 * A MOVE PRESERVES IDENTITY. This is the same record at a new address, and that
 * is exactly the distinction the UUID makes legible: address is
 * (screen, block, slot), identity is the UUID, and a move changes only the
 * address. Copy, which is a different operation with a different meaning, mints
 * a new identity instead. See qrmem_tile_copy. */
int qrmem_tile_move(qrmem_ap_t *ap, uint32_t src_screen, uint32_t src_block,
                    uint32_t src_slot, uint32_t dst_screen, uint32_t dst_block,
                    uint32_t dst_slot, qrmem_id_t id, char *err, size_t errlen) {
    qrmem_rec_t r;
    int rc;
    if (qrmem_require_owner(ap, src_screen, id, err, errlen) != 0)
        return -1;
    if (qrmem_require_owner(ap, dst_screen, id, err, errlen) != 0)
        return -1;
    if (src_screen == dst_screen && src_block == dst_block && src_slot == dst_slot) {
        set_err(err, errlen, "source and destination are the same cell");
        return -1;
    }
    if (qrmem_cell_read(ap, src_screen, src_block, src_slot, &r, err, errlen) != 0)
        return -1;
    /* Publish the destination BEFORE tombstoning the source. If the copy fails
     * the record still exists in exactly one place; the reverse order could
     * lose it outright. */
    qrmem_op_begin(ap, dst_screen, NULL);
    rc = qrmem_cell_publish(ap, dst_screen, dst_block, dst_slot, &r, err, errlen);
    if (rc != 0)
        return rc;
    qrmem_plane_store_block(ap, dst_screen, dst_block);
    qrmem_op_end(ap, dst_screen);
    qrmem_op_begin(ap, src_screen, NULL);
    rc = qrmem_cell_tomb(ap, src_screen, src_block, src_slot, err, errlen);
    if (rc == 0) {
        qrmem_plane_store_block(ap, src_screen, src_block);
        qrmem_op_end(ap, src_screen);
    }
    return rc;
}

/* SUPERSEDE. The record stays where it is, marked as a tomb: superseded is a
 * different fact from never-existed, and a reader that cannot tell them apart
 * will re-derive a conclusion that was already retired. */
int qrmem_tile_supersede(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                         uint32_t slot, qrmem_id_t id, qrmem_uuid_t by_id,
                         char *err, size_t errlen) {
    qrmem_rec_t r;
    int rc;
    int have_by;
    if (qrmem_require_owner(ap, screen, id, err, errlen) != 0)
        return -1;
    if (!qrmem_uuid_is_nil(&by_id)) {
        /* Record the supersession inside the body so the successor is
         * discoverable from the retired cell alone. */
        if (qrmem_cell_read(ap, screen, block, slot, &r, err, errlen) != 0)
            return -1;
        if (r.type == QRMEM_CT_TOMB) {
            set_err(err, errlen, "record (screen %u, block %u, slot %u) is already superseded",
                    screen, block, slot);
            return -1;
        }
        /* A DEDICATED tag. The first version reused QRMEM_TLV_SOURCE here,
         * which broke two things at once: it collided with a record's real
         * provenance (the body's first SOURCE tag still won on read, so the
         * successor was invisible), and it broke this file's own rule that a new
         * field is a new TLV and never a reused one. */
        /* The successor is identified by UUID and stored as 16 raw bytes, not
         * as text: identity inside a record should cost the same whether it is
         * the record's own id or the id of what replaced it. */
        {
            unsigned char existing[QRMEM_UUID_BYTES];
            size_t got = 0;
            char self_txt[QRMEM_UUID_TEXT_LEN + 1];
            char old_txt[QRMEM_UUID_TEXT_LEN + 1];
            char new_txt[QRMEM_UUID_TEXT_LEN + 1];
            have_by = (qrmem_rec_get_bytes(&r, QRMEM_TLV_SUCCESSOR, existing,
                                           sizeof existing, &got) == 0 &&
                       got == QRMEM_UUID_BYTES);
            qrmem_uuid_text(&r.id, self_txt, sizeof self_txt);
            if (!have_by) {
                if (qrmem_rec_add_bytes(&r, QRMEM_TLV_SUCCESSOR, by_id.b,
                                        QRMEM_UUID_BYTES) != 0) {
                    set_err(err, errlen,
                            "no room in record (screen %u, block %u, slot %u) to "
                            "record the successor",
                            screen, block, slot);
                    return -1;
                }
            } else {
                qrmem_uuid_t old;
                memcpy(old.b, existing, QRMEM_UUID_BYTES);
                qrmem_uuid_text(&old, old_txt, sizeof old_txt);
                qrmem_uuid_text(&by_id, new_txt, sizeof new_txt);
                if (!qrmem_uuid_equal(&old, &by_id)) {
                    set_err(err, errlen,
                            "record %s already records successor %s; a record "
                            "names one successor",
                            self_txt, old_txt);
                    return -1;
                }
            }
        }
        qrmem_op_begin(ap, screen, NULL);
        rc = qrmem_cell_publish(ap, screen, block, slot, &r, err, errlen);
        if (rc != 0)
            return rc;
        qrmem_op_end(ap, screen);
    }
    qrmem_op_begin(ap, screen, NULL);
    rc = qrmem_cell_tomb(ap, screen, block, slot, err, errlen);
    if (rc == 0) {
        qrmem_plane_store_block(ap, screen, block);
        qrmem_op_end(ap, screen);
    }
    return rc;
}

/* Bounded inverted index.
 *
 * One fixed table per screen: QRMEM_INDEX_ENTRIES slots of (key_hash, cell).
 * A lookup reads 16 KiB of pairs instead of 4.7 MiB of cells, which is the
 * whole reason this table exists. Two properties are load-bearing:
 *
 *  - No scan fallback. An index miss is reported as a miss. A fallback scan is
 *    the exact cost being avoided, and a "helpful" fallback would quietly
 *    reintroduce it the first time a lookup missed.
 *  - No eviction. A full table refuses the insert. Evicting the entry some
 *    other reader is about to follow turns a capacity limit into a wrong
 *    answer, which is worse than a refusal.
 */
static qrmem_index_ent_t *table_for(const qrmem_ap_t *ap, uint32_t screen) {
    return ap->index + (size_t)screen * QRMEM_INDEX_ENTRIES;
}

/* The insert, without the ownership gate.
 *
 * Shared by the agent-facing path and the restore path, which differ only in
 * whether a live writer is required. Restore has none: it runs before any agent
 * exists, and it is rebuilding DERIVED state from the record that owns the key -
 * so requiring ownership there would make the rebuild impossible by
 * construction. Splitting it out is what keeps that difference explicit rather
 * than leaving a bypass flag someone can set by accident. */
static int index_insert(qrmem_ap_t *ap, uint32_t screen, const char *key,
                        uint32_t block, uint32_t slot, char *err,
                        size_t errlen) {
    qrmem_index_ent_t *t;
    size_t klen;
    uint32_t h, ci, first_free = QRMEM_INDEX_ENTRIES;
    if (!ap || !ap->hdr || !key) {
        set_err(err, errlen, "index put needs a fabric and a key");
        return -1;
    }
    if (!qrmem_screen_valid(screen)) {
        set_err(err, errlen, "screen %u does not exist (0..%u)", screen,
                QRMEM_SCREENS - 1u);
        return -1;
    }
    if (!qrmem_block_valid(block) || !qrmem_slot_valid(slot)) {
        set_err(err, errlen,
                "record (block %u, slot %u) is outside the fabric", block,
                slot);
        return -1;
    }
    klen = strlen(key);
    if (klen == 0 || klen > 256u) {
        set_err(err, errlen, "key length %zu is out of range (1..256)", klen);
        return -1;
    }
    h = qrmem_fnv1a32(key, klen);
    if (h == 0u)
        h = 1u; /* 0 is the empty-slot marker; fold the one colliding key onto 1 */
    ci = qrmem_record_index(block, slot);
    t = table_for(ap, screen);
    for (uint32_t i = 0; i < QRMEM_INDEX_ENTRIES; i++) {
        uint32_t cur = atomic_load_explicit(&t[i].key_hash,
                                            memory_order_acquire);
        if (cur == h) {
            uint32_t at = atomic_load_explicit(&t[i].cell_index,
                                               memory_order_acquire);
            if (at == ci)
                return 0; /* already indexed: idempotent */
            continue; /* same key, different cell: both stay reachable */
        }
        if (cur == 0u && first_free == QRMEM_INDEX_ENTRIES)
            first_free = i;
    }
    if (first_free == QRMEM_INDEX_ENTRIES) {
        set_err(err, errlen,
                "screen %u index is full (%u entries); refusing the insert "
                "rather than evicting an entry a reader may be following",
                screen, (unsigned)QRMEM_INDEX_ENTRIES);
        return -1;
    }
    /* Release on the cell pointer, which is the last word written. A reader
     * that acquires this key_hash is guaranteed to see the cell_index, and the
     * cell itself was published before this call. */
    atomic_store_explicit(&t[first_free].cell_index, ci, memory_order_relaxed);
    atomic_store_explicit(&t[first_free].key_hash, h, memory_order_release);
    return 0;
}

int qrmem_index_put(qrmem_ap_t *ap, uint32_t screen, qrmem_id_t id,
                    const char *key, uint32_t block, uint32_t slot, char *err,
                    size_t errlen) {
    /* Only the owning agent may change what a lookup finds on its screen. */
    if (qrmem_require_owner(ap, screen, id, err, errlen) != 0)
        return -1;
    return index_insert(ap, screen, key, block, slot, err, errlen);
}

/* Rebuild one derived index entry from a record that carries its own key.
 *
 * Called only by the restore path, after the record has been republished. Named
 * for what it does rather than made a flag on qrmem_index_put, because a caller
 * that can rebuild the index for a screen it does not own is exactly the hole
 * this split exists to avoid being opened from the agent surface. */
int qrmem_index_restore(qrmem_ap_t *ap, uint32_t screen, const char *key,
                        uint32_t block, uint32_t slot) {
    char err[256] = "";
    return index_insert(ap, screen, key, block, slot, err, sizeof err);
}

int qrmem_index_drop_cell(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                          uint32_t slot) {
    qrmem_index_ent_t *t;
    uint32_t ci;
    if (!ap || !ap->hdr || !qrmem_screen_valid(screen) ||
        !qrmem_block_valid(block) || !qrmem_slot_valid(slot))
        return -1;
    t = table_for(ap, screen);
    ci = qrmem_record_index(block, slot);
    for (uint32_t i = 0; i < QRMEM_INDEX_ENTRIES; i++) {
        if (atomic_load_explicit(&t[i].key_hash, memory_order_acquire) == 0u)
            continue;
        if (atomic_load_explicit(&t[i].cell_index, memory_order_acquire) == ci)
            /* Clear the key last: a reader that sees the slot empty has already
             * acquired the release that cleared it, so it cannot be mid-read on
             * a half-torn entry. */
            atomic_store_explicit(&t[i].key_hash, 0u, memory_order_release);
    }
    return 0;
}

int qrmem_index_drop_key(qrmem_ap_t *ap, uint32_t screen, const char *key) {
    qrmem_index_ent_t *t;
    size_t klen;
    uint32_t h;
    if (!ap || !ap->hdr || !key || !qrmem_screen_valid(screen))
        return -1;
    klen = strlen(key);
    if (klen == 0 || klen > 256u)
        return -1;
    h = qrmem_fnv1a32(key, klen);
    if (h == 0u)
        h = 1u;
    t = table_for(ap, screen);
    for (uint32_t i = 0; i < QRMEM_INDEX_ENTRIES; i++)
        if (atomic_load_explicit(&t[i].key_hash, memory_order_acquire) == h)
            atomic_store_explicit(&t[i].key_hash, 0u, memory_order_release);
    return 0;
}

int qrmem_index_lookup(qrmem_ap_t *ap, uint32_t screen, const char *key,
                       uint32_t cap, uint32_t *out_block, uint32_t *out_slot,
                       size_t *n_out, char *err, size_t errlen) {
    const qrmem_index_ent_t *t;
    size_t klen, found = 0;
    uint32_t h;
    if (!ap || !ap->hdr || !key || !out_block || !out_slot || !n_out) {
        set_err(err, errlen, "index lookup needs a fabric, a key and outputs");
        return -1;
    }
    if (!qrmem_screen_valid(screen)) {
        set_err(err, errlen, "screen %u does not exist (0..%u)", screen,
                QRMEM_SCREENS - 1u);
        return -1;
    }
    if (cap == 0u || cap > QRMEM_INDEX_ENTRIES) {
        set_err(err, errlen, "lookup cap %u is out of range (1..%u)", cap,
                QRMEM_INDEX_ENTRIES);
        return -1;
    }
    klen = strlen(key);
    if (klen == 0 || klen > 256u) {
        set_err(err, errlen, "key length %zu is out of range (1..256)", klen);
        return -1;
    }
    h = qrmem_fnv1a32(key, klen);
    if (h == 0u)
        h = 1u;
    t = table_for(ap, screen);
    for (uint32_t i = 0; i < QRMEM_INDEX_ENTRIES && found < cap; i++) {
        /* Acquire, paired with the writer's release on key_hash. */
        if (atomic_load_explicit(&t[i].key_hash, memory_order_acquire) != h)
            continue;
        out_block[found] = atomic_load_explicit(&t[i].cell_index,
                                              memory_order_acquire) /
                          QRMEM_SLOTS_PER_BLOCK;
        out_slot[found] = atomic_load_explicit(&t[i].cell_index,
                                             memory_order_acquire) %
                         QRMEM_SLOTS_PER_BLOCK;
        found++;
    }
    *n_out = found;
    return 0;
}
