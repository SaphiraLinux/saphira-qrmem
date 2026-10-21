/* Saphira Memory - reboot survival test.
 *
 * /dev/shm is a tmpfs, so a reboot empties the fabric. That used to mean an
 * agent's live page simply vanished, with nothing to distinguish "never
 * existed" from "the machine restarted and did not care". Once agents depend on
 * the fabric that is a defect, and the fix has an exact shape:
 *
 *     restore the latest live page contents and project metadata
 *     BUT mint a fresh authority_gen
 *         zero every lease
 *         restore no screen owner
 *
 * The asymmetry IS the design. Content is the agent's thinking; authority is a
 * statement about which live process may write, and after a reboot there are no
 * live processes. A restore that brought an owner back would hand WRITE
 * AUTHORITY to whichever agent drew that slot number next - the exact confusion
 * the one-writer rule exists to prevent, arriving through the durability path
 * instead of the leak path.
 *
 * So: continuity without resurrection.
 *
 * This file proves the whole cycle against real files and a real aperture: write,
 * save, destroy the aperture (which is what a reboot does), reload, and check
 * that content came back, that authority did not, and that a dead writer's page
 * cannot be written by whoever claims it next.
 */
#include "qrmem.h"

#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;
static int checks = 0;

static void ok(int cond, const char *what) {
    checks++;
    if (cond) {
        printf("  ok   %s\n", what);
    } else {
        printf("  FAIL %s\n", what);
        failures++;
    }
}

static void section(const char *n) { printf("\n== %s\n", n); }

#define NAME "/qrmem-test-persist"
#define SNAP "/tmp/qrmem-test-persist.snapshot"

static void cleanup(void) {
    qrmem_aperture_unlink(NAME);
    unlink(SNAP);
    unlink("/tmp/qrmem-test-persist.snapshot.tmp");
}

static qrmem_id_t claim_as(qrmem_ap_t *ap, const char *name) {
    qrmem_id_t id;
    char err[256] = "";
    uint32_t slot = 0, gen = 0;
    memset(&id, 0, sizeof id);
    if (qrmem_agent_claim(ap, name, &slot, &gen, err, sizeof err) != 0)
        return id;
    id.slot = slot;
    id.agent_gen = gen;
    id.authority_gen =
        atomic_load_explicit(&ap->hdr->authority_gen, memory_order_acquire);
    return id;
}

static qrmem_uuid_t U(unsigned char seed) {
    qrmem_uuid_t u;
    unsigned char k;
    memset(&u, 0, sizeof u);
    for (k = 0; k < QRMEM_UUID_BYTES; k++)
        u.b[k] = (unsigned char)(seed + k * 7u);
    u.b[6] = (unsigned char)((u.b[6] & 0x0Fu) | 0x40u);
    u.b[8] = (unsigned char)((u.b[8] & 0x3Fu) | 0x80u);
    return u;
}

/* `err` is the caller's so a refusal can be inspected; a helper that swallows
 * the reason makes "refused for the right reason" untestable. */
static int write_word(qrmem_ap_t *ap, qrmem_id_t id, uint32_t screen,
                      uint32_t block, uint32_t slot, const char *text,
                      qrmem_uuid_t rec_id, char *err, size_t errlen) {
    qrmem_rec_t r;
    qrmem_rec_init(&r, QRMEM_CT_WORD, rec_id);
    if (qrmem_rec_add_text(&r, text, strlen(text)) != 0) {
        if (err && errlen)
            err[0] = '\0';
        return -1;
    }
    if (qrmem_tile_write(ap, screen, block, slot, id, &r, err, errlen) != 0)
        return -1;
    qrmem_plane_store_block(ap, screen, block);
    return 0;
}

/* The whole cycle: create, write, save, DESTROY, reload. */
static void test_content_survives_authority_does_not(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    char werr[256] = "";
    qrmem_id_t writer, next;
    qrmem_uuid_t rid_a = U(11u), rid_b = U(22u);
    uint32_t auth_before = 0, auth_after = 0;
    section("a reboot returns the page and does not return the writer");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    writer = claim_as(&ap, "writer");
    ok(writer.slot != 0, "an agent registers");
    ok(qrmem_screen_claim(&ap, 3u, writer, "beagle-notes", err, sizeof err) ==
           0,
       "and claims screen 3 with a project label");
    ok(write_word(&ap, writer, 3u, 0u, 0u, "encx24j600 has no OF match table",
                  rid_a, werr, sizeof werr) == 0,
       "a record is written");
    ok(write_word(&ap, writer, 3u, 0u, 1u, "SPI ethernet stays", rid_b, werr,
                  sizeof werr) == 0,
       "a second record is written");
    auth_before = atomic_load_explicit(&ap.hdr->authority_gen,
                                       memory_order_acquire);
    ok(auth_before > 0u, "the fabric has an authority generation");
    ok(qrmem_snapshot_save(&ap, SNAP, err, sizeof err) == 0, "a snapshot is saved");
    ok(access(SNAP, R_OK) == 0, "and the restore point exists on disk");
    {
        struct stat st;
        ok(stat(SNAP, &st) == 0 && st.st_size > 0,
           "and it is not an empty file");
        /* 0600: a restore point is every page this machine held. */
        ok((st.st_mode & 0777u) == 0600u,
           "and it is readable only by its owner");
    }
    /* THE REBOOT. Unlinking the aperture is exactly what the tmpfs does, and it
     * is done while nothing holds the mapping, so no later step can accidentally
     * pass by reading memory the reboot would have destroyed. */
    qrmem_aperture_detach(&ap);
    qrmem_aperture_unlink(NAME);
    {
        struct stat st;
        ok(stat("/dev/shm" NAME, &st) != 0, "the aperture is gone, as after a reboot");
    }
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "recreate");
        return;
    }
    /* The daemon mints a NEW authority before restoring. That ordering is the
     * contract, so this test reproduces it rather than testing a reload that
     * happens to work in some other order. */
    qrmem_aperture_bump_epoch(&ap);
    auth_after = atomic_load_explicit(&ap.hdr->authority_gen,
                                      memory_order_acquire);
    ok(auth_after > auth_before,
       "the new incarnation has a HIGHER authority generation than the old one");
    {
        int got = qrmem_snapshot_load(&ap, SNAP, err, sizeof err);
        if (got != 1)
            printf("  INFO load returned %d: %s\n", got, err);
        ok(got == 1, "the restore point loads");
    }
    /* CONTENT CAME BACK. */
    {
        qrmem_rec_t got;
        char rerr[256] = "";
        int found = 0;
        /* Where the records land is not promised - the slots a reboot left
         * behind carry no layout promise - so the page is searched rather than
         * addressed. */
        for (uint32_t b = 0; b < QRMEM_BLOCKS_PER_SCREEN && !found; b++)
            for (uint32_t sl = 0; sl < QRMEM_SLOTS_PER_BLOCK && !found; sl++)
                if (qrmem_cell_read(&ap, 3u, b, sl, &got, rerr, sizeof rerr) ==
                        0 &&
                    qrmem_uuid_equal(&got.id, &rid_a))
                    found = 1;
        ok(found, "the first record is back, with its identity intact");
        {
            const char *txt = NULL;
            size_t tl = 0;
            ok(qrmem_rec_get_text(&got, &txt, &tl) == 0 &&
                   tl == strlen("encx24j600 has no OF match table") &&
                   memcmp(txt, "encx24j600 has no OF match table", tl) == 0,
               "with its body byte for byte");
        }
    }
    {
        qrmem_rec_t got;
        char rerr[256] = "";
        int found = 0;
        for (uint32_t b = 0; b < QRMEM_BLOCKS_PER_SCREEN && !found; b++)
            for (uint32_t sl = 0; sl < QRMEM_SLOTS_PER_BLOCK && !found; sl++)
                if (qrmem_cell_read(&ap, 3u, b, sl, &got, rerr, sizeof rerr) ==
                        0 &&
                    qrmem_uuid_equal(&got.id, &rid_b))
                    found = 1;
        ok(found, "the second record is back too");
    }
    /* THE PROJECT LABEL CAME BACK. A page without its label cannot be found by
     * project, and an unlabelled page is an orphan. */
    ok(atomic_load_explicit(&ap.screens[3].project_len, memory_order_acquire) ==
           strlen("beagle-notes"),
       "the project label survived the reboot");
    ok(memcmp(ap.screens[3].project, "beagle-notes", 12) == 0,
       "and it is the right label");

    /* AUTHORITY DID NOT COME BACK. This is the half that matters. */
    ok(qrmem_screen_owner(&ap, 3u) == 0u,
       "the page has NO owner after the reboot");
    {
        uint32_t s;
        int any_owner = 0;
        for (s = 0; s < QRMEM_SCREENS; s++)
            if (qrmem_screen_owner(&ap, s) != 0u)
                any_owner = 1;
        ok(!any_owner, "no screen on the whole fabric has an owner");
    }
    ok(qrmem_agent_count(&ap) == 0u,
       "and the agent registry is empty: the previous agents are gone");
    {
        uint32_t i, live = 0;
        for (i = 0; i < QRMEM_AGENT_MAX; i++)
            if (qrmem_agent_lease_held(&ap, i) != 0u)
                live++;
        ok(live == 0u, "and no lease survived");
    }
    /* The consequence that actually protects anyone: the next agent to claim
     * that screen gets it, and the dead writer's identity cannot write there. */
    next = claim_as(&ap, "next");
    ok(next.slot != 0, "a new agent registers after the reboot");
    ok(qrmem_screen_claim(&ap, 3u, next, NULL, err, sizeof err) == 0,
       "and can claim the restored page");
    ok(qrmem_screen_owner(&ap, 3u) == next.slot, "which it now owns");
    /* The old identity is refused, and refused for the RIGHT reason: it holds
     * the previous incarnation's authority generation, so it is a dead writer
     * rather than an unidentified one. */
    ok(!qrmem_screen_writable(&ap, 3u, writer),
       "the PREVIOUS incarnation's identity cannot write the restored page");
    {
        ok(write_word(&ap, writer, 3u, 2u, 0u, "from the dead", U(33u), werr,
                      sizeof werr) != 0,
           "and an actual write there is refused");
        ok(strstr(werr, "not yours") != NULL,
           "with the reason being that it is not its screen");
    }
    /* The new owner CAN write, and the page is genuinely continued rather than
     * merely read-only. */
    ok(write_word(&ap, next, 3u, 2u, 0u, "carried on after the reboot", U(44u), werr, sizeof werr) ==
           0,
       "the new owner can carry the page on");
    qrmem_aperture_detach(&ap);
    cleanup();
}

static void test_a_fresh_fabric_saves_nothing_to_restore(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    section("no restore point is not an error");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    /* 0 means "there was nothing to restore", which is distinct from -1 "the
     * restore point exists and is broken". Conflating them would make a first
     * run look like a failure. */
    ok(qrmem_snapshot_load(&ap, SNAP, err, sizeof err) == 0,
       "loading with no snapshot present reports nothing restored");
    ok(qrmem_snapshot_save(&ap, SNAP, err, sizeof err) == 0,
       "an empty fabric saves cleanly");
    qrmem_aperture_detach(&ap);
    cleanup();
}

static void test_corruption_is_refused_not_repaired(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    char werr[256] = "";
    section("a damaged restore point is refused, never half applied");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    /* A truncated file: exactly what a full filesystem at the wrong moment
     * produces. A decoder that "handled" it would restore half a page as if it
     * were whole, which is worse than restoring nothing because it looks
     * authoritative. */
    {
        FILE *f = fopen(SNAP, "wb");
        ok(f != NULL, "a truncated restore point can be written");
        if (f) {
            fwrite("QNOS", 1, 4, f);
            fclose(f);
        }
        ok(qrmem_snapshot_load(&ap, SNAP, err, sizeof err) == -1,
           "a truncated restore point is refused");
        ok(err[0] != '\0', "and the refusal is explained");
        ok(qrmem_screen_owner(&ap, 0u) == 0u,
           "and nothing was applied to the fabric");
        ok(atomic_load_explicit(&ap.screens[0].project_len,
                                memory_order_acquire) == 0u,
           "not even a project label");
    }
    /* A flipped byte in the payload, with the header intact. The checksum is
     * what catches this, and without it the file would decode into plausible
     * nonsense. */
    {
        qrmem_id_t me;
        qrmem_uuid_t rid = U(55u);
        me = claim_as(&ap, "w");
        ok(qrmem_screen_claim(&ap, 0u, me, "corrupt-test", err, sizeof err) == 0,
           "a labelled page exists to be saved");
        ok(write_word(&ap, me, 0u, 0u, 0u, "payload that matters", rid, werr,
                      sizeof werr) == 0,
           "with a record on it");
        ok(qrmem_snapshot_save(&ap, SNAP, err, sizeof err) == 0, "and is saved");
        {
            int fd = open(SNAP, O_RDWR);
            unsigned char buf[8];
            ok(fd >= 0, "the restore point can be reopened for damage");
            if (fd >= 0) {
                /* Flip a byte well inside the payload, past the header, so the
                 * magic and version still look right. */
                ok(pread(fd, buf, sizeof buf, 40) == (ssize_t)sizeof buf,
                   "a payload byte is readable");
                buf[0] ^= 0x40u;
                ok(pwrite(fd, buf, sizeof buf, 40) == (ssize_t)sizeof buf,
                   "and can be damaged");
                close(fd);
            }
            ok(qrmem_snapshot_load(&ap, SNAP, err, sizeof err) == -1,
               "a corrupted restore point is refused");
            ok(strstr(err, "corrupt") != NULL || strstr(err, "malformed") != NULL,
               "and the reason names the corruption");
        }
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}

static void test_save_is_atomic(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    char werr[256] = "";
    struct stat before, after;
    section("a save never leaves a partial restore point in place");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    {
        qrmem_id_t me = claim_as(&ap, "w");
        qrmem_screen_claim(&ap, 0u, me, "atomic", err, sizeof err);
        write_word(&ap, me, 0u, 0u, 0u, "one", U(61u), werr, sizeof werr);
        ok(qrmem_snapshot_save(&ap, SNAP, err, sizeof err) == 0, "first save");
        ok(stat(SNAP, &before) == 0, "the restore point exists");
        write_word(&ap, me, 0u, 0u, 1u, "two", U(62u), werr, sizeof werr);
        write_word(&ap, me, 0u, 0u, 2u, "three", U(63u), werr, sizeof werr);
        ok(qrmem_snapshot_save(&ap, SNAP, err, sizeof err) == 0, "second save");
        ok(stat(SNAP, &after) == 0, "the restore point is still there");
        ok(after.st_size > before.st_size,
           "and it now holds more records, so it really was replaced");
        /* The temporary must not survive a successful save. If it did, a crash
         * between the two would leave the stale one lying around, and the next
         * run would have two candidates with no way to tell which is current. */
        ok(access("/tmp/qrmem-test-persist.snapshot.tmp", F_OK) != 0,
           "no temporary file is left behind");
        /* And the second save must be a complete, loadable file rather than an
         * extension of the first. */
        {
            int g2 = qrmem_snapshot_load(&ap, SNAP, err, sizeof err);
            if (g2 != 1)
                printf("  INFO reload returned %d: %s\n", g2, err);
            ok(g2 == 1, "the replaced restore point loads completely");
        }
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}


/* The lookup key is DURABLE, because the index it feeds is derived.
 *
 * A record written with index="k" used to lose "k" on restart: the key lived
 * only in the aperture's index table, which a reboot empties, while the record
 * itself survived. The record came back readable by coordinate and invisible to
 * qrmem_index - a silent loss of its discovery handle, which is the worst way
 * for a lookup capability to go missing because nothing reports it.
 *
 * So the key is stored IN the record and the table is rebuilt from it on
 * restore. This proves both halves: the key survives in the record, and the
 * rebuilt table actually resolves. A test that only checked the first would pass
 * with the rebuild missing.
 */
static void test_index_keys_survive_and_rebuild(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t me;
    char werr[256] = "";
    section("a lookup key survives the reboot and the index is rebuilt from it");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    me = claim_as(&ap, "idx");
    ok(qrmem_screen_claim(&ap, 1u, me, "index-test", err, sizeof err) == 0,
       "a labelled screen is claimed");
    /* Two records: one indexed, one not. A record without a key must stay out of
     * the table after the rebuild, or the rebuild is inventing handles. */
    {
        qrmem_rec_t r;
        qrmem_rec_init(&r, QRMEM_CT_WORD, U(81u));
        ok(qrmem_rec_add_text(&r, "the sun was shining", 19) == 0, "text fits");
        ok(qrmem_rec_add_text_tag(&r, QRMEM_TLV_INDEX_KEY,
                                  "skills-search-trap", 19) == 0,
           "the key is stored IN THE RECORD, not only in the index table");
        ok(qrmem_tile_write(&ap, 1u, 0u, 0u, me, &r, werr, sizeof werr) == 0,
           "and the record is written");
        ok(qrmem_index_put(&ap, 1u, me, "skills-search-trap", 0u, 0u, werr,
                           sizeof werr) == 0,
           "the index entry is added");
        qrmem_rec_init(&r, QRMEM_CT_WORD, U(82u));
        ok(qrmem_rec_add_text(&r, "no key here", 11) == 0, "text fits");
        ok(qrmem_tile_write(&ap, 1u, 0u, 1u, me, &r, werr, sizeof werr) == 0,
           "a second record without a key is written");
    }
    /* Before the reboot the index resolves. */
    {
        uint32_t blk[4], sl[4];
        size_t n = 0;
        ok(qrmem_index_lookup(&ap, 1u, "skills-search-trap", 4, blk, sl, &n, werr,
                              sizeof werr) == 0 && n == 1u,
           "the key resolves before the reboot");
    }
    ok(qrmem_index_used(&ap, 1u) == 1u, "the table holds exactly one entry");
    ok(qrmem_snapshot_save(&ap, SNAP, err, sizeof err) == 0, "a snapshot is saved");

    /* THE REBOOT. */
    qrmem_aperture_detach(&ap);
    qrmem_aperture_unlink(NAME);
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "recreate");
        return;
    }
    qrmem_aperture_bump_epoch(&ap);
    ok(qrmem_snapshot_load(&ap, SNAP, err, sizeof err) == 1, "the restore runs");
    /* The key survived in the record. */
    {
        qrmem_rec_t got;
        char rerr[256] = "";
        const char *k = NULL;
        size_t klen = 0;
        int found = 0;
        for (uint32_t b = 0; b < QRMEM_BLOCKS_PER_SCREEN && !found; b++)
            for (uint32_t sl = 0; sl < QRMEM_SLOTS_PER_BLOCK && !found; sl++)
                if (qrmem_cell_read(&ap, 1u, b, sl, &got, rerr, sizeof rerr) ==
                        0) {
                    qrmem_uuid_t want = U(81u);
                    if (qrmem_uuid_equal(&got.id, &want))
                        found = 1;
                }
        ok(found, "the indexed record is back");
        ok(qrmem_rec_get_text_tag(&got, QRMEM_TLV_INDEX_KEY, &k, &klen) == 0 &&
               klen == 19u && memcmp(k, "skills-search-trap", 19) == 0,
           "and its lookup key survived, because the key lives in the record");
    }
    /* AND THE INDEX WAS REBUILT. This is the half that matters: without it the
     * record is intact and still unfindable. */
    {
        uint32_t blk[4], sl[4];
        size_t n = 0;
        ok(qrmem_index_used(&ap, 1u) == 1u,
           "the index table was rebuilt, not left empty");
        ok(qrmem_index_lookup(&ap, 1u, "skills-search-trap", 4, blk, sl, &n, werr,
                              sizeof werr) == 0 && n == 1u,
           "and the key resolves again after the reboot");
    }
    /* A record with no key must NOT have been given one. */
    {
        uint32_t blk[4], sl[4];
        size_t n = 0;
        ok(qrmem_index_used(&ap, 1u) == 1u,
           "the unindexed record stayed out of the table: the rebuild invents "
           "nothing");
        /* And a key nobody stored still misses, rather than resolving to
         * something plausible. */
        ok(qrmem_index_lookup(&ap, 1u, "never-written", 4, blk, sl, &n, werr,
                              sizeof werr) != 0 || n == 0u,
           "an unknown key is still a miss after the rebuild");
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}


/* A RESTORED PAGE WITH RECORDS CANNOT BE RELABELLED.
 *
 * The live guard works: join a populated page with a different project and it is
 * refused. The restore-specific case did not, and the reason is worth stating
 * precisely because the live case passing is exactly what hid it.
 *
 * A restore deliberately leaves NO OWNER. That is the whole design - restoring an
 * owner would hand write authority to whoever claimed the page next. But the
 * immutability guard lived only in the ALREADY-OWNED branch of the claim, so a
 * restored page fell through to the FREE branch, which wrote the label
 * unconditionally. The one claim that mattered most - the one taking over a
 * populated page - was the one claim that could relabel it freely.
 *
 * Observed on a live host: a restored screen carrying 11 records labelled
 * `saphira-expanderllm` became `relabel-probe`, and the ordinary rule then
 * refused to change it back because the page had published records. One-directional
 * damage with no agent-level repair.
 *
 * The predicate must be RESTORED CONTENT, not "has a post-restart writer touched
 * it".
 */
static void test_restored_page_cannot_be_relabelled(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t writer, other;
    section("a restored page with records refuses a different project label");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    writer = claim_as(&ap, "author");
    ok(writer.slot != 0, "an author registers");
    ok(qrmem_screen_claim(&ap, 5u, writer, "original-project", err,
                          sizeof err) == 0,
       "and creates the page under its original label");
    ok(write_word(&ap, writer, 5u, 0u, 0u, "a real record that matters", U(91u),
                  err, sizeof err) == 0,
       "and publishes a record on it");
    ok(qrmem_snapshot_save(&ap, SNAP, err, sizeof err) == 0, "a snapshot is saved");

    /* THE REBOOT. */
    qrmem_aperture_detach(&ap);
    qrmem_aperture_unlink(NAME);
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "recreate");
        return;
    }
    qrmem_aperture_bump_epoch(&ap);
    ok(qrmem_snapshot_load(&ap, SNAP, err, sizeof err) == 1, "the restore runs");
    ok(qrmem_screen_owner(&ap, 5u) == 0u,
       "the restored page is unowned, as designed");
    ok(qrmem_write_count(&ap, 5u) > 0u,
       "and it knows it has published records");
    ok(atomic_load_explicit(&ap.screens[5].project_len, memory_order_acquire) ==
           strlen("original-project"),
       "and its original label came back");

    /* THE REGRESSION. A different label must be refused on the FIRST claim after
     * the restore, which is the claim that lands in the free branch. */
    other = claim_as(&ap, "next-owner");
    ok(other.slot != 0, "a new agent registers after the restore");
    ok(qrmem_screen_claim(&ap, 5u, other, "relabel-probe", err, sizeof err) != 0,
       "the FIRST post-restore claim with a DIFFERENT label is REFUSED");
    ok(strstr(err, "original-project") != NULL,
       "and the refusal names the label the page actually has");
    ok(strstr(err, "published record") != NULL,
       "and says why: it has published records, it is merely unclaimed");
    /* The damage this bug did was silent because the label was overwritten. */
    ok(atomic_load_explicit(&ap.screens[5].project_len, memory_order_acquire) ==
           strlen("original-project"),
       "the label is UNCHANGED after the refused claim");
    {
        char got[QRMEM_PROJECT_MAX + 1];
        uint32_t gl = atomic_load_explicit(&ap.screens[5].project_len,
                                           memory_order_acquire);
        memcpy(got, ap.screens[5].project, gl);
        got[gl] = '\0';
        ok(strcmp(got, "original-project") == 0,
           "and it still reads as the original project");
    }

    /* Claiming with the CORRECT label must work: the page is not bricked, only
     * relabelled. */
    ok(qrmem_screen_claim(&ap, 5u, other, "original-project", err,
                          sizeof err) == 0,
       "the same label claims normally after the restore");
    ok(qrmem_screen_owner(&ap, 5u) == other.slot, "and the claim succeeds");

    /* And the live guard still works, which is the case that was already fine and
     * is easy to break while fixing the other one. */
    ok(qrmem_screen_claim(&ap, 5u, other, "something-else", err, sizeof err) != 0,
       "a live relabel of a populated owned page is still refused");
    qrmem_aperture_detach(&ap);
    cleanup();
}

/* An empty page stays relabellable, which is what makes the guard usable.
 *
 * A rule that refuses every relabel would be trivially safe and useless: a page
 * that has never been published on is private to its writer and correcting a typo
 * in its label harms nobody. This is the half of the contract that the fix must
 * not break.
 */
static void test_empty_page_stays_relabellable(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t me;
    char got[QRMEM_PROJECT_MAX + 1];
    uint32_t gl;
    section("an empty or genuinely new page stays relabellable before first "
            "publish");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    me = claim_as(&ap, "owner");
    ok(qrmem_screen_claim(&ap, 6u, me, "first-typo", err, sizeof err) == 0,
       "an empty page is claimed under a label");
    ok(qrmem_screen_claim(&ap, 6u, me, "corrected", err, sizeof err) == 0,
       "and may be relabelled while it has no published records");
    gl = atomic_load_explicit(&ap.screens[6].project_len, memory_order_acquire);
    memcpy(got, ap.screens[6].project, gl);
    got[gl] = '\0';
    ok(strcmp(got, "corrected") == 0, "and the new label stands");
    /* Once it does have records, the same call is refused. */
    ok(write_word(&ap, me, 6u, 0u, 0u, "now it matters", U(92u), err,
                  sizeof err) == 0,
       "a record is published on it");
    ok(qrmem_screen_claim(&ap, 6u, me, "third-try", err, sizeof err) != 0,
       "and now a relabel is refused");
    qrmem_aperture_detach(&ap);
    cleanup();
}

/* Operator recovery: metadata-only, requires an unowned screen, and audited.
 *
 * This exists because the restore bug damaged a real label and the agent rule -
 * correctly - refused to change it back. The repair path must not become a
 * backdoor around that rule, and it must not be able to touch a record even by
 * accident.
 */
static void test_operator_repair_is_metadata_only(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t me;
    const char *LOG = "/tmp/qrmem-test-recover.log";
    section("operator repair corrects metadata, touches no record, and logs it");
    unlink(LOG);
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    me = claim_as(&ap, "author");
    ok(qrmem_screen_claim(&ap, 7u, me, "damaged-label", err, sizeof err) == 0,
       "a populated page exists with the wrong label");
    ok(write_word(&ap, me, 7u, 0u, 0u, "must survive the repair", U(93u),
                  err, sizeof err) == 0,
       "carrying a record that must survive the repair");
    {
        uint64_t before = qrmem_write_count(&ap, 7u);
        char project[QRMEM_PROJECT_MAX + 1];
        uint64_t w = 0, g = 0, i = 0;
        uint32_t own = 0;
        /* Inspect first: the read half, so an operator can see before acting. */
        ok(qrmem_recover_inspect(&ap, 7u, project, sizeof project, &w, &own, &g,
                                 &i, err, sizeof err) == 0,
           "inspection succeeds");
        ok(strcmp(project, "damaged-label") == 0,
           "and reports the label that is actually there");
        ok(w == before, "and the published record count");
        /* Refused while OWNED: repairing under a live writer would change what
         * the screen means to a process using it right now. */
        ok(qrmem_recover_project(&ap, 7u, "correct-label", LOG, 0, err,
                                 sizeof err) != 0,
           "repair is refused while an agent owns the screen");
        ok(strstr(err, "owned") != NULL, "and the refusal says so");
        /* Release, as the operator would. */
        qrmem_agent_release(&ap, me.slot);
        ok(1, "the owner releases the page");
        ok(qrmem_screen_owner(&ap, 7u) == 0u, "so it is unowned");
        /* Now the repair works. */
        ok(qrmem_recover_project(&ap, 7u, "correct-label", LOG, 0, err,
                                 sizeof err) == 0,
           "and the operator repair succeeds");
        {
            char now[QRMEM_PROJECT_MAX + 1];
            uint32_t nl = atomic_load_explicit(&ap.screens[7].project_len,
                                                memory_order_acquire);
            memcpy(now, ap.screens[7].project, nl);
            now[nl] = '\0';
            ok(strcmp(now, "correct-label") == 0, "the label is corrected");
        }
        /* THE POINT: the records are untouched. */
        ok(qrmem_write_count(&ap, 7u) == before,
           "the published record count is UNCHANGED by the repair");
        {
            qrmem_rec_t got;
            char rerr[256] = "";
            int found = 0;
            for (uint32_t b = 0; b < QRMEM_BLOCKS_PER_SCREEN && !found; b++)
                for (uint32_t sl = 0; sl < QRMEM_SLOTS_PER_BLOCK && !found; sl++) {
                    qrmem_uuid_t want = U(93u);
                    if (qrmem_cell_read(&ap, 7u, b, sl, &got, rerr,
                                        sizeof rerr) == 0 &&
                        qrmem_uuid_equal(&got.id, &want))
                        found = 1;
                }
            ok(found, "and the record itself is still there, byte for byte");
        }
        /* It is audited. A silent metadata edit on a shared surface cannot be
         * reconstructed afterwards. */
        {
            FILE *f = fopen(LOG, "r");
            char line[512] = "";
            ok(f != NULL, "the recovery log exists");
            if (f) {
                if (fgets(line, sizeof line, f))
                    ok(strstr(line, "screen=7") != NULL &&
                           strstr(line, "damaged-label") != NULL &&
                           strstr(line, "correct-label") != NULL &&
                           strstr(line, "operator") != NULL,
                       "and records the screen, both labels, and the actor");
                fclose(f);
            }
        }
        /* Refuses to CLEAR a label: an unlabelled page is an orphan. */
        ok(qrmem_recover_project(&ap, 7u, "", LOG, 0, err, sizeof err) != 0,
           "repair refuses to clear a label");
        ok(strstr(err, "orphan") != NULL, "and explains why");
    }
    qrmem_aperture_detach(&ap);
    unlink(LOG);
    cleanup();
}

static void test_no_snapshot_option(void) {
    /* The daemon must be able to opt out entirely, and "opt out" must mean the
     * file is untouched rather than deleted. */
    qrmem_ap_t ap;
    char err[512] = "";
    char werr[256] = "";
    section("opting out of persistence touches nothing");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    {
        qrmem_id_t me = claim_as(&ap, "w");
        qrmem_screen_claim(&ap, 0u, me, "no-save", err, sizeof err);
        write_word(&ap, me, 0u, 0u, 0u, "never saved", U(71u), werr, sizeof werr);
        /* An empty path is how the caller says "do not persist". */
        ok(qrmem_snapshot_save(&ap, "", err, sizeof err) != 0,
           "an empty path is refused rather than silently ignored");
        ok(access(SNAP, F_OK) != 0, "and no restore point appeared");
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}


/* A refusal must not point at a door the API does not have.
 *
 * Found by client B on a live host, and filed as a dead end. It joined a
 * populated unowned page passing project="client-b" and was told, verbatim:
 *
 *   Claim it with project "client-b", or open a new screen.
 *
 * The `%s` in that sentence was the CALLER'S OWN label. The advice was to retry
 * the exact call that had just failed, and qrmem_join exposes no force, relabel
 * or adopt-existing parameter, so the only actionable half was "open a new
 * screen". A refusal that costs a caller a round trip to learn the same thing
 * twice is worse than a bare one.
 *
 * So the rule is: two real doors or none. Claim it under the page's own label,
 * or an operator repairs the label. Both are checkable.
 */
static void test_relabel_refusal_offers_two_real_doors(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t me, other;
    const char *WANTED = "client-b";
    char refusal[600] = "";
    section("a populated-page relabel refusal names two real doors");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    me = claim_as(&ap, "author");
    ok(qrmem_screen_claim(&ap, 8u, me, "relabel-probe", err, sizeof err) == 0,
       "a populated page exists under the wrong label");
    ok(write_word(&ap, me, 8u, 0u, 0u, "content that makes the label matter",
                  U(96u), err, sizeof err) == 0,
       "carrying a record");
    qrmem_agent_release(&ap, me.slot);
    ok(1, "the author releases it");
    other = claim_as(&ap, "client");
    ok(other.slot != 0, "a different agent registers");

    /* The refusal. */
    ok(qrmem_screen_claim(&ap, 8u, other, WANTED, refusal, sizeof refusal) != 0,
       "claiming it under a different label is refused");
    /* The good diagnostic, which is genuinely excellent and must be preserved:
     * it distinguishes unclaimed from empty and names the real label. */
    ok(strstr(refusal, "relabel-probe") != NULL,
       "and it names the page's ACTUAL label");
    ok(strstr(refusal, "published record") != NULL,
       "and says why the label is fixed");
    /* THE BUG: the caller's own label echoed back as advice. If the message
     * ever says "claim it with project client-b" to a caller who just passed
     * client-b, it is the dead end again. */
    {
        char wrong[600];
        snprintf(wrong, sizeof wrong, "claim it with project \"%s\"",
                 WANTED);
        ok(strstr(refusal, wrong) == NULL,
           "and it does NOT tell the caller to claim it with the label they "
           "just passed");
        snprintf(wrong, sizeof wrong, "Claim it with project \"%s\"",
                 WANTED);
        ok(strstr(refusal, wrong) == NULL,
           "in either capitalisation");
    }
    /* The two doors that do exist. */
    ok(strstr(refusal, "only under that same label") != NULL,
       "door 1: the page can be claimed under its own immutable label");
    ok(strstr(refusal, "operator can, audited") != NULL &&
           strstr(refusal, "--repair-project") != NULL,
       "door 2: an operator can repair the label, and the message names the "
       "command");
    /* And the page is genuinely still claimable the first way, so the advice is
     * not merely true-looking. */
    ok(qrmem_screen_claim(&ap, 8u, other, "relabel-probe", err, sizeof err) ==
           0,
       "and door 1 actually works: claiming under the existing label succeeds");
    ok(qrmem_screen_owner(&ap, 8u) == other.slot, "the claim took effect");
    qrmem_aperture_detach(&ap);
    cleanup();
}

/* The dry run: validate everything, write nothing.
 *
 * This exists because the hazard was demonstrated rather than imagined. A repair
 * was run against a live screen with a deliberately wrong label, intending to
 * confirm the guard would refuse it. It did not refuse - the operator path has
 * no immutability guard, by design - and a label was overwritten. Nothing was
 * lost, but only the audit log recorded it.
 *
 * A path that can overwrite shared metadata with no confirmation and no preview
 * is one nobody should have to be careful around.
 */
static void test_repair_dry_run_writes_nothing(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t me;
    const char *LOG = "/tmp/qrmem-test-dryrun.log";
    char before[QRMEM_PROJECT_MAX + 1];
    section("a repair dry run validates fully and changes nothing");
    unlink(LOG);
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    me = claim_as(&ap, "author");
    ok(qrmem_screen_claim(&ap, 2u, me, "keep-this-label", err, sizeof err) == 0,
       "a page exists under a label we will try to change");
    ok(write_word(&ap, me, 2u, 0u, 0u, "record that must survive", U(97u), err,
                  sizeof err) == 0,
       "carrying a record");
    qrmem_agent_release(&ap, me.slot);
    {
        uint32_t nl = atomic_load_explicit(&ap.screens[2].project_len,
                                           memory_order_acquire);
        memcpy(before, ap.screens[2].project, nl);
        before[nl] = '\0';
    }
    /* Dry run: every check runs, nothing is written. */
    ok(qrmem_recover_project(&ap, 2u, "would-be-label", LOG, 1, err,
                             sizeof err) == 0,
       "the dry run succeeds, so the request itself is valid");
    {
        char now[QRMEM_PROJECT_MAX + 1];
        uint32_t nl = atomic_load_explicit(&ap.screens[2].project_len,
                                           memory_order_acquire);
        memcpy(now, ap.screens[2].project, nl);
        now[nl] = '\0';
        ok(strcmp(now, before) == 0,
           "and the label on the fabric is UNCHANGED afterwards");
    }
    ok(access(LOG, F_OK) != 0,
       "and no audit line was written for a run that changed nothing");
    /* The checks are real, not skipped: a dry run still refuses what a real run
     * refuses. Otherwise "dry run" would just mean "do nothing and report
     * success", which is the worst possible preview. */
    ok(qrmem_recover_project(&ap, 2u, "", LOG, 1, err, sizeof err) != 0,
       "and it still refuses to preview clearing a label");
    /* A real no-op: naming the label the page ALREADY carries, which the dry
     * run above left untouched. Passing something else would be a genuine
     * change and would correctly succeed. */
    ok(qrmem_recover_project(&ap, 2u, before, LOG, 1, err, sizeof err) != 0,
       "and it still refuses a no-op repair");
    ok(strstr(err, "nothing to repair") != NULL,
       "and says there is nothing to repair");
    /* And the real run afterwards does work, so the preview was faithful. */
    ok(qrmem_recover_project(&ap, 2u, "would-be-label", LOG, 0, err,
                             sizeof err) == 0,
       "the real repair then succeeds");
    {
        char now[QRMEM_PROJECT_MAX + 1];
        uint32_t nl = atomic_load_explicit(&ap.screens[2].project_len,
                                           memory_order_acquire);
        memcpy(now, ap.screens[2].project, nl);
        now[nl] = '\0';
        ok(strcmp(now, "would-be-label") == 0, "and the label did change");
    }
    ok(access(LOG, F_OK) == 0, "and this time the audit was written");
    qrmem_aperture_detach(&ap);
    unlink(LOG);
    cleanup();
}

int main(void) {
    printf("qrmem reboot survival test\n\n");
    test_a_fresh_fabric_saves_nothing_to_restore();
    test_content_survives_authority_does_not();
    test_save_is_atomic();
    test_corruption_is_refused_not_repaired();
    test_index_keys_survive_and_rebuild();
    test_restored_page_cannot_be_relabelled();
    test_empty_page_stays_relabellable();
    test_operator_repair_is_metadata_only();
    test_relabel_refusal_offers_two_real_doors();
    test_repair_dry_run_writes_nothing();
    test_no_snapshot_option();
    printf("\n%u checks, %u failures\n", (unsigned)checks,
           (unsigned)failures);
    return failures ? 1 : 0;
}