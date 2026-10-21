/* Saphira Memory - code plane contract test.
 *
 * The plane is the part a human actually looks at, so the property under test is
 * not "it renders" but "what it renders is really what is stored".
 *
 * Every case here goes through qrmem_plane_verify_block, which decodes from the
 * packed plane and compares against the record store WITHOUT re-encoding. That
 * asymmetry is the point: if the encoder were consulted, a lossy or miscompiled
 * encoder would happily agree with itself and no test would ever fail.
 *
 * The corruption cases write directly into the mapped aperture, the way a
 * confused process, a bad pointer, or hardware would - not through the API. If
 * the decode path cannot catch that, a viewer built on it would show a
 * confident, well-formed, wrong image. */

#include "qrmem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int checks = 0, failures = 0;

static void ok(int cond, const char *what) {
    checks++;
    if (cond) {
        printf("  ok   %s\n", what);
    } else {
        printf("  FAIL %s\n", what);
        failures++;
    }
}


#define NAME "/qrmem-test-plane"

static void cleanup(void) { qrmem_aperture_unlink(NAME); }

/* Count light and dark modules in one 7x7 corner. */
static void corner_counts(const unsigned char *mods, size_t *dark, size_t *light) {
    size_t d = 0, l = 0, bx, by;
    for (by = 0; by < 7u; by++)
        for (bx = 0; bx < 7u; bx++) {
            if (mods[by * QRMEM_BLOCK_DIM + bx])
                l++;
            else
                d++;
        }
    *dark = d;
    *light = l;
}

/* Enrolled identity for this file's tests. A bare slot is never authority. */
static qrmem_id_t g_me = {0, 0, 0};

static int enrol(qrmem_ap_t *ap, const char *name, char *err, size_t errlen) {
    char e[256] = "";
    uint32_t slot = 0, gen = 0;
    if (qrmem_agent_claim(ap, name, &slot, &gen, e, sizeof e) != 0)
        return -1;
    g_me.slot = slot;
    g_me.agent_gen = gen;
    g_me.authority_gen = 0;
    ap->self_agent = slot;
    (void)err;
    (void)errlen;
    return 0;
}

/* Write one record into (screen, block, slot) and redraw its block. */
static int put(qrmem_ap_t *ap, uint32_t screen, uint32_t block, uint32_t slot,
               uint32_t id, const char *text, char *err, size_t errlen) {
    qrmem_rec_t r;
    /* Identity is 16 raw bytes, so a test that varied only the low 32 bits of a
     * record id was only ever testing 32 bits of it. Vary a full byte of the
     * UUID instead: the plane encodes whole cells, and a change in the high
     * bytes has to reach the picture exactly as a change in the low bytes did. */
    {
        qrmem_uuid_t u;
        unsigned char k;
        memset(&u, 0, sizeof u);
        for (k = 0; k < QRMEM_UUID_BYTES; k++)
            u.b[k] = (unsigned char)(id + k * 7u);
        u.b[6] = (unsigned char)((u.b[6] & 0x0Fu) | 0x40u);
        u.b[8] = (unsigned char)((u.b[8] & 0x3Fu) | 0x80u);
        qrmem_rec_init(&r, QRMEM_CT_WORD, u);
    }
    qrmem_rec_add_text(&r, text, strlen(text));
    qrmem_rec_add_u32(&r, QRMEM_TLV_SLOT, slot);
    if (qrmem_tile_write(ap, screen, block, slot, g_me, &r, err,
                         errlen) != 0)
        return -1;
    return 0;
}

static void test_capacity(void) {
    printf("  info one module is one bit: %u x %u = %u bits/block\n",
           QRMEM_BLOCK_DIM, QRMEM_BLOCK_DIM,
           QRMEM_BLOCK_DIM * QRMEM_BLOCK_DIM);
    printf("  info five records need %u bits, the frame holds %u modules\n",
           QRMEM_CELL_BYTES * 8u * QRMEM_SLOTS_PER_BLOCK,
           (QRMEM_BLOCK_DIM - 8u) * (QRMEM_BLOCK_DIM - 12u));
    /* The geometric claim the whole RAM budget rests on. If five records did not
     * fit in one block at one bit per module, the encoder would have to smuggle
     * extra bits somewhere and the plane would stop being honest. */
    ok((size_t)(QRMEM_BLOCK_DIM - 8u) * (QRMEM_BLOCK_DIM - 12u) >=
           (size_t)QRMEM_CELL_BYTES * 8u * QRMEM_SLOTS_PER_BLOCK,
       "five records fit in one block with room to spare");
}

static void test_empty_block_is_dense(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    unsigned char *mods;
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    mods = malloc((size_t)QRMEM_BLOCK_DIM * QRMEM_BLOCK_DIM);
    ok(mods != NULL, "scratch buffer");
    if (mods) {
        ok(qrmem_plane_encode_block(&ap, 0u, 0u, mods) == 0,
           "an untouched block still encodes");
        /* An empty block must not render as a featureless rectangle, because a
         * human cannot tell that apart from "there is no surface here at all".
         *
         * It is NOT asserted to be 50% dark, and deliberately so. An unwritten
         * record is genuinely all zero bytes, so a round-trip-exact plane MUST
         * render those modules dark. Padding the zeros with invented bits would
         * improve the picture and destroy the only property worth having: that
         * every module on the surface is a bit of something actually stored.
         * Structure carries the "this is memory, not absence" signal instead -
         * finders, timing and the integrity field are present whether or not a
         * record has been written. */
        {
            size_t d = 0, l = 0;
            corner_counts(mods, &d, &l);
            ok(d > 0 && l > 0,
               "an empty block still carries its finder pattern");
        }
        ok(qrmem_plane_store_block(&ap, 0u, 0u) == 0, "and it is drawn");
        ok(qrmem_plane_verify_block(&ap, 0u, 0u, err, sizeof err) == 0,
           "an empty block verifies against itself");
        free(mods);
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}

static void test_round_trip(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    int all_ok = 1;
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    ok(enrol(&ap, "plane", err, sizeof err) == 0, "enrol");
    ok(qrmem_screen_claim(&ap, 0u, g_me, NULL, err, sizeof err) == 0,
       "claim screen 0");

    for (uint32_t slot = 0; slot < QRMEM_SLOTS_PER_BLOCK; slot++) {
        char text[64];
        snprintf(text, sizeof text, "record number %u lives here", slot);
        if (put(&ap, 0u, 3u, slot, 5000u + slot, text, err, sizeof err) != 0) {
            ok(0, "write a record");
            all_ok = 0;
            break;
        }
    }
    ok(all_ok, "all five records of block 3 are written");

    /* Every block that holds records, and every untouched one, must decode. */
    for (uint32_t b = 0; b < QRMEM_BLOCKS_PER_SCREEN; b++) {
        char e2[512] = "";
        if (qrmem_plane_verify_block(&ap, 0u, b, e2, sizeof e2) != 0) {
            printf("       block %u: %s\n", b, e2);
            all_ok = 0;
        }
    }
    ok(all_ok, "every block on the screen decodes back to its records");

    /* Two blocks with identical contents must still differ in the plane, because
     * the padding seed is positional. Without that, a viewer could not tell one
     * block from another and the surface would be lying about layout. */
    {
        unsigned char *a = malloc((size_t)QRMEM_BLOCK_DIM * QRMEM_BLOCK_DIM);
        unsigned char *c = malloc((size_t)QRMEM_BLOCK_DIM * QRMEM_BLOCK_DIM);
        if (a && c) {
            ok(qrmem_plane_encode_block(&ap, 0u, 0u, a) == 0 &&
                   qrmem_plane_encode_block(&ap, 0u, 1u, c) == 0,
               "encode two empty blocks");
            ok(memcmp(a, c, (size_t)QRMEM_BLOCK_DIM * QRMEM_BLOCK_DIM) != 0,
               "two empty blocks still render differently");
        }
        free(a);
        free(c);
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}

static void test_corruption_is_caught(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    uint32_t x, y;
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    if (enrol(&ap, "plane2", err, sizeof err) != 0) {
        ok(0, "enrol");
        return;
    }
    qrmem_screen_claim(&ap, 0u, g_me, NULL, err, sizeof err);
    for (uint32_t slot = 0; slot < QRMEM_SLOTS_PER_BLOCK; slot++) {
        char text[64];
        snprintf(text, sizeof text, "corruption probe %u", slot);
        put(&ap, 0u, 2u, slot, 6000u + slot, text, err, sizeof err);
    }
    ok(qrmem_plane_verify_block(&ap, 0u, 2u, err, sizeof err) == 0,
       "the block verifies before anyone touches it");

    /* Flip a payload module by going straight at the mapped plane. This is the
     * behaviour a viewer depends on: a single damaged bit must surface as an
     * error, not as a plausible-looking image. */
    x = qrmem_block_x(2u) + 8u;
    y = qrmem_block_y(2u) + 8u;
    qrmem_plane_set(&ap, 0u, x, y, qrmem_plane_get(&ap, 0u, x, y) ? 0u : 1u);
    ok(qrmem_plane_verify_block(&ap, 0u, 2u, err, sizeof err) != 0,
       "a flipped payload module is refused");
    ok(strstr(err, "integrity") != NULL,
       "and it is reported as an integrity failure");
    qrmem_aperture_detach(&ap);
    cleanup();
}

static void test_block_boundaries(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    /* A block must own its modules outright: writing block N may not disturb
     * block N+1, or one block's records would silently rewrite a neighbour's
     * picture. */
    for (uint32_t b = 0; b < QRMEM_BLOCKS_PER_SCREEN; b++)
        qrmem_plane_store_block(&ap, 0u, b);
    for (uint32_t b = 0; b + 1u < QRMEM_BLOCKS_PER_SCREEN; b++) {
        char e2[512] = "";
        if (qrmem_plane_verify_block(&ap, 0u, b, e2, sizeof e2) != 0) {
            printf("       block %u: %s\n", b, e2);
            ok(0, "neighbouring blocks stay independent");
            goto done;
        }
    }
    ok(1, "neighbouring blocks stay independent");
done:
    ok(qrmem_plane_verify_block(&ap, 0u, QRMEM_BLOCKS_PER_SCREEN - 1u, err,
                                sizeof err) == 0,
       "the last block verifies too");
    qrmem_aperture_detach(&ap);
    cleanup();
}

int main(void) {
    printf("qrmem code plane contract test\n");
    test_capacity();
    test_empty_block_is_dense();
    test_round_trip();
    test_corruption_is_caught();
    test_block_boundaries();
    printf("\nchecks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
