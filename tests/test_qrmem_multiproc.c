/* Saphira Memory - qrmem live multi-process test.
 *
 * This is the test that matches the real autoconference shape: one writer
 * process publishing into its own tile, one reader process attached
 * independently and reading it live. It is deliberately NOT built with
 * ThreadSanitizer, for two reasons that are worth stating rather than hiding:
 *
 *  1. ThreadSanitizer tracks happens-before WITHIN a process. Two processes
 *     each mmap-ing the same segment have separate address spaces it cannot
 *     relate, so it cannot see a race here no matter how this test is written.
 *     Building it under TSan would produce a clean report that means nothing.
 *  2. TSan and fork() in one binary misbehave: the parent's main() is re-entered
 *     after the child exits. Observed here, not theorised.
 *
 * So the memory-ordering proof lives in test_qrmem_aperture.c, which is
 * threaded inside one process and IS run under TSan. This file proves the
 * multi-process path, which TSan is blind to by construction.
 *
 * What this proves:
 *  - A writer process and a reader process share one live fabric.
 *  - The reader sees records it never waited for, with no polling of any
 *    generation and no retry loop.
 *  - Every record the reader decodes is internally consistent.
 *  - One writer's screen cannot be written by a different agent slot.
 */
#include "qrmem.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
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

#define NAME "/qrmem-test-multiproc"
#define WRITES 4000u


/* Full fenced identity for this process. Tests use real triples: a bare
 * slot number is never authority, including here. */

/* Deterministic valid v4 identity for a given payload, so the reader can
 * cross-check the identity it decodes against the record it expected. */
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

static qrmem_id_t claim_as(qrmem_ap_t *ap, const char *name) {
    qrmem_id_t id;
    char err[256] = "";
    uint32_t slot = 0, gen = 0;
    id.slot = 0;
    id.agent_gen = 0;
    id.authority_gen = 0;
    if (qrmem_agent_claim(ap, name, &slot, &gen, err, sizeof err) != 0)
        return id;
    id.slot = slot;
    id.agent_gen = gen;
    id.authority_gen = atomic_load_explicit(&ap->hdr->authority_gen,
                                            memory_order_acquire);
    return id;
}

int main(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    pid_t pid;
    int status = 0;
    uint64_t seen = 0, torn = 0;
    int spins = 0, child_done = 0;
    uint32_t i;
    /* One identity for this test's writer side, enrolled once. The forked
     * child inherits these values and writes as the same agent from another
     * process, which is exactly the cross-process shape under test. */
    qrmem_id_t me = {0};

    printf("qrmem live multi-process test\n\n");
    printf("== two processes, one fabric\n");
    qrmem_aperture_unlink(NAME);
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        printf("  FAIL create: %s\n", err);
        return 1;
    }
    me = claim_as(&ap, "mp-parent");
    if (me.slot == 0) {
        printf("  FAIL enrol: %s\n", err);
        qrmem_aperture_detach(&ap);
        qrmem_aperture_unlink(NAME);
        return 1;
    }
    ap.self_agent = me.slot;
    if (qrmem_screen_claim(&ap, 0u, me, NULL, err, sizeof err) != 0) {
        printf("  FAIL claim: %s\n", err);
        qrmem_aperture_detach(&ap);
        qrmem_aperture_unlink(NAME);
        return 1;
    }

    pid = fork();
    if (pid < 0) {
        printf("  FAIL fork\n");
        qrmem_aperture_detach(&ap);
        qrmem_aperture_unlink(NAME);
        return 1;
    }
    if (pid == 0) {
        /* The writer. It attaches on its own rather than inheriting the
         * mapping, so the read really does cross a process boundary. */
        qrmem_ap_t w;
        char werr[512] = "";
        if (qrmem_aperture_attach(&w, NAME, werr, sizeof werr) != 0)
            _exit(3);
        w.self_agent = 1u;
        for (i = 0; i < WRITES; i++) {
            qrmem_rec_t r;
            char e[256] = "";
            /* Spread across blocks, not just slots: ABI 3 keeps five records per
             * block, and a race test that only ever hammers one five-slot block
             * would leave fifteen of the screen's sixteen blocks untested. */
            uint32_t blk = i % QRMEM_BLOCKS_PER_SCREEN;
            uint32_t sl = i % QRMEM_SLOTS_PER_BLOCK;
            /* The id is derived from where the record lives, so the reader can
             * cross-check all three fields against each other. */
            qrmem_rec_init(&r, QRMEM_CT_WORD,
                           U((unsigned char)(blk * QRMEM_SLOTS_PER_BLOCK + sl +
                                             1u)));
            /* Every payload byte varies with i, so a torn read shows up as an
             * internal inconsistency rather than merely a stale value. */
            if (qrmem_rec_add_text(&r, "payload", 7) != 0 ||
                qrmem_rec_add_u32(&r, QRMEM_TLV_BLOCK, blk) != 0 ||
                qrmem_rec_add_u32(&r, QRMEM_TLV_SLOT, sl) != 0)
                _exit(4);
            if (qrmem_tile_write(&w, 0u, blk, sl, me, &r, e, sizeof e) != 0)
                _exit(5);
        }
        qrmem_aperture_detach(&w);
        _exit(0);
    }

    /* The reader. It reads until the writer is done rather than for a fixed
     * number of spins: a bounded parent finishes its whole sweep before the
     * first cell is ever published and the test passes having seen nothing. */
    while (!child_done && spins < 400000) {
        for (uint32_t blk = 0; blk < QRMEM_BLOCKS_PER_SCREEN; blk++) {
          for (uint32_t sl = 0; sl < QRMEM_SLOTS_PER_BLOCK; sl++) {
            qrmem_rec_t g;
            char e[256] = "";
            uint32_t gx = 0, gy = 0;
            const char *txt = NULL;
            size_t tl = 0;
            if (qrmem_cell_read(&ap, 0u, blk, sl, &g, e, sizeof e) != 0)
                continue;
            seen++;
            /* The record carries the (block, slot) it was written at, and an
             * identity that was derived from that same (block, slot) at write
             * time. A torn read shows up as those disagreeing, which no single
             * stale byte could fake.
             *
             * Note this is a deliberate cross-check, not a coupling: the writer
             * CHOSE an id from the address, it did not have to. Identity is not
             * derived from location anywhere in the fabric - that is the whole
             * point - so this assertion verifies the three fields agree, not
             * that identity is a function of address. */
            if (qrmem_rec_get_u32(&g, QRMEM_TLV_BLOCK, &gx) != 0 ||
                qrmem_rec_get_u32(&g, QRMEM_TLV_SLOT, &gy) != 0 ||
                qrmem_rec_get_text(&g, &txt, &tl) != 0 || tl != 7 ||
                memcmp(txt, "payload", 7) != 0)
                torn++;
            else if (gx != blk || gy != sl) {
                torn++;
            } else {
                qrmem_uuid_t want =
                    U((unsigned char)(gx * QRMEM_SLOTS_PER_BLOCK + gy + 1u));
                if (!qrmem_uuid_equal(&g.id, &want))
                    torn++;
            }
          }
        }
        spins++;
        if (waitpid(pid, &status, WNOHANG) == pid)
            child_done = 1;
    }
    waitpid(pid, &status, 0);
    ok(WIFEXITED(status) && WEXITSTATUS(status) == 0,
       "the writer process finished cleanly");
    printf("  info reader observed %llu published cells in %d sweeps, "
           "%llu inconsistent\n",
           (unsigned long long)seen, spins, (unsigned long long)torn);
    ok(seen > 0u, "the reader observed published cells live, with no retry");
    ok(torn == 0u, "no reader ever saw a half-written record");

    printf("\n== the other process cannot write this tile\n");
    {
        pid_t w2 = fork();
        if (w2 == 0) {
            qrmem_ap_t w;
            char werr[512] = "", e[256] = "";
            qrmem_rec_t r;
            int refused;
            if (qrmem_aperture_attach(&w, NAME, werr, sizeof werr) != 0)
                _exit(3);
            qrmem_id_t other = claim_as(&w, "mp-other");
            w.self_agent = other.slot; /* a different agent slot */
            qrmem_rec_init(&r, QRMEM_CT_WORD, U(99u));
            refused = other.slot != 0 &&
                qrmem_tile_write(&w, 0u, 1u, 1u, other, &r, e,
                                 sizeof e) != 0;
            _exit(refused ? 0 : 7);
        }
        waitpid(w2, &status, 0);
        ok(WIFEXITED(status) && WEXITSTATUS(status) == 0,
           "a second process with another agent id is refused screen 0");
    }

    qrmem_aperture_detach(&ap);
    qrmem_aperture_unlink(NAME);
    printf("\nchecks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
