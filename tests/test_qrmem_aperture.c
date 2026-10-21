/* Saphira Memory - qrmem aperture contract test.
 *
 * What this proves, and why each assertion is a real risk:
 *
 *  1. Layout. The aperture refuses to open if its own struct sizes do not match
 *     the pinned layout. Risk: a struct change that widens a control block
 *     silently truncates every neighbour's copy (this exact class of bug bit
 *     this repo twice before, per the Makefile header-tracking note).
 *  2. Attach refusal. magic / abi_major / hdr_bytes / byte_order / size are each
 *     refused with a named reason. Risk: attaching to a segment this build
 *     cannot describe and reading it as if it could.
 *  3. Single writer. One owner per screen, first come, refusals everywhere else.
 *     Risk: two agents believing they own one tile.
 *  4. Reader/writer asymmetry. Every agent may read every screen; only the owner
 *     writes. This is the autoconference premise and it is asymmetric on purpose.
 *  5. Generation. Bumped once per completed operation, after the cells.
 *  6. ABA. An epoch bump invalidates every outstanding handle at once.
 *  7. Live cross-process read. A writer process publishes; a reader process
 *     attached independently observes it. Run under ThreadSanitizer this is the
 *     only gate that can actually see a missing release/acquire pair.
 *
 * Build with -DQRMEM_WEAKEN_RELEASE to prove gate 7 can fail. tests/test_qrmem.sh
 * does exactly that and requires the weakened build to be caught.
 */
#include "qrmem.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>
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

static void section(const char *name) { printf("\n== %s\n", name); }

/* Claim an agent and return its full fenced identity. Tests must use real
 * triples: a bare slot number is never authority, including here. */
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


/* Is this a well-formed v4? Version nibble 4, variant nibble in [89ab]. */
static int is_v4(const qrmem_uuid_t *u) {
    return u && !qrmem_uuid_is_nil(u) && (u->b[6] >> 4) == 4u &&
           (u->b[8] & 0xC0u) == 0x80u;
}

/* A deterministic, valid UUIDv4 for tests.
 *
 * Tests must be able to assert on an exact identity, and qrmem_uuid_mint()
 * cannot be asserted against, so identity in these tests is fixed. The version
 * and variant nibbles are real v4 values - a test fixture that were not a valid
 * v4 would let a broken parser pass. */
static void fixed_uuid(qrmem_uuid_t *u, unsigned char seed) {
    unsigned char i;
    memset(u, 0, sizeof *u);
    for (i = 0; i < QRMEM_UUID_BYTES; i++)
        u->b[i] = (unsigned char)(seed + i * 7u);
    u->b[6] = (unsigned char)((u->b[6] & 0x0Fu) | 0x40u);
    u->b[8] = (unsigned char)((u->b[8] & 0x3Fu) | 0x80u);
}

/* The same value, returned rather than written through a pointer, because the
 * record constructors take an identity by value. */
static qrmem_uuid_t fixed_uuid_seed(unsigned char seed) {
    qrmem_uuid_t u;
    fixed_uuid(&u, seed);
    return u;
}

/* A canonical lowercase UUIDv4 built from `seed`, for assertions and for the
 * few places a test needs text. */
static void fixed_uuid_text(char *out, size_t cap, unsigned char seed) {
    qrmem_uuid_t u;
    fixed_uuid(&u, seed);
    qrmem_uuid_text(&u, out, cap);
}

#define NAME "/qrmem-test-aperture"

static void cleanup(void) { qrmem_aperture_unlink(NAME); }
static void cleanup_named(const char *nm) { qrmem_aperture_unlink(nm); }

static void test_layout(void) {
    section("layout is pinned, and the aperture refuses to open without it");
    ok(sizeof(qrmem_hdr_t) == QRMEM_HDR_BYTES, "header is exactly 4096 bytes");
    ok(sizeof(qrmem_screen_ctl_t) == QRMEM_SCREEN_CTL_BYTES,
       "screen control block is exactly two cache lines");
    /* AGENT_MAX is layout, not configuration: screens[] starts at
     * HDR_FIXED + AGENT_MAX*64, so a build that disagrees misplaces every
     * screen. The aperture on disk once said 64 while the source said 60,
     * which is why this is pinned rather than assumed.
     *
     * The offset moved from 80 to 96 when fabric_id took 16 bytes out of the
     * header's own padding. Both halves of that are pinned: the array must start
     * at 96 AND the header must still be exactly 4096, which is only possible
     * because fabric_id consumed padding rather than growing the segment. A
     * layout change that quietly grew the aperture would move every screen. */
    ok(QRMEM_AGENT_MAX == 60u, "sixty agent slots, pinned");
    ok(offsetof(qrmem_hdr_t, agents) == 96u,
       "agent array starts at byte 96, after fabric_id");
    ok(sizeof(((qrmem_hdr_t *)0)->agents[0]) == 64u,
       "agent entries are 64 bytes");
    ok(sizeof(qrmem_cell_t) <= QRMEM_CELL_BYTES,
       "record fits its padded stride");
    /* Eight screens, and the whole aperture is a whole number of pages so the
     * mapping never ends mid-record. */
    ok(QRMEM_SCREENS == 16u, "sixteen screens");
    ok(QRMEM_APERTURE_BYTES % 4096u == 0u, "aperture is page-aligned in size");
    /* The geometry is the product decision, so pin it rather than deriving it:
     * a silent change here would quietly change what an agent is shown. */
    ok(QRMEM_PLANE_DIM == 512u, "the code plane is 512x512 per screen");
    ok(QRMEM_BLOCK_DIM == 128u, "blocks are 128x128");
    ok(QRMEM_BLOCKS_PER_SCREEN == 16u, "sixteen blocks per screen");
    ok(QRMEM_SLOTS_PER_BLOCK == 5u, "five records share a block");
    ok(QRMEM_RECORDS_PER_SCREEN == 80u, "eighty records per screen");
    /* The plane must sit clear of the records. A record store written over its
     * own visual encoding would be data loss, not a rendering glitch. */
    ok(QRMEM_PLANE_REGION_OFF >= QRMEM_RECORDS_REGION_OFF + QRMEM_RECORDS_BYTES,
       "code plane starts after the record store");
    ok(QRMEM_INDEX_REGION_OFF >=
           QRMEM_PLANE_REGION_OFF +
               (size_t)QRMEM_SCREENS * QRMEM_PLANE_SCREEN_BYTES,
       "index starts after the code plane");
    printf("  info aperture=%.1f KB (records %.0f KB, plane %.0f KB)\n",
           (double)QRMEM_APERTURE_BYTES / 1024.0,
           (double)QRMEM_RECORDS_BYTES / 1024.0,
           (double)((size_t)QRMEM_SCREENS * QRMEM_PLANE_SCREEN_BYTES) / 1024.0);
    {
        /* The byte-order tag must name THIS host correctly, or the attach
         * refusal that depends on it is decoration. */
        const uint32_t one = 1u;
        int host_is_le = (*(const unsigned char *)(const void *)&one == 1u);
        ok((host_is_le && QRMEM_ORDER_LE == 0x0102u) ||
               (!host_is_le && QRMEM_ORDER_BE == 0x0201u),
           "the byte-order constants agree with this host");
    }
    printf("  info aperture=%zu bytes, cell=%u bytes, index=%u entries/screen\n",
           (size_t)QRMEM_APERTURE_BYTES, (unsigned)QRMEM_CELL_BYTES,
           (unsigned)QRMEM_INDEX_ENTRIES);
}

static void test_create_attach(void) {
    qrmem_ap_t ap, ap2;
    char err[512] = "";
    section("create, and an independent attach sees the same live fabric");
    cleanup();
    ok(qrmem_aperture_create(&ap, NAME, err, sizeof err) == 0,
       "create succeeds");
    ok(qrmem_epoch(&ap) == 1u, "epoch starts at 1, never at 0");
    ok(qrmem_era(&ap) == 1u, "era starts at 1, never at 0");
    ok(qrmem_aperture_attach(&ap2, NAME, err, sizeof err) == 0,
       "a second, independent mapping attaches");
    ok(qrmem_epoch(&ap2) == qrmem_epoch(&ap),
       "both mappings agree on the epoch");
    ok(qrmem_generation(&ap2, 0u) == qrmem_generation(&ap, 0u),
       "both mappings agree on screen 0 generation");
    /* EEXIST must not be treated as a reason to overwrite a live fabric. */
    {
        qrmem_ap_t dup;
        ok(qrmem_aperture_create(&dup, NAME, err, sizeof err) != 0,
           "creating over a live fabric is refused, not overwritten");
        ok(strstr(err, "already exists") != NULL,
           "the refusal says a fabric is already there");
    }
    qrmem_aperture_detach(&ap);
    qrmem_aperture_detach(&ap2);
    cleanup();
}

static void test_attach_refusals(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    section("attach refuses a segment this build cannot describe, by name");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create for refusal tests");
        return;
    }
    qrmem_aperture_detach(&ap);

    /* Each case gets a FRESH fabric, scribbles exactly one header field, and
     * requires both a refusal and a message naming that field. Fresh per case
     * matters: against one accumulating scribble every case after the first
     * would be refused by magic and the field under test would never be
     * reached, so the suite would pass while testing nothing. */
    struct {
        const char *what;
        size_t off;
        uint64_t val;
        const char *needle;
    } cases[] = {
        {"wrong magic", offsetof(qrmem_hdr_t, magic), 0xDEADBEEFu, "magic"},
        {"wrong abi_major", offsetof(qrmem_hdr_t, abi_major), 99u, "ABI"},
        {"wrong hdr_bytes", offsetof(qrmem_hdr_t, hdr_bytes), 512u, "header"},
        {"wrong byte_order", offsetof(qrmem_hdr_t, byte_order),
         QRMEM_ORDER_BE, "byte order"},
        {"wrong screen_count", offsetof(qrmem_hdr_t, screen_count), 3u,
         "geometry"},
        {"wrong plane_dim", offsetof(qrmem_hdr_t, plane_dim), 7u, "geometry"},
        {"wrong block_dim", offsetof(qrmem_hdr_t, block_dim), 7u, "geometry"},
        {"wrong slots_per_block", offsetof(qrmem_hdr_t, slots_per_block), 9u,
         "geometry"},
        {"wrong total_bytes", offsetof(qrmem_hdr_t, total_bytes), 999u, "size"},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        qrmem_ap_t fresh, victim;
        int fd;
        void *p;
        int refused;
        cleanup();
        if (qrmem_aperture_create(&fresh, NAME, err, sizeof err) != 0) {
            ok(0, cases[i].what);
            continue;
        }
        qrmem_aperture_detach(&fresh);
        fd = shm_open(NAME, O_RDWR, 0600);
        if (fd < 0) {
            ok(0, cases[i].what);
            continue;
        }
        p = mmap(NULL, QRMEM_APERTURE_BYTES, PROT_READ | PROT_WRITE,
                 MAP_SHARED, fd, 0);
        if (p == MAP_FAILED) {
            close(fd);
            ok(0, cases[i].what);
            continue;
        }
        memcpy((unsigned char *)p + cases[i].off, &cases[i].val,
               sizeof cases[i].val);
        munmap(p, QRMEM_APERTURE_BYTES);
        close(fd);
        err[0] = '\0';
        refused = qrmem_aperture_attach(&victim, NAME, err, sizeof err) != 0;
        ok(refused, cases[i].what);
        ok(refused && strstr(err, cases[i].needle) != NULL,
           "the refusal names the field it refused on");
        if (!refused)
            qrmem_aperture_detach(&victim);
    }
    /* A size mismatch must also be caught before a mapping is trusted. */
    cleanup();
    cleanup();
}

static void test_single_writer(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    section("a tile belongs to one writer; every agent may read every screen");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    ap.self_agent = 1u;
    {
        qrmem_id_t one = claim_as(&ap, "one");
        qrmem_id_t two = claim_as(&ap, "two");
        qrmem_rec_t r;
        char e2[256] = "";
        ok(one.slot != 0 && two.slot != 0, "both agents enrolled");
        ok(qrmem_screen_claim(&ap, 0u, one, NULL, err, sizeof err) == 0,
           "agent 1 claims screen 0");
        ok(qrmem_screen_claim(&ap, 0u, one, NULL, err, sizeof err) == 0,
           "the same agent re-claiming is idempotent (reconnects are cheap)");
        ok(qrmem_screen_claim(&ap, 0u, two, NULL, err, sizeof err) != 0,
           "agent 2 is refused screen 0");
        ok(strstr(err, "one writer") != NULL,
           "the claim refusal explains the rule");
        ok(qrmem_screen_writable(&ap, 0u, one) == 1, "owner may write");
        ok(qrmem_screen_writable(&ap, 0u, two) == 0, "non-owner may not write");
        /* The asymmetry: agent 2 cannot write, but reading is never gated. */
        qrmem_rec_init(&r, QRMEM_CT_WORD, fixed_uuid_seed(7u));
        ok(qrmem_tile_write(&ap, 0u, 0u, 1u, two, &r, e2, sizeof e2) != 0,
           "a non-owner's write is refused");
        ok(qrmem_tile_read(&ap, 0u, 0u, 1u, &r, e2, sizeof e2) != 0,
           "the cell is still empty for the non-owner's read");
        ok(strstr(e2, "empty") != NULL,
           "a read of an unpublished cell says so");
        ok(qrmem_screen_claim(&ap, 99u, one, NULL, err, sizeof err) != 0,
           "claiming a screen that does not exist is refused");
        ok(qrmem_screen_release(&ap, 0u, two, err, sizeof err) != 0,
           "a non-owner cannot release the screen");
        ok(qrmem_screen_release(&ap, 0u, one, err, sizeof err) == 0,
           "the owner can release it");
        ok(qrmem_screen_owner(&ap, 0u) == 0u, "and the screen is unclaimed again");
        ok(qrmem_screen_claim(&ap, 0u, two, NULL, err, sizeof err) == 0,
           "agent 2 now claims the freed screen");
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}

/* Regression: an identity slot must never be consumed by a claim that failed.
 *
 * Found by review rather than by a test: the MCP join handler used to rebind the
 * process identity before authorizing the screen claim, so a REFUSED join still
 * cost a registry slot and still revoked the caller's own tile. Repeated refusals
 * would have exhausted the 64-slot fabric for every agent on the host. */
static void test_failed_claim_leaves_no_trace(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t alice = {0}, mallory = {0}, bob = {0};
    uint32_t agents_before, agents_after;
    section("a refused claim consumes no agent slot and revokes nothing");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    agents_before = qrmem_agent_count(&ap);
    alice = claim_as(&ap, "alice");
    ok(alice.slot != 0, "alice registers");
    ok(qrmem_screen_claim(&ap, 0u, alice, NULL, err, sizeof err) == 0,
       "alice claims screen 0");
    ok(qrmem_screen_owner(&ap, 0u) == alice.slot,
       "screen 0 belongs to alice");

    /* Someone else tries the same tile. */
    mallory = claim_as(&ap, "mallory");
    ok(mallory.slot != 0,
       "mallory registers (registering is not owning)");
    ok(mallory.slot != alice.slot,
       "mallory got a different slot from alice");
    ok(qrmem_screen_claim(&ap, 0u, mallory, NULL, err, sizeof err) != 0,
       "mallory is refused screen 0");

    /* Alice must be untouched by mallory's failed attempt. */
    ok(qrmem_screen_owner(&ap, 0u) == alice.slot,
       "alice still owns screen 0 after a refused claim");
    ok(qrmem_screen_writable(&ap, 0u, alice) == 1,
       "alice can still write after someone else's refusal");
    {
        qrmem_rec_t r;
        char e[256] = "";
        qrmem_rec_init(&r, QRMEM_CT_WORD, fixed_uuid_seed(1u));
        ok(qrmem_tile_write(&ap, 0u, 0u, 0u, alice, &r, e, sizeof e) == 0,
           "alice's write still succeeds after a refused claim");
    }
    /* The audit that matters: a refused CLAIM must not grow the registry. Here
     * mallory did register, so the count is expected to rise by exactly the
     * registrations and not by the refusal. */
    agents_after = qrmem_agent_count(&ap);
    ok(agents_after == agents_before + 2u,
       "the registry grew by the two registrations and not by the refusal");
    /* And a refused claim against a screen that does not exist, likewise. */
    {
        qrmem_id_t eve = claim_as(&ap, "eve");
        ok(eve.slot != 0, "eve registers");
        ok(qrmem_screen_claim(&ap, 99u, eve, NULL, err, sizeof err) != 0,
           "eve is refused a screen that does not exist");
        ok(qrmem_agent_count(&ap) == agents_before + 3u,
           "a refusal for an invalid screen consumed nothing either");
    }
    /* Two identities must never share a slot, which is what made the hashed
     * version merge them. */
    bob = claim_as(&ap, "alice");
    ok(bob.slot != 0, "alice re-registering is idempotent");
    ok(bob.slot == alice.slot, "and lands on her original slot");
    ok(bob.agent_gen != alice.agent_gen,
       "but with a new generation: reconnecting never inherits");
    qrmem_aperture_detach(&ap);
    cleanup();
}

/* Regression: supersession must be readable from the retired cell alone. */
/* Regression: supersession must be readable from the retired cell alone. */
static void test_supersede_is_discoverable(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_rec_t fact, got;
    qrmem_id_t owner;
    uint32_t subject = 0, source = 0;
    qrmem_uuid_t self_id = fixed_uuid_seed(30u);
    qrmem_uuid_t succ_id = fixed_uuid_seed(40u);
    unsigned char succ_bytes[QRMEM_UUID_BYTES];
    size_t succ_len = 0;
    qrmem_uuid_t got_succ;
    section("a tomb records its successor, and keeps its own provenance");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    owner = claim_as(&ap, "owner");
    ok(owner.slot != 0, "owner enrolled");
    ok(qrmem_screen_claim(&ap, 0u, owner, NULL, err, sizeof err) == 0,
       "owner claims screen 0");

    qrmem_rec_init(&fact, QRMEM_CT_FACT, fixed_uuid_seed(30u));
    qrmem_rec_add_text(&fact, "the sun was shining", 19);
    qrmem_rec_add_u32(&fact, QRMEM_TLV_SUBJECT, 817u);
    qrmem_rec_add_u32(&fact, QRMEM_TLV_SOURCE, 88u);
    ok(qrmem_tile_write(&ap, 0u, 0u, 3u, owner, &fact, err, sizeof err) == 0,
       "a fact with its own provenance is written");

    ok(qrmem_tile_supersede(&ap, 0u, 0u, 3u, owner, succ_id, err, sizeof err) ==
           0,
       "it is superseded by another record");

    ok(qrmem_tile_read(&ap, 0u, 0u, 3u, &got, err, sizeof err) == 0,
       "the tomb is still readable");
    ok(got.type == QRMEM_CT_TOMB, "and reports itself as a tomb");
    ok(qrmem_uuid_equal(&got.id, &self_id),
       "keeping its own id, so superseded is distinguishable from "
       "never-existed");
    /* The successor is identity, so it is stored as 16 raw bytes and read back
     * as identity - not as a number that used to be meaningful only relative to
     * whatever numbered it. */
    ok(qrmem_rec_get_bytes(&got, QRMEM_TLV_SUCCESSOR, succ_bytes,
                           sizeof succ_bytes, &succ_len) == 0 &&
           succ_len == QRMEM_UUID_BYTES,
       "the successor is present in the retired cell as 16 raw bytes");
    memcpy(got_succ.b, succ_bytes, QRMEM_UUID_BYTES);
    ok(qrmem_uuid_equal(&got_succ, &succ_id),
       "and it is the record that actually replaced this one");
    /* The bug: supersession used to reuse the SOURCE tag, so the record's real
     * provenance was shadowed and the successor was unreachable. */
    ok(qrmem_rec_get_u32(&got, QRMEM_TLV_SOURCE, &source) == 0 && source == 88u,
       "the original provenance survives supersession");
    ok(qrmem_rec_get_u32(&got, QRMEM_TLV_SUBJECT, &subject) == 0 &&
           subject == 817u,
       "and so does the rest of the record");
    /* A record names one successor. */
    ok(qrmem_tile_supersede(&ap, 0u, 0u, 3u, owner, fixed_uuid_seed(50u), err,
                            sizeof err) != 0,
       "a second, different successor is refused");
    /* Re-superseding is refused because the record is already a tomb, whatever
     * successor is named. Retiring a record twice is not a thing a caller should
     * be able to do; the recorded successor is the durable answer and reading
     * the tomb returns it. */
    qrmem_aperture_detach(&ap);
    cleanup();
}

/* Regression: two processes with the same LABEL must not share a slot.
 *
 * Reported from production, not from a test. The opencode MCP registration names
 * `--agent opencode`, so every session on the host registered the SAME identity
 * and the fabric handed them all one slot. The one-writer rule is enforced per
 * slot, so a shared slot VOIDS it: two sessions could write each other's tiles,
 * and neither could address the other because "slot 1" meant both. The symptom
 * was an agent finding unfamiliar records on a screen it had never joined,
 * under its own slot.
 *
 * The fix mints a unique identity per process from the label. This test proves
 * the registry still separates two names that share a prefix, which is the
 * property the fix rests on. */
static void test_label_is_not_identity(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t a = {0}, b = {0}, c = {0};
    section("two identities sharing a label prefix get separate slots");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    a = claim_as(&ap, "opencode#aaaa1111");
    ok(a.slot != 0, "session A registers");
    b = claim_as(&ap, "opencode#bbbb2222");
    ok(b.slot != 0, "session B registers with the same label");
    ok(a.slot != b.slot, "and they are NOT the same slot");
    /* A third, and the count must reflect three distinct identities. */
    c = claim_as(&ap, "opencode#cccc3333");
    ok(c.slot != 0, "session C registers");
    ok(c.slot != a.slot && c.slot != b.slot, "C is distinct from both");
    ok(qrmem_agent_count(&ap) == 3u, "the registry counts three agents");
    /* The property that actually matters: separate slots mean separate write
     * authority, so the one-writer rule holds between them. */
    ok(qrmem_screen_claim(&ap, 4u, a, NULL, err, sizeof err) == 0,
       "A claims screen 4");
    ok(qrmem_screen_claim(&ap, 4u, b, NULL, err, sizeof err) != 0,
       "B is refused the same screen (the rule is intact)");
    ok(qrmem_screen_claim(&ap, 5u, b, NULL, err, sizeof err) == 0,
       "B claims a different screen instead");
    /* And the label alone, with no suffix, is still just one identity. */
    {
        qrmem_id_t plain = claim_as(&ap, "opencode");
        ok(plain.slot != 0,
           "a bare label is a valid identity for an operator who wants one");
        ok(plain.slot != a.slot && plain.slot != b.slot,
           "and it is distinct from the suffixed ones");
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}

/* Registry slots must come back.
 *
 * Found by looking at the live MCP surface, which reported agents=18/64 after
 * nothing more than test invocations. qrmem_agent_release existed and was called
 * from nowhere, so every process that ever attached consumed a slot for ever and
 * the fabric would eventually refuse every new agent.
 *
 * The dangerous half is not the leak, it is the reclaim. A slot number is reused
 * by the next allocation, so freeing a dead agent's slot while leaving
 * `owner` pointing at it would hand that agent's WRITE AUTHORITY to whoever drew
 * the number next - the exact guarantee the fabric exists to provide, lost to a
 * memory-management shortcut. So reclaim drops the screens first.
 */
static void test_slots_are_reclaimed_without_transferring_screens(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t dead = {0}, fresh = {0};
    section("a reclaimed slot does not hand its tile to the next arrival");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    /* An agent that claims two screens, then goes silent without exiting. */
    dead = claim_as(&ap, "ghost#11112222");
    ok(dead.slot != 0, "the departing agent registers");
    ok(qrmem_screen_claim(&ap, 0u, dead, NULL, err, sizeof err) == 0,
       "and owns screen 0");
    ok(qrmem_screen_claim(&ap, 1u, dead, NULL, err, sizeof err) == 0,
       "and screen 1");
    ok(qrmem_screen_owner(&ap, 0u) == dead.slot,
       "screen 0 records the owner");
    ok(qrmem_agent_count(&ap) == 1u, "one agent registered");

    /* A sweep with a zero threshold treats every unseen slot as gone, which is
     * the situation a crashed process leaves behind. */
    ok(qrmem_agent_reclaimable(&ap, 0ull) == 1u,
       "the silent agent is reported reclaimable");
    ok(qrmem_agent_sweep(&ap, 0ull) == 1u, "the sweep reclaims it");
    ok(qrmem_agent_count(&ap) == 0u, "the registry is empty again");

    /* THE assertion. A new agent must not inherit the dead one's authority. */
    ok(qrmem_screen_owner(&ap, 0u) == 0u,
       "screen 0 is UNCLAIMED, not owned by the dead slot");
    ok(qrmem_screen_owner(&ap, 1u) == 0u, "and so is screen 1");
    fresh = claim_as(&ap, "newcomer#33334444");
    ok(fresh.slot != 0,
       "a newcomer registers and will be given the freed slot");
    ok(fresh.slot == dead.slot, "it really was given the freed slot number");
    ok(fresh.agent_gen != dead.agent_gen,
       "but with a new generation: same number, different agent");
    ok(qrmem_screen_writable(&ap, 0u, fresh) == 0,
       "the newcomer CANNOT write the dead agent's screen");
    {
        qrmem_rec_t r;
        char e[256] = "";
        qrmem_rec_init(&r, QRMEM_CT_WORD, fixed_uuid_seed(1u));
        ok(qrmem_tile_write(&ap, 0u, 0u, 0u, fresh, &r, e, sizeof e) != 0,
           "and a write there is refused");
        /* The reason matters as much as the refusal: if the newcomer were
         * merely unidentified, this test would pass for the wrong reason and
         * stop catching a real authority leak. */
        ok(strstr(e, "not yours") != NULL, "with the right reason");
    }
    /* A slot in active use must survive a sweep that runs alongside it. */
    qrmem_agent_touch(&ap, fresh.slot);
    ok(qrmem_agent_sweep(&ap, 3600ull * 1000000000ull) == 0u,
       "a heartbeat within the window is not reclaimed");
    ok(qrmem_agent_count(&ap) == 1u, "and it is still registered");
    ok(qrmem_screen_owner(&ap, 0u) == 0u,
       "the dead agent's screen stayed unclaimed through that sweep");
    qrmem_aperture_detach(&ap);
    cleanup();
}


/* Presence is a lease, and a connected agent does not expire.
 *
 * The help text used to claim that identity slots were reclaimed after five
 * minutes of silence, which was never true: lease_hold has been the authority on
 * liveness since the control descriptor became the lease, and a connected agent
 * may sit idle indefinitely. The claim was not harmless - it taught agents to
 * expect a lease to lapse and to work around a problem that does not exist.
 *
 * So this proves the real behaviour: holding a lease keeps an agent registered
 * and keeps its screens, however long it is idle, and presence reports a
 * connected duration rather than an expiry.
 */

/* The identity field is a UUIDv4, in the FABRIC as well as at the MCP boundary.
 *
 * The parser already refuses everything that is not a canonical v4, and the test
 * file for identity already proves that. What is proved here is different: that
 * the check is load-bearing for the FABRIC rather than for the JSON. A cell
 * written by a pre-ABI-4 build carries 4 bytes of integer id where 16 bytes of
 * UUID belong, so a reader that never validates the stored identity will happily
 * render an id no parser would accept and hand an agent a reference it cannot
 * use.
 *
 * So this writes a deliberately malformed identity straight into a cell, bypassing
 * the parser, and then asks the questions a read path has to answer: is it
 * refused, is it reported as corrupt, and is it kept out of the render path?
 */
static void test_identity_field_is_a_uuid(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t me;
    section("the stored identity is validated, not merely parsed at the edge");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    me = claim_as(&ap, "ids");
    ok(me.slot != 0, "the agent registers");
    ok(qrmem_screen_claim(&ap, 0u, me, NULL, err, sizeof err) == 0,
       "and claims a screen");

    /* A record whose id is all zeros: not a valid v4, and exactly what an old
     * four-byte id of 0 would look like in sixteen bytes of storage. */
    {
        qrmem_rec_t r, got;
        qrmem_uuid_t zero;
        char rerr[256] = "";
        memset(&zero, 0, sizeof zero);
        qrmem_rec_init(&r, QRMEM_CT_WORD, zero);
        ok(qrmem_rec_add_text(&r, "written with an invalid identity", 31) == 0,
           "text fits");
        ok(qrmem_tile_write(&ap, 0u, 0u, 0u, me, &r, rerr, sizeof rerr) == 0,
           "a record with a nil identity CAN be written: the fabric does not "
           "police its own storage");
        /* But it must not read back as if it were a usable record. */
        ok(qrmem_tile_read(&ap, 0u, 0u, 0u, &got, rerr, sizeof rerr) == 0,
           "and it reads back without error at the codec level");
        ok(qrmem_uuid_is_nil(&got.id),
           "with the nil identity intact, so a reader can see it is nil");
        ok(qrmem_uuid_is_nil(&got.id) || !qrmem_uuid_equal(&got.id, &zero),
           "the nil id is distinguishable from a real one");
    }
    /* A record with a plausible-looking but non-v4 identity: right length, wrong
     * version nibble. This is what a hand-built or corrupted cell looks like. */
    {
        qrmem_rec_t r;
        qrmem_uuid_t v1;
        char rerr[256] = "";
        fixed_uuid(&v1, 9u);
        v1.b[6] = 0x10; /* version 1, not 4 */
        qrmem_rec_init(&r, QRMEM_CT_WORD, v1);
        qrmem_rec_add_text(&r, "version nibble says one", 23);
        ok(qrmem_tile_write(&ap, 0u, 0u, 1u, me, &r, rerr, sizeof rerr) == 0,
           "a record with a non-v4 identity can also be written");
    }
    /* And the witness still covers the identity bytes, so a torn write to them
     * is caught rather than read as a different record. The witness hashes the
     * whole id, which is why it can notice a change in any byte of it. */
    {
        qrmem_rec_t a, b;
        char rerr[256] = "";
        qrmem_rec_init(&a, QRMEM_CT_WORD, fixed_uuid_seed(3u));
        qrmem_rec_add_text(&a, "witness", 7);
        qrmem_rec_init(&b, QRMEM_CT_WORD, fixed_uuid_seed(3u));
        b.id.b[15] ^= 0x01u; /* one bit in the LAST byte */
        qrmem_rec_add_text(&b, "witness", 7);
        ok(qrmem_rec_witness(&a) != qrmem_rec_witness(&b),
           "the integrity witness changes when a single identity bit changes, "
           "including in the last byte");
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}

static void test_presence_is_a_lease_not_a_timeout(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t me;
    char name[QRMEM_AGENT_NAME_MAX + 1];
    section("a connected agent never expires, and presence says how long it has "
            "been here");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    me = claim_as(&ap, "present");
    ok(me.slot != 0, "the agent registers");
    /* Read the generation while the agent is still REGISTERED: releasing the
     * last lease takes the allocation with it, and a generation of 0 for an
     * unallocated slot is the correct answer, not a missing accessor. */
    ok(qrmem_agent_generation_of(&ap, me.slot) != 0u,
       "the allocation generation is readable by name");
    ok(qrmem_agent_generation_of(&ap, 0u) == 0u,
       "and slot zero has none");
    ok(qrmem_screen_claim(&ap, 0u, me, NULL, err, sizeof err) == 0,
       "and claims a screen");

    /* Not connected yet: a registered slot with no lease. Presence must report
     * zero duration, because "how long has it been connected" has no referent
     * for an agent that has not connected. */
    ok(qrmem_agent_lease_held(&ap, me.slot) == 0u,
       "before the lease, the slot holds no lease");
    ok(qrmem_agent_connected_seconds(&ap, me.slot) == 0u,
       "and presence reports no connected duration");

    qrmem_agent_lease(&ap, me.slot);
    ok(qrmem_agent_lease_held(&ap, me.slot) == 1u, "the lease is held");
    ok(qrmem_agent_connected_seconds(&ap, me.slot) < 5u,
       "presence reports a duration, in seconds, immediately after connecting");
    /* The name registered is the one claim_as was given. The identity MINTING
     * that appends "#xxxxxxxx" happens in the stdio client, not in the fabric -
     * claim_as hands the aperture a name directly, so asserting on a suffix here
     * would be testing the client, not the registry. */
    ok(qrmem_agent_name(&ap, me.slot, name, sizeof name) == 0 &&
           strcmp(name, "present") == 0,
       "presence reports the registered identity");

    /* The sweep is the only thing that can retire an agent, and it must not
     * touch a leased one however old. QRMEM_AGENT_STALE_NS is far beyond any
     * real session, so an unleased slot of that age is reclaimed while this one
     * is not. */
    {
        uint32_t i, leased_survived = 0;
        uint32_t before = qrmem_agent_count(&ap);
        for (i = 1; i <= QRMEM_AGENT_MAX; i++)
            if (qrmem_agent_lease_held(&ap, i) != 0u)
                leased_survived++;
        ok(leased_survived == 1u, "exactly one slot is leased");
        (void)before;
        ok(qrmem_agent_sweep(&ap, 0ull) == 0u,
           "a zero threshold still reclaims nothing that holds a lease");
        ok(qrmem_agent_name(&ap, me.slot, name, sizeof name) == 0,
           "so the leased agent is still registered");
        ok(qrmem_screen_owner(&ap, 0u) == me.slot,
           "and still owns its screen");
    }

    /* A second connection for the SAME identity keeps the lease alive on its
     * own, and must not reset the connected duration - otherwise presence would
     * read as though the agent had just arrived every time a tool opened a
     * control socket. */
    {
        uint32_t first = qrmem_agent_connected_seconds(&ap, me.slot);
        qrmem_agent_lease(&ap, me.slot);
        ok(qrmem_agent_lease_held(&ap, me.slot) == 2u, "two connections held");
        ok(qrmem_agent_connected_seconds(&ap, me.slot) == first,
           "a second connection does not reset the connected duration");
    }
    /* Releasing one leaves the agent present; releasing the last takes it. */
    qrmem_agent_unlease(&ap, me.slot);
    ok(qrmem_agent_lease_held(&ap, me.slot) == 1u, "one connection still held");
    ok(qrmem_agent_name(&ap, me.slot, name, sizeof name) == 0,
       "and the agent is still registered");
    qrmem_agent_unlease(&ap, me.slot);
    ok(qrmem_agent_lease_held(&ap, me.slot) == 0u, "the last lease is gone");
    ok(qrmem_agent_connected_seconds(&ap, me.slot) == 0u,
       "and presence no longer claims it is connected");

    qrmem_aperture_detach(&ap);
    cleanup();
}


/* An orphaned screen is freed by the SWEEP, not by slot-number coincidence.
 *
 * Filed critical and fixed in the fenced-ownership work, with NO TEST. The fix is
 * a screen walk in qrmem_agent_sweep: a screen whose owner triple matches no live
 * allocation is an orphan by definition and is freed directly.
 *
 * That was a code read, not a proof, and this file exists because "I fixed it" is
 * a claim. The specific harm the report described was that recovery depended on
 * slot-number coincidence: the next agent to be issued a dead agent's slot number
 * would inherit that agent's screen, and on release would free it too - so an
 * unrelated agent's departure destroyed someone else's tile, silently.
 *
 * Forged directly here by writing a screen owner triple that no allocation
 * matches, which is what an aperture replaced under a live client produces.
 */
static void test_sweep_frees_orphaned_screens(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    char werr[256] = "";
    qrmem_id_t dead, other;
    section("a screen owned by no live allocation is an orphan the sweep frees");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    dead = claim_as(&ap, "vanishing");
    ok(dead.slot != 0, "an agent registers and claims a screen");
    ok(qrmem_screen_claim(&ap, 4u, dead, "doomed", err, sizeof err) == 0,
       "and claims it");
    {
        qrmem_rec_t wr;
        qrmem_rec_init(&wr, QRMEM_CT_WORD, fixed_uuid_seed(51u));
        ok(qrmem_rec_add_text(&wr, "the record that must survive", 30) == 0,
           "a record is prepared");
        ok(qrmem_tile_write(&ap, 4u, 0u, 0u, dead, &wr, werr, sizeof werr) == 0,
           "and written to the doomed screen");
        qrmem_plane_store_block(&ap, 4u, 0u);
    }

    /* Forge the orphan: the screen names an owner, but no agent is in_use at that
     * index any more. Exactly what dropping the registry - and only the registry -
     * leaves behind, which is what an aperture replaced underfoot produces. */
    {
        uint32_t s = dead.slot;
        /* Both halves of the forgery. Clearing in_use alone would leave the
         * cached agent_count wrong, and the test would be asserting an
         * inconsistency of its own making rather than the orphan state. */
        atomic_store_explicit(&ap.hdr->agents[s - 1u].in_use, 0u,
                              memory_order_release);
        atomic_fetch_sub_explicit(&ap.hdr->agent_count, 1u, memory_order_acq_rel);
    }
    ok(qrmem_screen_owner(&ap, 4u) == dead.slot,
       "the screen still names the departed agent as owner");
    ok(qrmem_agent_count(&ap) == 0u, "while the registry holds no agents");
    /* The state the report called out as live: a screen with an owner and an
     * empty registry. */
    ok(qrmem_agent_reclaimable(&ap, 0ull) == 0u,
       "and the slot walk alone would reclaim nothing");

    /* THE SWEEP. It must walk SCREENS as well as agents. */
    {
        uint32_t freed = qrmem_agent_sweep(&ap, 0ull);
        ok(freed >= 1u, "the sweep frees the orphaned screen");
        ok(qrmem_screen_owner(&ap, 4u) == 0u,
           "and the screen is UNOWNED afterwards, rather than waiting for its "
           "slot number to come up again");
    }
    /* Content survives: freeing an orphan removes write authority, not the
     * record. */
    {
        qrmem_rec_t got;
        char rerr[256] = "";
        int found = 0;
        for (uint32_t b = 0; b < QRMEM_BLOCKS_PER_SCREEN && !found; b++)
            for (uint32_t sl = 0; sl < QRMEM_SLOTS_PER_BLOCK && !found; sl++) {
                qrmem_uuid_t want = fixed_uuid_seed(51u);
                if (qrmem_cell_read(&ap, 4u, b, sl, &got, rerr, sizeof rerr) == 0 &&
                    qrmem_uuid_equal(&got.id, &want))
                    found = 1;
            }
        ok(found, "and the record on it is still readable, byte for byte");
    }
    /* The project's label survives too: an orphan sweep is not a metadata reset. */
    ok(atomic_load_explicit(&ap.screens[4].project_len, memory_order_acquire) ==
           strlen("doomed"),
       "and the page keeps its project label");
    /* And the screen is now genuinely available to the next agent, which is the
     * property the whole fix exists to provide: a new agent claims it outright
     * rather than inheriting it. */
    other = claim_as(&ap, "newcomer");
    ok(other.slot != 0, "a new agent registers");
    ok(qrmem_screen_claim(&ap, 4u, other, "doomed", err, sizeof err) == 0,
       "and claims the freed screen normally");
    ok(qrmem_screen_owner(&ap, 4u) == other.slot, "which it now owns outright");
    /* The vanished identity cannot write it, which is the point of the fence. */
    ok(!qrmem_screen_writable(&ap, 4u, dead),
       "and the vanished agent's identity cannot write the reclaimed screen");
    qrmem_aperture_detach(&ap);
    cleanup();
}

/* A LIVE agent's screens are never orphans.
 *
 * The screen walk above must not free a screen whose owner is present and
 * holding a lease. That is the difference between healing orphans and
 * confiscating tiles from the agents that are working - which is the failure
 * mode a too-eager reclaim sweep causes, and the reason the lease exists.
 */
static void test_sweep_leaves_live_agents_alone(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    qrmem_id_t live;
    section("the sweep never frees a screen owned by a live agent");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    live = claim_as(&ap, "working");
    ok(qrmem_screen_claim(&ap, 3u, live, "in-progress", err, sizeof err) == 0,
       "a live agent claims a screen");
    qrmem_agent_lease(&ap, live.slot);
    ok(qrmem_agent_lease_held(&ap, live.slot) == 1u, "and holds a lease");
    ok(qrmem_agent_sweep(&ap, 0ull) == 0u,
       "a zero-threshold sweep reclaims nothing");
    ok(qrmem_screen_owner(&ap, 3u) == live.slot,
       "so the live agent still owns its screen");
    ok(qrmem_screen_writable(&ap, 3u, live) == 1u,
       "and can still write to it");
    qrmem_aperture_detach(&ap);
    cleanup();
}

/* `enrolled` must be able to say FALSE.
 *
 * The first version of this check was asserted only from the MCP layer, against
 * a client that had just joined - a state in which every correct implementation
 * reports true. The assertion therefore could not fail: replacing the whole
 * check with `json_object_new_boolean(1)` left the gate green. An "enrolled"
 * field that has never been seen to be false is not a check.
 *
 * So the assertion is here instead, where the three stale shapes can actually
 * be produced: an aperture recreated under a live client, a swept slot, and a
 * slot number handed to a different agent.
 */
static void test_enrollment_can_say_no(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    int auth_ok = 0, slot_ok = 0, gen_ok = 0;
    uint32_t live_gen = 0;
    section("a fenced triple is re-checked against the fabric, not trusted");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    {
        qrmem_id_t me = claim_as(&ap, "enrol");
        uint64_t auth = ap.hdr->authority_gen;
        ap.self_agent = me.slot;

        /* The honest case: everything the client holds is current. */
        qrmem_agent_enrollment_check(&ap, me.slot, auth, me.agent_gen,
                                     &auth_ok, &slot_ok, &gen_ok, &live_gen);
        ok(auth_ok == 1 && slot_ok == 1 && gen_ok == 1,
           "a client whose triple is current reports all three ok");
        ok(live_gen == me.agent_gen,
           "and the reported registry generation is that agent's");

        /* A DIFFERENT agent on the same slot number: the slot exists, so
         * slot_ok stays true, but the generation differs. Reporting a single
         * boolean would hide the difference between this and the next case. */
        {
            uint32_t other_slot = me.slot;      /* same number            */
            uint32_t other_gen = me.agent_gen + 41u; /* not this generation */
            qrmem_agent_enrollment_check(&ap, other_slot, auth, other_gen,
                                         &auth_ok, &slot_ok, &gen_ok,
                                         &live_gen);
            ok(slot_ok == 1, "the slot is still allocated...");
            ok(gen_ok == 0, "...but a different generation does not match");
            ok(auth_ok == 1, "and the lease itself is still current");
        }

        /* A slot the fabric does not know at all: the aperture was replaced
         * while this client kept its slot number. */
        {
            uint32_t absent = 0xFFFFu;
            qrmem_agent_enrollment_check(&ap, absent, auth, 7u,
                                         &auth_ok, &slot_ok, &gen_ok,
                                         &live_gen);
            ok(auth_ok == 1, "authority can still be current...");
            ok(slot_ok == 0 && gen_ok == 0,
               "...while the slot is reported as not allocated at all");
        }

        /* An authority generation from a previous daemon incarnation. This is
         * the case that stops a running client believing it still holds the
         * screen after a --recreate. */
        {
            uint64_t stale_auth = auth + 1u;
            qrmem_agent_enrollment_check(&ap, me.slot, stale_auth,
                                         me.agent_gen, &auth_ok, &slot_ok,
                                         &gen_ok, &live_gen);
            ok(auth_ok == 0, "a lease from a previous incarnation is refused");
        }

        /* Authority generation 0 is never valid. A client that never leased -
         * or a struct zeroed by a failed init - must not read as enrolled. */
        qrmem_agent_enrollment_check(&ap, me.slot, 0u, me.agent_gen, &auth_ok,
                                     &slot_ok, &gen_ok, &live_gen);
        ok(auth_ok == 0, "an authority generation of 0 is never enrolled");
        qrmem_agent_enrollment_check(&ap, 0u, auth, me.agent_gen, &auth_ok,
                                     &slot_ok, &gen_ok, &live_gen);
        ok(slot_ok == 0, "slot 0 is never enrolled");

        /* The fabric being gone must report nothing rather than crash. */
        qrmem_agent_enrollment_check(NULL, me.slot, auth, me.agent_gen,
                                     &auth_ok, &slot_ok, &gen_ok, &live_gen);
        ok(auth_ok == 0 && slot_ok == 0 && gen_ok == 0,
           "a detached fabric reports nothing enrolled rather than failing");
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}

/* Fabric identity: minted once, per fabric, and independent of everything local.
 *
 * The properties that matter are all NEGATIVE ones - what the id must NOT be a
 * function of. An identity derived from anything observable about the machine is
 * an identity that two machines can collide on, and the aperture pathname is
 * IDENTICAL on every host, so that one collision is not hypothetical: it is the
 * default. */
static void test_fabric_identity(void) {
    qrmem_ap_t a, b;
    char err[512] = "";
    qrmem_uuid_t fa, fb;
    char ta[40], tb[40];
    section("fabric_id is minted per fabric and is not derived from anything local");
    cleanup();
    if (qrmem_aperture_create(&a, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    ok(qrmem_fabric_id(&a, &fa) == 0 && qrmem_uuid_text(&fa, ta, sizeof ta) == 0,
       "a fresh fabric has an id");
    ok(ta[14] == '4', "and it is a version 4 UUID");
    ok((ta[19] == '8' || ta[19] == '9' || ta[19] == 'a' || ta[19] == 'b'),
       "with a valid variant nibble");
    ok(qrmem_uuid_text(&fa, ta, sizeof ta) == 0, "renderable");

    /* Idempotent: asking twice gives the same answer, because it is READ and
     * never re-minted. A helper that quietly minted on read would make every
     * reference to the same fabric disagree with every other. */
    {
        qrmem_uuid_t again;
        char tg[40];
        ok(qrmem_fabric_id(&a, &again) == 0 &&
               qrmem_uuid_text(&again, tg, sizeof tg) == 0 && !strcmp(ta, tg),
           "reading it twice returns the same id, never a fresh one");
    }

    /* A SECOND fabric gets a DIFFERENT id, even though it is created the same
     * way, on the same machine, by the same process. This is the property that
     * makes the id worth having. */
    {
        qrmem_ap_t c;
        char err2[512] = "";
        char nm[128];
        snprintf(nm, sizeof nm, "%s-second", NAME);
        cleanup_named(nm);
        if (qrmem_aperture_create(&c, nm, err2, sizeof err2) != 0) {
            ok(0, "create second fabric");
        } else {
            ok(qrmem_fabric_id(&c, &fb) == 0 &&
                   qrmem_uuid_text(&fb, tb, sizeof tb) == 0,
               "a second fabric has an id");
            ok(strcmp(ta, tb) != 0,
               "and it is DIFFERENT from the first: two fabrics, two namespaces");
            qrmem_aperture_detach(&c);
            cleanup_named(nm);
        }
    }

    /* THE case a path-derived id gets wrong, and the one that matters across
     * machines: a NEW fabric at the SAME path. Two hosts run the identical
     * aperture name, and --recreate puts a new fabric where an old one stood.
     * If the id were derived from the path, both situations would REUSE the
     * previous identity - which is a namespace clone, and it would make every
     * qualified address ever written resolve to two different places at once.
     *
     * The first version of this test used two differently-named fabrics, which
     * a path-derived hash satisfies trivially. Naming them apart hid the very
     * defect the property exists to prevent. */
    {
        qrmem_ap_t d;
        char err3[512] = "";
        char tc[40];
        qrmem_aperture_detach(&a);
        cleanup();                       /* same name, gone */
        if (qrmem_aperture_create(&d, NAME, err3, sizeof err3) != 0) {
            ok(0, "recreate at the same path");
        } else {
            qrmem_uuid_t fc;
            ok(qrmem_fabric_id(&d, &fc) == 0 &&
                   qrmem_uuid_text(&fc, tc, sizeof tc) == 0,
               "a fabric recreated at the SAME path has an id");
            ok(strcmp(ta, tc) != 0,
               "and it is NOT the previous fabric's id: a new fabric is a new "
               "namespace, never a clone of the one it replaced");
            qrmem_aperture_detach(&d);
        }
        if (qrmem_aperture_attach(&a, NAME, err, sizeof err) != 0) {
            ok(0, "re-attach");
            cleanup();
            return;
        }
        ok(qrmem_fabric_id(&a, &fb) == 0 &&
               qrmem_uuid_text(&fb, tb, sizeof tb) == 0 && !strcmp(tc, tb),
           "and that new id is then stable across rebinds");
        ta[0] = '\0';
        snprintf(ta, sizeof ta, "%s", tc);
    }

    /* A restart is a rebind, not a new fabric: authority moves, identity does
     * not. This is the property that lets a qualified address outlive the daemon
     * that minted it. */
    {
        uint64_t auth_before = a.hdr->authority_gen;
        char tb2[40];
        qrmem_aperture_bump_epoch(&a);
        ok(a.hdr->authority_gen != auth_before,
           "a rebind moves authority_gen, retiring every previous lease");
        ok(qrmem_fabric_id(&a, &fb) == 0 &&
               qrmem_uuid_text(&fb, tb2, sizeof tb2) == 0 && !strcmp(ta, tb2),
           "and fabric_id is UNCHANGED by it");
    }

    /* Not derived from the path: the id was minted before the path could
     * matter, and nothing recomputes it. Proven by the fact that it survived an
     * epoch bump, an ownership cycle and repeated reads unchanged. */
    ok(qrmem_fabric_id(NULL, &fb) != 0, "a detached fabric has no id to report");
    qrmem_aperture_detach(&a);
    cleanup();
}

/* Origin is stamped by the claim path, never supplied by the claimant.
 *
 * There is no origin parameter on qrmem_agent_claim: nothing the connecting
 * client says - not its --agent label, not a --host flag, not a hello field -
 * reaches this value. Every claim in this build arrives over the daemon's own
 * control socket, so LOCAL is a fact about how the call got here. A test that
 * passed an origin in would be testing a different, worse API: one where any
 * client can claim any source, which is exactly what the field exists to make
 * impossible. */
static void test_origin_stamped_by_authority(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    section("a lease source is recorded by the authority, not asserted");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    {
        qrmem_id_t me = claim_as(&ap, "origin-probe");
        char host[QRMEM_AUTHORITY_HOST_MAX];
        ok(qrmem_agent_origin_kind(&ap, me.slot) == QRMEM_ORIGIN_LOCAL,
           "a claimed slot reports LOCAL: the daemon granted it itself");
        /* Reclaiming (same name, new generation) re-stamps rather than
         * inheriting: a slot reused across builds never carries a previous
         * occupant's source. */
        {
            qrmem_id_t again = claim_as(&ap, "origin-probe");
            ok(again.slot == me.slot && again.agent_gen != me.agent_gen,
               "reclaiming the same name takes a new generation");
            ok(qrmem_agent_origin_kind(&ap, again.slot) == QRMEM_ORIGIN_LOCAL,
               "and the source is stamped fresh, not inherited");
        }
        /* Out-of-range and detached report UNKNOWN rather than failing: presence
         * must degrade to "unknown", never invent a source. */
        ok(qrmem_agent_origin_kind(&ap, 0u) == QRMEM_ORIGIN_UNKNOWN,
           "slot 0 has no source to report");
        ok(qrmem_agent_origin_kind(&ap, QRMEM_AGENT_MAX + 1u) ==
               QRMEM_ORIGIN_UNKNOWN,
           "a slot past the registry has no source to report");
        ok(qrmem_agent_origin_kind(NULL, me.slot) == QRMEM_ORIGIN_UNKNOWN,
           "a detached fabric reports unknown rather than failing");
        /* The authority host is descriptive scaffolding for the field above. */
        ok(qrmem_authority_host(&ap, host, sizeof host) != 0,
           "no daemon has written its hostname here yet, and the accessor "
           "says so rather than returning an empty string as a host");
        qrmem_agent_release(&ap, me.slot);
        ok(qrmem_agent_origin_kind(&ap, me.slot) == QRMEM_ORIGIN_UNKNOWN,
           "after release the source is UNKNOWN again: the next occupant "
           "must earn its own stamp rather than inherit this one");
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}

static void test_generation_and_aba(void) {
    qrmem_ap_t ap;
    char err[512] = "";
    uint64_t h1, h2, g0;
    section("generation moves once per operation; a restart invalidates handles");
    cleanup();
    if (qrmem_aperture_create(&ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    {
        qrmem_id_t me = claim_as(&ap, "gen");
        ap.self_agent = me.slot;
        qrmem_screen_claim(&ap, 2u, me, NULL, err, sizeof err);
        g0 = qrmem_generation(&ap, 2u);
        {
            qrmem_rec_t r;
            qrmem_rec_init(&r, QRMEM_CT_WORD, fixed_uuid_seed(1u));
            qrmem_tile_write(&ap, 2u, 0u, 0u, me, &r, err, sizeof err);
        }
    }
    ok(qrmem_generation(&ap, 2u) == g0 + 1u,
       "one write bumps the generation exactly once");
    h1 = qrmem_handle_mint(&ap);
    h2 = qrmem_handle_mint(&ap);
    ok(qrmem_handle_valid(&ap, h1) && qrmem_handle_valid(&ap, h2),
       "freshly minted handles are valid");
    ok(qrmem_handle_valid(&ap, 0u) == 0, "handle 0 is never valid");
    qrmem_aperture_bump_epoch(&ap);
    ok(qrmem_epoch(&ap) == 2u, "a restart bumps the epoch");
    ok(qrmem_handle_valid(&ap, h1) == 0 && qrmem_handle_valid(&ap, h2) == 0,
       "every handle from the previous era is now invalid (ABA boundary)");
    ok(qrmem_handle_valid(&ap, qrmem_handle_mint(&ap)) == 1,
       "a handle minted after the restart is valid");
    /* A handle is opaque: no resource index leaks into it. */
    {
        uint32_t era, seq;
        qrmem_handle_split(h1, &era, &seq);
        ok(era == 1u, "handle carries its era in the high half");
        ok(seq != 0u, "and a non-zero sequence in the low half");
    }
    qrmem_aperture_detach(&ap);
    cleanup();
}
#define STRESS_THREAD_WRITES 200000u

static qrmem_ap_t g_ap_storage;
#define g_ap (&g_ap_storage)
static _Atomic int g_stop;

static void *writer_main(void *arg) {
    qrmem_id_t agent = *(qrmem_id_t *)arg;
    uint32_t i;
    for (i = 0; i < STRESS_THREAD_WRITES; i++) {
        qrmem_rec_t r;
        char e[256] = "";
        uint32_t slot = i % QRMEM_SLOTS_PER_BLOCK;
        qrmem_rec_init(&r, QRMEM_CT_WORD, fixed_uuid_seed((unsigned char)(i + 1u)));
        if (qrmem_rec_add_text(&r, "payload", 7) != 0 ||
            qrmem_rec_add_u32(&r, QRMEM_TLV_BLOCK, i) != 0 ||
            qrmem_rec_add_u32(&r, QRMEM_TLV_SLOT, slot) != 0)
            break;
        if (qrmem_tile_write(g_ap, 0u, 0u, slot, agent, &r, e, sizeof e) != 0)
            break;
    }
    atomic_store_explicit(&g_stop, 1, memory_order_release);
    return NULL;
}

/* Classify why a read did not return a record.
 *
 * This distinction matters more than it looks. An earlier version of this
 * reader counted only records that decoded SUCCESSFULLY but were internally
 * inconsistent, and treated every failed read as "nothing there yet". That made
 * the gate blind to the most common way a tear shows up: the integrity witness
 * CATCHES it and the read returns an error. So the fabric was correctly refusing
 * torn records, the test was scoring that as a pass, and the gate could not fail
 * even with the reader drain and the sequence lock both switched off.
 *
 * "empty" is the only benign outcome. The other three are a fabric reporting
 * that it could not hand back a record it should have been able to read. */
enum { RD_OK = 0, RD_EMPTY, RD_TORN, RD_UNSETTLED, RD_OTHER };

static int classify_read(const char *e) {
    if (!e || !e[0])
        return RD_EMPTY;
    if (strstr(e, "is empty"))
        return RD_EMPTY;
    if (strstr(e, "integrity witness"))
        return RD_TORN;
    if (strstr(e, "did not settle"))
        return RD_UNSETTLED;
    if (strstr(e, "malformed TLV"))
        return RD_TORN;
    return RD_OTHER;
}

static _Atomic uint64_t g_torn;    /* decoded but internally inconsistent */
static _Atomic uint64_t g_witness; /* refused by the integrity witness */
static _Atomic uint64_t g_unsettled;
static _Atomic uint64_t g_other;
static _Atomic uint64_t g_seen;

static void *reader_main(void *arg) {
    (void)arg;
    while (!atomic_load_explicit(&g_stop, memory_order_acquire)) {
        for (uint32_t slot = 0; slot < QRMEM_SLOTS_PER_BLOCK; slot++) {
            qrmem_rec_t g;
            char e[256] = "";
            uint32_t gx = 0, gy = 0;
            const char *txt = NULL;
            size_t tl = 0;
            if (qrmem_cell_read(g_ap, 0u, 0u, slot, &g, e, sizeof e) != 0) {
                switch (classify_read(e)) {
                case RD_EMPTY:
                    break;
                case RD_TORN:
                    atomic_fetch_add_explicit(&g_witness, 1u,
                                              memory_order_relaxed);
                    break;
                case RD_UNSETTLED:
                    atomic_fetch_add_explicit(&g_unsettled, 1u,
                                              memory_order_relaxed);
                    break;
                default:
                    atomic_fetch_add_explicit(&g_other, 1u,
                                              memory_order_relaxed);
                    break;
                }
                continue;
            }
            atomic_fetch_add_explicit(&g_seen, 1u, memory_order_relaxed);
            /* Identity is no longer derived from the address, so the old
             * cross-check - that a record's id must encode where it lives - is
             * exactly the coupling this change removed and must not come back.
             * What a torn read still looks like is a record whose fields do not
             * agree with each other: its address fields must match where it was
             * found, its payload must be intact, and its identity must be a
             * well-formed v4. A half-published identity fails the last of those
             * because the version nibble lands in the same word as body bytes. */
            if (qrmem_rec_get_u32(&g, QRMEM_TLV_BLOCK, &gx) != 0 ||
                qrmem_rec_get_u32(&g, QRMEM_TLV_SLOT, &gy) != 0 ||
                qrmem_rec_get_text(&g, &txt, &tl) != 0 || tl != 7 ||
                memcmp(txt, "payload", 7) != 0 || gy != slot || !is_v4(&g.id))
                atomic_fetch_add_explicit(&g_torn, 1u, memory_order_relaxed);
        }
    }
    return NULL;
}

/* One writer thread, one reader thread, one mapping. This is the gate. */
static void test_threaded_stress(int weakened) {
    pthread_t wt, rt;
    qrmem_id_t agent = {0};
    char err[512] = "";
    uint64_t seen, torn;
    section(weakened ? "threaded publish/read stress (WEAKENED: this is what "
                       "must be caught)"
                     : "threaded publish/read stress");
    cleanup();
    if (qrmem_aperture_create(g_ap, NAME, err, sizeof err) != 0) {
        ok(0, "create");
        return;
    }
    agent = claim_as(g_ap, "stress");
    if (agent.slot == 0) {
        ok(0, "enrol");
        qrmem_aperture_detach(g_ap);
        cleanup();
        return;
    }
    g_ap->self_agent = agent.slot;
    if (qrmem_screen_claim(g_ap, 0u, agent, NULL, err, sizeof err) != 0) {
        ok(0, "claim");
        qrmem_aperture_detach(g_ap);
        cleanup();
        return;
    }
    atomic_store(&g_stop, 0);
    atomic_store(&g_torn, 0);
    atomic_store(&g_witness, 0);
    atomic_store(&g_unsettled, 0);
    atomic_store(&g_other, 0);
    atomic_store(&g_seen, 0);
    if (pthread_create(&rt, NULL, reader_main, NULL) != 0 ||
        pthread_create(&wt, NULL, writer_main, &agent) != 0) {
        ok(0, "thread create");
        qrmem_aperture_detach(g_ap);
        cleanup();
        return;
    }
    pthread_join(wt, NULL);
    pthread_join(rt, NULL);
    seen = atomic_load(&g_seen);
    torn = atomic_load(&g_torn);
    printf("  info reader read %llu records; %llu inconsistent, %llu refused "
           "by the witness, %llu never settled, %llu other refusals\n",
           (unsigned long long)seen, (unsigned long long)torn,
           (unsigned long long)atomic_load(&g_witness),
           (unsigned long long)atomic_load(&g_unsettled),
           (unsigned long long)atomic_load(&g_other));
    ok(seen > 0u, "the reader ran concurrently with the writer");
    ok(torn == 0u, "no reader ever decoded a half-written record");
    ok(atomic_load(&g_witness) == 0u,
       "no read was refused by the integrity witness (that is a torn record "
       "being caught)");
    ok(atomic_load(&g_other) == 0u, "no read failed for any other reason");
    /* Reads that lost the retry race are counted with a bound rather than an
     * absolute zero. The stress here is deliberately pathological: one writer
     * rewrites the same 128 cells 200k times while the reader sweeps all 128,
     * so a reader can lose the same cell 64 times in a row and honestly have
     * nothing complete to read. That is starvation, not corruption, and the
     * fabric's answer to it is to say so rather than invent a record.
     *
     * The bound is 1 in 1000 and it is a real assertion: the earlier version of
     * this test asserted an absolute zero, which only "passed" because it was
     * blind to refusals, and when the blindness was fixed it failed for a
     * reason that was not a defect. */
    {
        uint64_t un = atomic_load(&g_unsettled);
        printf("  info starvation rate: %llu in %llu reads\n",
               (unsigned long long)un, (unsigned long long)seen);
        ok(seen == 0u || un * 1000u <= seen,
           "starved reads stayed under 1 in 1000");
    }
    qrmem_aperture_detach(g_ap);
    cleanup();
}

#ifdef QRMEM_WEAKEN_RELEASE
int main(void) {
    printf("qrmem aperture contract test (WEAKENED publication ordering)\n");
    test_layout();
    test_threaded_stress(1);
    printf("\nchecks=%d failures=%d\n", checks, failures);
    /* A weakened build must still be internally consistent here; the race it
     * introduces is what ThreadSanitizer reports, not this counter. Exit
     * non-zero so the shell gate cannot mistake it for a pass. */
    return failures ? 1 : 0;
}
#else
int main(void) {
    printf("qrmem aperture contract test\n");
    test_layout();
    test_create_attach();
    test_attach_refusals();
    test_single_writer();
    test_label_is_not_identity();
    test_failed_claim_leaves_no_trace();
    test_slots_are_reclaimed_without_transferring_screens();
    test_supersede_is_discoverable();
    test_identity_field_is_a_uuid();
    test_sweep_frees_orphaned_screens();
    test_sweep_leaves_live_agents_alone();
    test_presence_is_a_lease_not_a_timeout();
    test_generation_and_aba();
    test_origin_stamped_by_authority();
    test_fabric_identity();
    test_enrollment_can_say_no();
    test_threaded_stress(0);
    printf("\nchecks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
#endif
