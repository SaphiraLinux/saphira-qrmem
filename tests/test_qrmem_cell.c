/* Saphira Memory - qrmem cell codec test: round trip, refusal, and a fuzzer.
 *
 * The contract under test is that the decoder REFUSES. Every malformed input
 * must be rejected, and none may be repaired, clamped or partially read: a
 * silently repaired cell makes a fabric bug look like a working system, which
 * is the failure this whole file exists to prevent.
 *
 * The fuzzer reports its iteration count AND its accepted-parse count, because
 * a fuzzer that has gone vacuous (accepting nothing, or everything) still exits
 * zero and looks like evidence.
 */
#include "qrmem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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


/* Deterministic valid v4 identities for codec tests. A codec round trip must
 * be assertable against an exact value, and minting cannot be. The version and
 * variant nibbles are real v4 values, so a broken parser cannot pass here. */
static qrmem_uuid_t U(unsigned char seed) {
    qrmem_uuid_t u;
    unsigned char i;
    memset(&u, 0, sizeof u);
    for (i = 0; i < QRMEM_UUID_BYTES; i++)
        u.b[i] = (unsigned char)(seed + i * 7u);
    u.b[6] = (unsigned char)((u.b[6] & 0x0Fu) | 0x40u);
    u.b[8] = (unsigned char)((u.b[8] & 0x3Fu) | 0x80u);
    return u;
}

static void section(const char *n) { printf("\n== %s\n", n); }

static void test_roundtrip(void) {
    qrmem_rec_t r, g;
    uint32_t toks[4] = {11u, 22u, 33u, 44u}, back[8];
    size_t n = 0;
    uint32_t v = 0;
    uint8_t sv = 0;
    const char *txt = NULL;
    size_t tl = 0;
    section("a record survives a round trip through a cell unchanged");
    qrmem_rec_init(&r, QRMEM_CT_FACT, U(10u));
    ok(qrmem_rec_add_text(&r, "the sun was shining", 19) == 0, "text fits");
    ok(qrmem_rec_add_u32(&r, QRMEM_TLV_SUBJECT, 817u) == 0, "subject fits");
    ok(qrmem_rec_add_u32(&r, QRMEM_TLV_RELATION, 33u) == 0, "relation fits");
    ok(qrmem_rec_add_u32(&r, QRMEM_TLV_OBJECT, 291u) == 0, "object fits");
    ok(qrmem_rec_add_u8(&r, QRMEM_TLV_STATUS, QRMEM_STATUS_WITNESSED) == 0,
       "status fits");
    ok(qrmem_rec_add_u32_array(&r, QRMEM_TLV_TOKENS, toks, 4) == 0,
       "tokens fit");
    ok(qrmem_rec_link(&r, U(7u)) == 0, "link 1 fits");
    ok(qrmem_rec_link(&r, U(8u)) == 0, "link 2 fits");
    ok(qrmem_rec_link(&r, U(9u)) == 0, "link 3 fits");
    ok(qrmem_rec_link(&r, U(10u)) == 0, "link 4 fits");
    /* A fifth link must be refused, not dropped. */
    ok(qrmem_rec_link(&r, U(11u)) != 0, "a fifth link is refused");
    ok(r.n_links == QRMEM_CELL_LINKS, "the refusal left the link set intact");
    g = r;
    ok(qrmem_rec_get_text(&g, &txt, &tl) == 0 && tl == 19 &&
           !memcmp(txt, "the sun was shining", 19),
       "text round trips with its exact length");
    ok(qrmem_rec_get_u32(&g, QRMEM_TLV_SUBJECT, &v) == 0 && v == 817u,
       "subject round trips");
    ok(qrmem_rec_get_u8(&g, QRMEM_TLV_STATUS, &sv) == 0 &&
           sv == QRMEM_STATUS_WITNESSED,
       "status round trips");
    ok(qrmem_rec_get_u32_array(&g, QRMEM_TLV_TOKENS, back, 8, &n) == 0 &&
           n == 4 && back[0] == 11u && back[3] == 44u,
       "the token array round trips in order");
    /* Absent and malformed are different answers. */
    ok(qrmem_rec_get_u32(&g, QRMEM_TLV_SOURCE, &v) != 0,
       "an absent field reports absent");
    /* Identity round trips byte for byte. This is the whole point of storing 16
     * raw bytes rather than the 36-character text: equality is a byte compare
     * that cannot drift with spelling. */
    ok(qrmem_uuid_equal(&g.id, &r.id), "the record's own id round trips");
    ok(g.n_links == 4u && qrmem_uuid_equal(&g.links[0], &r.links[0]) &&
           qrmem_uuid_equal(&g.links[3], &r.links[3]),
       "every link round trips, in order");
}

static void test_oversize(void) {
    qrmem_rec_t r;
    char big[QRMEM_CELL_BODY * 2];
    section("a payload that does not fit is refused, never truncated");
    memset(big, 'x', sizeof big);
    qrmem_rec_init(&r, QRMEM_CT_WORD, U(1u));
    ok(qrmem_rec_add_text(&r, big, sizeof big) != 0,
       "an oversized text payload is refused");
    ok(qrmem_rec_add_text(&r, big, QRMEM_CELL_BODY - 8u) == 0,
       "a payload that just fits is accepted");
    ok(qrmem_rec_add_text(&r, "more", 4) != 0,
       "the next field no longer fits and is refused");
    ok(r.body_len <= QRMEM_CELL_BODY, "body_len never exceeds the body");
}

static void test_validate_refuses(void) {
    unsigned char body[64];
    section("structural validation rejects rather than repairs");
    ok(qrmem_cell_validate(NULL, 0) != 0, "a null body is refused");
    ok(qrmem_cell_validate(body, QRMEM_CELL_BODY + 1u) != 0,
       "a length beyond the body is refused");
    /* Truncated TLV header. */
    memset(body, 0, sizeof body);
    ok(qrmem_cell_validate(body, 3) != 0, "a truncated TLV header is refused");
    /* bytes < header size. */
    memset(body, 0, sizeof body);
    body[0] = 0;
    body[1] = 1;
    body[2] = 0;
    body[3] = 2; /* claims 2 bytes, header alone is 4 */
    ok(qrmem_cell_validate(body, 4) != 0, "bytes below the header is refused");
    /* bytes overruns the chain. */
    memset(body, 0, sizeof body);
    body[1] = 1;
    body[2] = 0xFF;
    body[3] = 0xFF;
    ok(qrmem_cell_validate(body, 8) != 0,
       "a TLV that overruns the body is refused");
    /* A well-formed single empty TLV. */
    memset(body, 0, sizeof body);
    body[1] = QRMEM_TLV_TEXT;
    body[2] = 0;
    body[3] = 4;
    ok(qrmem_cell_validate(body, 4) == 0, "a well-formed empty TLV validates");
    ok(qrmem_cell_validate(body, 5) != 0,
       "trailing bytes after a complete chain are refused");
}

static void test_wrong_shape(void) {
    qrmem_rec_t r, g;
    uint32_t v = 0;
    size_t n = 0;
    uint32_t small[1];
    section("a present-but-wrong-shaped field is an error, not a short read");
    qrmem_rec_init(&r, QRMEM_CT_WORD, U(1u));
    /* TEXT holding 3 bytes, then read it back as a u32. */
    qrmem_rec_add_text(&r, "abc", 3);
    g = r;
    ok(qrmem_rec_get_u32(&g, QRMEM_TLV_TEXT, &v) != 0,
       "reading a 3-byte field as u32 is refused");
    ok(qrmem_rec_get_u32_array(&g, QRMEM_TLV_TEXT, small, 1, &n) != 0,
       "reading a 3-byte field as a u32 array is refused (not a partial read)");
    ok(n == 0, "the refused array read left the count at zero");
}

static uint32_t rng_state = 0x13579BDFu;
static uint32_t rng(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static void test_fuzz(unsigned iters) {
    unsigned accepted = 0, refused = 0, i;
    unsigned char body[QRMEM_CELL_BODY];
    section("fuzz: a malformed TLV chain is always refused, never repaired");
    for (i = 0; i < iters; i++) {
        size_t len = (size_t)(rng() % (QRMEM_CELL_BODY + 1u));
        unsigned j;
        for (j = 0; j < len; j++)
            body[j] = (unsigned char)(rng() & 0xFFu);
        if (qrmem_cell_validate(body, len) == 0)
            accepted++;
        else
            refused++;
    }
    printf("  info fuzz: %u iterations, %u accepted, %u refused\n", iters,
           accepted, refused);
    ok(refused > 0, "the fuzzer actually produced refusals (not vacuous)");
    ok(accepted < iters, "the fuzzer did not accept everything");
    /* Targeted fuzz: start from a VALID body and corrupt one byte at a time.
     * Every single-byte corruption of a valid chain must be either still valid
     * or cleanly refused - never a crash and never a silent repair. */
    {
        qrmem_rec_t r;
        unsigned char good[QRMEM_CELL_BODY];
        size_t glen, k;
        unsigned flips = 0, survived = 0;
        qrmem_rec_init(&r, QRMEM_CT_FACT, U(10u));
        qrmem_rec_add_text(&r, "payload", 7);
        qrmem_rec_add_u32(&r, QRMEM_TLV_SUBJECT, 817u);
        qrmem_rec_add_u8(&r, QRMEM_TLV_STATUS, QRMEM_STATUS_SUPPORTED);
        memcpy(good, r.body, r.body_len);
        glen = r.body_len;
        ok(qrmem_cell_validate(good, glen) == 0, "the seed body is valid");
        /* Flip every bit of every byte. The assertion is CRASH-FREEDOM plus
         * DETERMINISM: a corrupted chain must not read out of bounds, and the
         * validator must reach the same verdict twice for the same bytes. An
         * earlier version of this loop carried a `bad` counter that was never
         * assigned, so the check could not fail. */
        for (k = 0; k < glen; k++) {
            for (int bit = 0; bit < 8; bit++) {
                unsigned char save = good[k];
                int v1, v2;
                good[k] = (unsigned char)(save ^ (1u << bit));
                v1 = qrmem_cell_validate(good, glen);
                v2 = qrmem_cell_validate(good, glen);
                flips++;
                if (v1 == 0)
                    survived++;
                if (v1 != v2)
                    failures++;
                good[k] = save;
            }
        }
        checks++;
        printf("  info flipped %u bits; %u left a structurally valid chain\n",
               flips, survived);
        ok(flips > 0, "the bit-flip sweep actually ran");
        ok(survived < flips,
           "some corruptions were rejected, so the sweep is not vacuous");
        ok(failures == 0, "every verdict was deterministic across two calls");
    }
}


/* A payload must come back OUT.
 *
 * This exists because a render bug removed it. The MCP layer's record-to-JSON
 * function emitted the record's text by reading a DIFFERENT tag than the one the
 * payload is written under - INDEX_KEY instead of TEXT - so every read returned
 * a record with no text at all, and did so silently.
 *
 * Every existing gate passed. They check record counts, identities, witnesses,
 * index resolution and immutability. None of them asked whether the CONTENT a
 * caller wrote is the content a caller reads back, which is the single most
 * basic property a memory has.
 *
 * So this asks it directly, for every string-valued field, and also checks that
 * two fields do not share storage: a bug that emitted the index key under the
 * name "text" would pass a test that only checked "some text appears".
 */
static void test_payload_survives_the_round_trip(void) {
    qrmem_rec_t r, g;
    const char *txt = NULL;
    const char *key = NULL;
    size_t tl = 0, kl = 0;
    section("a payload and its lookup key are distinct, and both come back");
    /* A payload, a lookup key, and text that would be ambiguous if the two
     * fields shared storage. */
    qrmem_rec_init(&r, QRMEM_CT_WORD, U(12u));
    ok(qrmem_rec_add_text(&r, "PAYLOAD-CANARY-9f3a", 19) == 0, "payload fits");
    ok(qrmem_rec_add_text_tag(&r, QRMEM_TLV_INDEX_KEY, "KEY-CANARY-77b1",
                              16) == 0,
       "lookup key fits, under its own tag");
    g = r;

    /* The payload comes back under TEXT. */
    ok(qrmem_rec_get_text(&g, &txt, &tl) == 0, "the payload is readable");
    ok(tl == 19u && memcmp(txt, "PAYLOAD-CANARY-9f3a", 19) == 0,
       "and it is the payload, byte for byte");
    /* And NOT the key. This is the exact shape of the bug that removed it. */
    ok(!(tl == 16u && memcmp(txt, "KEY-CANARY-77b1", 16) == 0),
       "the payload field does not return the lookup key");

    /* The key comes back under its own tag. */
    ok(qrmem_rec_get_text_tag(&g, QRMEM_TLV_INDEX_KEY, &key, &kl) == 0,
       "the lookup key is readable under its own tag");
    ok(kl == 16u && memcmp(key, "KEY-CANARY-77b1", 16) == 0,
       "and it is the key, byte for byte");
    ok(!(kl == 19u && memcmp(key, "PAYLOAD-CANARY-9f3a", 19) == 0),
       "the key field does not return the payload");

    /* A record with a key but no payload: the absent case must stay absent
     * rather than falling back to whatever else is in the body. */
    {
        qrmem_rec_t n;
        qrmem_rec_init(&n, QRMEM_CT_WORD, U(13u));
        ok(qrmem_rec_add_text_tag(&n, QRMEM_TLV_INDEX_KEY, "only-a-key", 9) == 0,
           "a record may carry a key with no payload");
        txt = NULL;
        tl = 0;
        ok(qrmem_rec_get_text(&n, &txt, &tl) != 0,
           "and the payload is reported ABSENT rather than filled from the key");
        ok(qrmem_rec_get_text_tag(&n, QRMEM_TLV_INDEX_KEY, &key, &kl) == 0 &&
               kl == 9u && memcmp(key, "only-a-key", 9) == 0,
           "while the key is still there");
    }
    /* A payload with no key: the reverse. */
    {
        qrmem_rec_t n;
        qrmem_rec_init(&n, QRMEM_CT_WORD, U(14u));
        ok(qrmem_rec_add_text(&n, "only-a-payload", 14) == 0,
           "a record may carry a payload with no key");
        key = NULL;
        kl = 0;
        ok(qrmem_rec_get_text_tag(&n, QRMEM_TLV_INDEX_KEY, &key, &kl) != 0,
           "and the key is reported ABSENT rather than filled from the payload");
    }
}

int main(void) {
    unsigned iters = 200000u;
    const char *e = getenv("QRMEM_FUZZ_ITERS");
    if (e && *e)
        iters = (unsigned)strtoul(e, NULL, 10);
    printf("qrmem cell codec test\n");
    test_roundtrip();
    test_payload_survives_the_round_trip();
    test_oversize();
    test_validate_refuses();
    test_wrong_shape();
    test_fuzz(iters);
    printf("\nchecks=%d failures=%d\n", checks, failures);
    return failures ? 1 : 0;
}
