/* Saphira Memory - record identity test.
 *
 * A record's id is a UUIDv4, full stop. That contract is what this file proves,
 * and it is worth a file of its own because the thing it replaced was wrong in
 * three separate ways, each of which had already caused real confusion:
 *
 *   1. `id` was a 32-bit integer the CALLER invented. Two agents on different
 *      screens both wrote 1031 and reasonably concluded they had named the same
 *      record. They had not, and nothing on the surface said so.
 *   2. Non-numeric ids were silently coerced to zero. A malformed call looked
 *      like a successful write of an id nobody chose.
 *   3. `id` was both a name and a label, so nothing distinguished "which record
 *      is this" from "a number the writer felt like using".
 *
 * The split that removes all three:
 *
 *     (screen, block, slot)  WHERE a record currently lives
 *     id (UUIDv4)            WHICH record it is
 *
 * The strictness is one-directional on purpose: canonical is lowercase, and
 * uppercase is REFUSED rather than normalised. Two spellings of one identity is
 * the ambiguity being removed, so the parser accepts exactly one form.
 *
 * Every refusal here must also leave `out` nil. A caller that ignores a -1 and
 * writes anyway must not end up publishing an all-zero identity that looks like
 * a deliberate choice.
 */
#include "qrmem.h"

#include <stdio.h>
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

static void section(const char *n) { printf("\n== %s\n", n); }

#define TLEN ((size_t)QRMEM_UUID_TEXT_LEN + 1u)

static void test_canonical_round_trip(void) {
    static const char *kGood =
        "f81d4fae-7dec-41d0-a765-00a0c91e6bf6";
    qrmem_uuid_t u;
    char err[256] = "";
    char back[TLEN];
    section("canonical text round trips byte for byte");
    ok(qrmem_uuid_parse(kGood, &u, err, sizeof err) == 0, "a canonical v4 parses");
    ok(qrmem_uuid_text(&u, back, TLEN) == 0, "and renders");
    ok(strcmp(back, kGood) == 0, "to exactly the text it came from");
    /* The specific byte offsets matter: this is the RFC 4122 layout, and a
     * parser that packed the fields in a different order would still round trip
     * its own mistakes while rejecting every real UUID. */
    ok(u.b[6] == 0x41u, "byte 6 carries the version nibble 4");
    ok(u.b[8] == 0xa7u, "byte 8 carries the variant bits 10");
    ok(u.b[0] == 0xf8u && u.b[15] == 0xf6u, "first and last bytes are in place");
    ok(!qrmem_uuid_is_nil(&u), "a parsed v4 is never the nil id");
}

static void test_refuses_everything_else(void) {
    /* Each of these is something an agent could plausibly send, or something
     * the previous integer implementation accepted. All must be refused, and
     * all must leave the output nil. */
    static const char *kBad[] = {
        /* the integer regime this type replaces */
        "1031",
        "0",
        "1",
        "-1",
        "99999999999999999999",
        /* right shape, wrong spelling */
        "F81D4FAE-7DEC-41D0-A765-00A0C91E6BF6",   /* uppercase */
        "f81d4fae-7dec-41d0-a765-00a0c91e6bf",     /* 35 chars */
        "f81d4fae-7dec-41d0-a765-00a0c91e6bf6a",   /* 37 chars */
        "f81d4fae7dec41d0a76500a0c91e6bf6",        /* no dashes */
        "f81d4fae-7dec-41d0-a765-00a0c91e6bf-",    /* trailing dash */
        "-f81d4fae-7dec-41d0-a765-00a0c91e6bf6",   /* leading dash */
        "f81d4fae-7dec-41d0-a765:00a0c91e6bf6",    /* colon instead of dash */
        "f81d4fae_7dec_41d0_a765_00a0c91e6bf6",    /* underscores */
        /* right length, not hex */
        "g81d4fae-7dec-41d0-a765-00a0c91e6bf6",
        "f81d4fae-7dec-41d0-a765-00a0c91e6bfg",
        "f81d4fae-7dec-41d0-a765-00a0c91e6b 6",
        /* UUID-shaped, wrong version */
        "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",    /* v1 */
        "f81d4fae-7dec-01d0-a765-00a0c91e6bf6",    /* nil uuid */
        "f81d4fae-7dec-71d0-a765-00a0c91e6bf6",    /* v7 */
        /* UUID-shaped, wrong variant */
        "f81d4fae-7dec-41d0-0765-00a0c91e6bf6",    /* variant 0 */
        "f81d4fae-7dec-41d0-c765-00a0c91e6bf6",    /* variant c */
        "f81d4fae-7dec-41d0-f765-00a0c91e6bf6",    /* variant f */
        /* labels */
        "",
        "record-1",
        "opencode:1031",
    };
    size_t i;
    section("anything that is not canonical UUIDv4 is refused, and leaves nil");
    for (i = 0; i < sizeof kBad / sizeof kBad[0]; i++) {
        qrmem_uuid_t u;
        char err[256] = "";
        char what[160];
        int rc = qrmem_uuid_parse(kBad[i], &u, err, sizeof err);
        snprintf(what, sizeof what, "refused: \"%s\"", kBad[i]);
        ok(rc != 0, what);
        /* The reason must say something, and must name the actual rule broken.
         * A bare "invalid" would send an agent looking for a bug in its own
         * request rather than at the contract. */
        ok(err[0] != '\0', "and the refusal carries a reason");
        /* Critically: a refused parse must not leave a usable identity. */
        ok(qrmem_uuid_is_nil(&u),
           "and the output is nil, so an ignored error cannot publish a zero id");
    }
}

static void test_version_and_variant_are_checked(void) {
    /* These four are the difference between "parses 36 hex chars" and "parses a
     * UUIDv4". Each is the right length with the right dashes. */
    static const char kV1[] = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    static const char kBadVar[] = "f81d4fae-7dec-41d0-0765-00a0c91e6bf6";
    static const char kGoodVarB[] = "f81d4fae-7dec-41d0-b765-00a0c91e6bf6";
    qrmem_uuid_t u;
    char err[256] = "";
    section("version and variant nibbles are checked, not assumed");
    ok(qrmem_uuid_parse(kV1, &u, err, sizeof err) != 0, "a UUIDv1 is refused");
    ok(strstr(err, "v4") != NULL, "and the reason names the version rule");
    ok(qrmem_uuid_parse(kBadVar, &u, err, sizeof err) != 0,
       "variant nibble 0 is refused");
    ok(strstr(err, "variant") != NULL, "and the reason names the variant rule");
    ok(qrmem_uuid_parse(kGoodVarB, &u, err, sizeof err) == 0,
       "variant nibble b is accepted, the range is [89ab]");
    /* Every variant in range must work, or the rule is not the rule it claims. */
    {
        static const char kV[] = {'8', '9', 'a', 'b'};
        size_t i;
        char text[TLEN];
        for (i = 0; i < 4u; i++) {
            memcpy(text, "f81d4fae-7dec-41d0-", 19);
            text[19] = kV[i];
            memcpy(text + 20, "765-00a0c91e6bf6", 16);
            text[TLEN - 1u] = '\0';
            ok(qrmem_uuid_parse(text, &u, err, sizeof err) == 0,
               "every variant nibble in [89ab] is accepted");
        }
    }
}

static void test_mint(void) {
    enum { N = 512 };
    qrmem_uuid_t seen[N];
    qrmem_uuid_t u;
    char err[256] = "";
    int dup = 0, bad = 0, nil = 0;
    size_t i, j;
    section("a minted id is a valid v4, and minting does not repeat itself");
    for (i = 0; i < N; i++) {
        char back[TLEN];
        if (qrmem_uuid_mint(&u, err, sizeof err) != 0) {
            ok(0, "mint");
            return;
        }
        if (qrmem_uuid_is_nil(&u))
            nil++;
        /* Version and variant must be FORCED, not left to the entropy draw.
         * A mint that did not set them would produce values its own parser
         * refuses, which is the worst possible inconsistency. */
        if ((u.b[6] >> 4) != 4u || (u.b[8] & 0xC0u) != 0x80u)
            bad++;
        /* And it must render to canonical text that parses back to itself. */
        if (qrmem_uuid_text(&u, back, TLEN) != 0 ||
            qrmem_uuid_parse(back, &u, err, sizeof err) != 0)
            bad++;
        seen[i] = u;
    }
    ok(nil == 0, "no minted id is nil");
    ok(bad == 0,
       "every minted id has forced v4 nibbles and round trips through text");
    /* Duplicate detection. 512 ids is far more than any real fabric will mint in
     * one run, so a collision here would mean the entropy source is broken. */
    for (i = 0; i < N; i++)
        for (j = i + 1; j < N; j++)
            if (qrmem_uuid_equal(&seen[i], &seen[j])) {
                dup++;
                i = N;
                break;
            }
    ok(dup == 0, "no two of 512 minted ids are equal");
}

static void test_nil_is_not_an_id(void) {
    qrmem_uuid_t z;
    char err[256] = "";
    char back[TLEN];
    memset(&z, 0, sizeof z);
    section("the nil id is 'no identity', not a valid one");
    ok(qrmem_uuid_is_nil(&z), "sixteen zero bytes read as nil");
    /* Nil means ABSENT, and it is absent from the text grammar entirely: no
     * canonical UUIDv4 text can encode sixteen zero bytes, because the version
     * nibble would have to be 4 in a byte that is all zeros. That is what makes
     * "omit the successor" expressible without ever colliding with a real id. */
    ok(qrmem_uuid_parse("00000000-0000-0000-0000-000000000000", &z, err,
                        sizeof err) != 0,
       "all-zero text is refused: it carries no v4 nibbles");
    ok(qrmem_uuid_is_nil(&z),
       "and a refused parse leaves nil, the same 'absent' answer");
    /* A near-nil value that IS a valid v4 is a real, distinct identity. It must
     * not be mistaken for absence just because most of its bytes are zero. */
    {
        qrmem_uuid_t near;
        ok(qrmem_uuid_parse("00000000-0000-4000-8000-000000000000", &near, err,
                            sizeof err) == 0,
           "a valid v4 with zero high bytes parses");
        ok(!qrmem_uuid_is_nil(&near),
           "and is NOT nil: only all-zero bytes mean absent");
        ok(!qrmem_uuid_equal(&near, &z),
           "so it is distinct from absent");
    }
    ok(qrmem_uuid_text(&z, back, TLEN) == 0,
       "a nil id still renders, for diagnostics");
    memset(&z, 0, sizeof z);
    ok(qrmem_uuid_is_nil(&z), "re-zeroed, it is nil again");
}

static void test_equality_is_byte_equality(void) {
    qrmem_uuid_t a, b;
    char err[256] = "";
    section("equality is a byte compare, with no tolerance for near misses");
    ok(qrmem_uuid_parse("f81d4fae-7dec-41d0-a765-00a0c91e6bf6", &a, err,
                        sizeof err) == 0,
       "parse a");
    ok(qrmem_uuid_parse("f81d4fae-7dec-41d0-a765-00a0c91e6bf6", &b, err,
                        sizeof err) == 0,
       "parse the same text again");
    ok(qrmem_uuid_equal(&a, &b), "identical text is identical identity");
    /* One bit different in the LAST byte must be a different record. This is
     * the property a truncated or truncated-compare implementation loses: it is
     * the byte an over-long comparison is most likely to drop. */
    b.b[15] ^= 0x01u;
    ok(!qrmem_uuid_equal(&a, &b), "one flipped bit in the last byte differs");
    b.b[15] ^= 0x01u;
    ok(qrmem_uuid_equal(&a, &b), "and flipping it back restores equality");
    /* And in the first byte, which a big-endian/little-endian mistake would
     * hit instead. */
    a.b[0] ^= 0x80u;
    ok(!qrmem_uuid_equal(&a, &b), "one flipped bit in the first byte differs");
    ok(!qrmem_uuid_equal(&a, NULL) && !qrmem_uuid_equal(NULL, &b),
       "a null identity never equals anything");
}

static void test_text_buffer_is_checked(void) {
    /* A caller with a short buffer must be refused, not overrun. Rendering 36
     * characters into a 36-byte buffer would be a one-byte overflow, and the
     * only place that knows is here. */
    qrmem_uuid_t u;
    char err[256] = "";
    char small[8];
    char exact[TLEN];
    memset(small, 0xAA, sizeof small);
    ok(qrmem_uuid_parse("f81d4fae-7dec-41d0-a765-00a0c91e6bf6", &u, err,
                        sizeof err) == 0,
       "parse");
    ok(qrmem_uuid_text(&u, small, sizeof small) != 0,
       "a short buffer is refused rather than overrun");
    ok(small[0] == '\0',
       "and the buffer is cleared, so a caller cannot read a partial UUID");
    ok(qrmem_uuid_text(&u, exact, TLEN) == 0, "the exact size is accepted");
    ok(strlen(exact) == QRMEM_UUID_TEXT_LEN, "and the result is 36 characters");
    ok(qrmem_uuid_text(&u, NULL, 0) != 0, "no buffer at all is refused");
}

static void test_tag_is_not_identity(void) {
    /* qrmem_uuid_tag exists for logs and captions. It must not be usable as
     * identity: two distinct records will collide in 32 bits eventually, and a
     * caller that treated the tag as the id would merge two records. All this
     * can prove is that the tag is a function of the UUID, not that it is
     * unique - so the test states the limitation instead of implying safety. */
    qrmem_uuid_t a, b;
    char err[256] = "";
    ok(qrmem_uuid_parse("f81d4fae-7dec-41d0-a765-00a0c91e6bf6", &a, err,
                        sizeof err) == 0,
       "parse a");
    ok(qrmem_uuid_parse("f81d4fae-7dec-41d0-a765-00a0c91e6bf6", &b, err,
                        sizeof err) == 0,
       "parse the same value as b");
    ok(qrmem_uuid_tag(&a) == qrmem_uuid_tag(&b),
       "the tag is stable for one identity");
    ok(qrmem_uuid_tag(NULL) == 0u, "and nil for no identity");
}

int main(void) {
    printf("qrmem record identity test\n\n");
    test_canonical_round_trip();
    test_refuses_everything_else();
    test_version_and_variant_are_checked();
    test_mint();
    test_nil_is_not_an_id();
    test_equality_is_byte_equality();
    test_text_buffer_is_checked();
    test_tag_is_not_identity();
    printf("\n%u checks, %u failures\n", (unsigned)checks,
           (unsigned)failures);
    return failures ? 1 : 0;
}