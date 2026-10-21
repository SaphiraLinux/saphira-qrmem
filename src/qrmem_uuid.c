/* Saphira Memory - qrmem record identity.
 *
 * A record's `id` is a UUIDv4 and nothing else. It used to be a 32-bit integer
 * the caller invented, which produced three separate failures:
 *
 *  1. Two agents writing 1031 into their own screens believed they had named
 *     the same record. They had not: an integer id is only meaningful relative
 *     to the convention of whoever minted it, and nothing in the fabric stated
 *     that convention, so "the same id" was an unverifiable guess.
 *  2. Non-numeric ids were silently coerced to zero. A malformed call therefore
 *     looked like a successful write of an id nobody chose.
 *  3. `id` was doing two jobs at once - it was both a name and a label. Nothing
 *     in the surface distinguished "which record this is" from "a number the
 *     writer felt like using".
 *
 * The split this module exists to make explicit:
 *
 *     (screen, block, slot)  WHERE a record currently lives
 *     id (UUIDv4)            WHICH record it is
 *
 * Address moves; identity does not.
 *
 * Storage is 16 RAW BYTES, not the 36-character text. The text form exists only
 * at the MCP boundary: parsing in, rendering out. A fabric that stored the
 * hyphenated string would spend 36 bytes per record plus per-link to carry five
 * punctuation characters, and would make byte comparison of identity depend on
 * spelling.
 *
 * Strictness is deliberate and one-directional. Canonical form is lowercase,
 * 8-4-4-4-12, with the version nibble fixed at 4 and the variant nibble in
 * [89ab]. Uppercase is REFUSED rather than normalised: two spellings of one
 * identity is exactly the ambiguity being removed, and a silent normalisation is
 * a place that rule can be got wrong. Anything that is not canonical is
 * refused before any mutation, so a rejected call leaves nothing behind.
 *
 * This module needs no crypto library. It reads the kernel entropy pool for
 * minting, which is what getrandom(2) and /dev/urandom are; it does no key
 * derivation, signing or encryption, so there is nothing here for OpenSSL to do.
 */
#include "qrmem.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void set_err(char *err, size_t errlen, const char *fmt, ...) {
    va_list ap;
    if (!err || !errlen)
        return;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* The nil UUID: 16 zero bytes. It is not a valid v4 (version nibble is 0), so it
 * doubles as "no identity given" without needing a separate flag. Every record
 * that has been given an identity has a non-nil one, and an all-zero id is
 * always a bug rather than a valid value. */
int qrmem_uuid_is_nil(const qrmem_uuid_t *u) {
    size_t i;
    if (!u)
        return 1;
    for (i = 0; i < QRMEM_UUID_BYTES; i++)
        if (u->b[i] != 0u)
            return 0;
    return 1;
}

static int hex_digit(char c, unsigned char *out) {
    unsigned char v;
    /* Lowercase only. An uppercase 'A' is not accepted here even though it is a
     * hex digit, because accepting it would mean two canonical spellings. */
    if (c >= '0' && c <= '9')
        v = (unsigned char)(c - '0');
    else if (c >= 'a' && c <= 'f')
        v = (unsigned char)(c - 'a' + 10);
    else
        return -1;
    *out = v;
    return 0;
}

/* Strict canonical UUIDv4 parse.
 *
 * Returns 0 and fills *out, or -1 with err set. Rejects, in this order:
 * wrong length, a non-lowercase hex digit, a dash in the wrong place, a version
 * nibble that is not 4, and a variant nibble outside [89ab]. The version and
 * variant checks are what make this a UUIDv4 rather than a UUID-shaped token -
 * a nil UUID or a UUIDv1 with the same shape would otherwise pass.
 *
 * *out is left zeroed on every failure, so a caller that ignores the return
 * value cannot end up writing a half-filled identity. */
int qrmem_uuid_parse(const char *text, qrmem_uuid_t *out, char *err,
                     size_t errlen) {
    size_t i;
    if (!out)
        return -1;
    memset(out, 0, sizeof *out);
    if (!text || !text[0]) {
        set_err(err, errlen, "an id is required");
        return -1;
    }
    if (strlen(text) != QRMEM_UUID_TEXT_LEN) {
        set_err(err, errlen,
                "id must be canonical UUIDv4 text: 36 characters, "
                "xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx (got %zu); "
                "integers and labels are not ids",
                strlen(text));
        return -1;
    }
    /* Dash positions are exact: 8, 13, 18, 23 and nowhere else. A misplaced
     * dash is the most likely typo, and accepting it would mean two spellings
     * of one identity again. */
    {
        static const size_t kDash[4] = {8u, 13u, 18u, 23u};
        size_t d;
        for (d = 0; d < 4u; d++) {
            if (text[kDash[d]] != '-') {
                set_err(err, errlen,
                        "id must be canonical UUIDv4 text: expected '-' at "
                        "position %zu",
                        kDash[d]);
                return -1;
            }
        }
    }
    /* Collect the 32 hex digits in order, ignoring dashes, then pack them
     * pairwise. Dashes were checked above, so nothing here is skipped twice. */
    {
        /* One entry per hex CHARACTER: a UUIDv4 has 32 of them, which is
         * twice QRMEM_UUID_BYTES. Sizing this by QRMEM_UUID_BYTES overflowed it
         * by 16 bytes - the compiler caught it, and the count check below was
         * wrong in the same way. */
        unsigned char nib[QRMEM_UUID_TEXT_NIBBLES];
        size_t n = 0;
        for (i = 0; i < QRMEM_UUID_TEXT_LEN; i++) {
            unsigned char v;
            if (i == 8u || i == 13u || i == 18u || i == 23u)
                continue;
            if (hex_digit(text[i], &v) != 0) {
                set_err(err, errlen,
                        "id must be canonical UUIDv4 text: position %zu is not "
                        "a lowercase hex digit (uppercase is refused; ids are "
                        "canonical lowercase)",
                        i);
                return -1;
            }
            nib[n++] = v;
        }
        if (n != QRMEM_UUID_TEXT_NIBBLES) {
            set_err(err, errlen, "id has %zu hex digits, expected %u", n,
                    (unsigned)QRMEM_UUID_TEXT_NIBBLES);
            return -1;
        }
        for (i = 0; i < QRMEM_UUID_BYTES; i++)
            out->b[i] = (unsigned char)((nib[2u * i] << 4) | nib[2u * i + 1u]);
    }
    /* Version nibble: the first hex digit of the third group. */
    if (out->b[6] >> 4 != 4u) {
        set_err(err, errlen,
                "id is not a UUIDv4: version nibble is %u, must be 4",
                (unsigned)(out->b[6] >> 4));
        memset(out, 0, sizeof *out); /* a refusal leaves no usable identity */
        return -1;
    }
    /* Variant nibble: the first hex digit of the fourth group, which must be
     * 8, 9, a or b (10xx in binary). */
    {
        unsigned char v = (unsigned char)(out->b[8] & 0xC0u);
        if (v != 0x80u) {
            set_err(err, errlen,
                    "id is not a UUIDv4: variant nibble must be one of "
                    "8, 9, a, b");
            memset(out, 0, sizeof *out); /* a refusal leaves no usable identity */
            return -1;
        }
    }
    return 0;
}

/* Render canonical lowercase text. Always produces exactly 36 characters and a
 * NUL, so the buffer must be QRMEM_UUID_TEXT_LEN + 1. No partial output on
 * failure: a truncated UUID is worse than none. */
int qrmem_uuid_text(const qrmem_uuid_t *u, char *out, size_t cap) {
    static const char kHex[] = "0123456789abcdef";
    /* Text offset of each byte's high nibble in canonical form:
     * bytes 0-3 at 0, bytes 4-5 at 9, 6-7 at 14, 8-9 at 19, 10-15 at 24. */
    static const unsigned char kAt[QRMEM_UUID_BYTES] = {
        0,  2,  4,  6,  9,  11, 14, 16, 19, 21, 24, 26,
        28, 30, 32, 34
    };
    size_t i;
    if (!u || !out || cap < (size_t)QRMEM_UUID_TEXT_LEN + 1u) {
        if (out && cap > 0u)
            out[0] = '\0';
        set_err(NULL, 0, "%s", "");
        return -1;
    }
    out[8] = out[13] = out[18] = out[23] = '-';
    for (i = 0; i < QRMEM_UUID_BYTES; i++) {
        out[kAt[i]] = kHex[(u->b[i] >> 4) & 0x0Fu];
        out[kAt[i] + 1u] = kHex[u->b[i] & 0x0Fu];
    }
    out[QRMEM_UUID_TEXT_LEN] = '\0';
    return 0;
}

/* Fill `out` with kernel entropy. Returns 0, or -1 with err. */
static int entropy(unsigned char *out, size_t len, char *err, size_t errlen) {
    int fd;
    size_t got = 0;
    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        while (got < len) {
            ssize_t n = read(fd, out + got, len - got);
            if (n > 0) {
                got += (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            break;
        }
        close(fd);
    }
    if (got == len)
        return 0;
    /* No entropy source: refuse rather than mint a predictable identity. A
     * record whose id could be guessed is worse than a write that failed, and
     * the caller can retry. */
    set_err(err, errlen,
            "no kernel entropy available to mint a record id; pass an id "
            "explicitly or retry");
    memset(out, 0, len);
    return -1;
}

/* Mint a fresh UUIDv4.
 *
 * Version 4 means "random", so the only real requirement is that the 122
 * non-version, non-variant bits are unpredictable. The variant and version
 * nibbles are then forced, which is what makes the result a valid v4 rather than
 * 16 random bytes. */
int qrmem_uuid_mint(qrmem_uuid_t *out, char *err, size_t errlen) {
    if (!out)
        return -1;
    memset(out, 0, sizeof *out);
    if (entropy(out->b, QRMEM_UUID_BYTES, err, errlen) != 0)
        return -1;
    out->b[6] = (unsigned char)((out->b[6] & 0x0Fu) | 0x40u);
    out->b[8] = (unsigned char)((out->b[8] & 0x3Fu) | 0x80u);
    return 0;
}

int qrmem_uuid_equal(const qrmem_uuid_t *a, const qrmem_uuid_t *b) {
    size_t i;
    if (!a || !b)
        return 0;
    for (i = 0; i < QRMEM_UUID_BYTES; i++)
        if (a->b[i] != b->b[i])
            return 0;
    return 1;
}

/* A short, stable, non-cryptographic tag for one UUID, for logs and plane
 * captions. FNV-1a over the raw bytes: this identifies a UUID for a human, it
 * does not authenticate anything, and it must never be used to decide whether
 * two records are the same record. */
uint32_t qrmem_uuid_tag(const qrmem_uuid_t *u) {
    return u ? qrmem_fnv1a32(u->b, QRMEM_UUID_BYTES) : 0u;
}