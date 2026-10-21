/* Saphira Memory - qrmem tile fabric: shared types and module contracts.
 *
 * A tile fabric is a shared-memory aperture of N screens. One agent owns each
 * screen and is its only writer; every agent may read every screen live. This
 * header is the whole contract between the fabric daemon, the MCP spoke and
 * any process that attaches directly.
 *
 * Two rules govern everything below.
 *
 *  1. A tile belongs to one WRITER, but its contents are live to every READER.
 *     Ownership is enforced here, in the fabric, by agent id - never by file
 *     mode. That is what lets the service run as one user today and a
 *     different user tomorrow without a redesign.
 *
 *  2. Publication is write-last. A writer fills a cell and only then publishes
 *     it with a release store; a reader acquires the publication word before
 *     it reads anything the writer produced. The inherited rule and its
 *     rationale, from the JANUS2026 upstream ring (src/core/ring.c:18-26):
 *
 *       producer: write payload bytes
 *                 atomic_store_explicit(&write_seq, s, memory_order_release)
 *       consumer: atomic_load_explicit(&write_seq, memory_order_acquire)
 *                 read payload bytes
 *
 *     `volatile` is never used as an ordering primitive. It is not one.
 *
 * The fabric holds NO SQL, ever. Transport code must not reach the database
 * (src/db.h). Durable persistence is an explicit agent decision, not a side
 * effect of writing a cell.
 */
#ifndef QRMEM_H
#define QRMEM_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/* Aperture identity.
 *
 * MAJOR is a REFUSAL, not a label. Any change to the on-disk layout of the
 * aperture - field order, field width, where a name lives - must bump it,
 * because an attacher that misreads the layout does not fail cleanly. It reads
 * a name from the wrong offset and matches the wrong agent.
 *
 * That is not hypothetical. Adding a heartbeat field to the agent slot moved
 * `name` from offset 8 to offset 16 while leaving sizeof unchanged, and the ABI
 * stayed at 1. Old slots then had the heartbeat field reading the first eight
 * bytes of an agent name, which is a large number, so every slot looked
 * permanently fresh and the reclaim sweep reclaimed nothing. The layout check
 * that would have caught it was itself bypassed, because the version number
 * never moved.
 *
 * MINOR is for additive, position-independent change only: new TLV tags, new
 * fields a reader may treat as absent. */
#define QRMEM_MAGIC 0x524D5153u /* "SQMR" - Saphira qrmem */
#define QRMEM_ABI_MAJOR 5u
#define QRMEM_ABI_MINOR 0u
#define QRMEM_DEFAULT_NAME "saphira-qrmem"

/* ---------------------------------------------------------------------------
 * GEOMETRY: two distinct things, and conflating them is the mistake this file
 * exists to prevent.
 *
 *   THE CODE PLANE is the visual memory surface: QRMEM_PLANE_DIM square
 *   modules per screen, one bit each, divided into QRMEM_BLOCKS_PER_SCREEN
 *   coded blocks of QRMEM_BLOCK_DIM square. This is what a human looks at and
 *   what a phone can eventually scan.
 *
 *   THE RECORD is the stored data: QRMEM_CELL_BYTES of machine fields. It is
 *   NOT a coded block and is NOT a module. A block is 128x128 modules; a record
 *   is 280 bytes; a record is encoded INTO a block, alongside its neighbours.
 *
 *   QRMEM_SLOTS_PER_BLOCK records share one block. The arithmetic that fixes it:
 *
 *     block            128 x 128 = 16384 modules = 2048 bytes = 16384 bits
 *     record                              280 bytes =  2240 bits
 *     payload budget     73% of block      = 11960 bits
 *     K = 11960 / 2240                     = 5 records per block
 *
 *   The other 27% is structure: finder patterns, timing, error correction and
 *   framing. That is what makes a block a CODE rather than a picture of bytes.
 *
 *   Modules are ONE BIT, and that is load-bearing rather than a space saving.
 *   A block of 2048 bytes holds five records at ~73% occupancy, which is dense
 *   and legible. Modules as bytes would make a block 16384 bytes holding the
 *   same five records at ~9%, which is the sparsity problem restated.
 *
 *   RAM, whole aperture, all eight screens: records 175 KB, plane 256 KB,
 *   index 32 KB, header 5 KB = about 468 KB. The previous 128x128-cell layout
 *   spent 35 MB, so this is 77x smaller while making the surface viewable.
 * ------------------------------------------------------------------------- */
/* One writer per screen, whichever host it is on. */
#define QRMEM_SCREENS 16u

#define QRMEM_PLANE_DIM 4096u
/* Logical blocks and visual viewports are deliberately different.  A block is
 * an addressing group of five records; a viewport is one real QR Code. */
#define QRMEM_BLOCK_DIM 0u
#define QRMEM_BLOCKS_PER_ROW 4u
#define QRMEM_BLOCKS_PER_SCREEN 16u
#define QRMEM_SLOTS_PER_BLOCK 5u
#define QRMEM_RECORDS_PER_SCREEN \
    (QRMEM_BLOCKS_PER_SCREEN * QRMEM_SLOTS_PER_BLOCK)
#define QRMEM_TOTAL_RECORDS (QRMEM_SCREENS * QRMEM_RECORDS_PER_SCREEN)

/* A plane row is QRMEM_PLANE_DIM bits, packed 8 to a byte. */
#define QRMEM_PLANE_ROW_BYTES (QRMEM_PLANE_DIM / 8u)
#define QRMEM_PLANE_SCREEN_BYTES (QRMEM_PLANE_DIM * QRMEM_PLANE_ROW_BYTES)
#define QRMEM_PLANE_COUNT 3u
#define QRMEM_PLANE_QR 0u
#define QRMEM_PLANE_OCCUPANCY 1u
#define QRMEM_PLANE_CHANGE 2u
#define QRMEM_PLANES_SCREEN_BYTES (QRMEM_PLANE_COUNT * QRMEM_PLANE_SCREEN_BYTES)

/* Record identity is a UUIDv4: 16 raw bytes in storage, 36 characters of
 * canonical lowercase text at the MCP boundary. See qrmem_uuid_t. */
#define QRMEM_UUID_BYTES 16u
#define QRMEM_UUID_TEXT_LEN 36u
/* Canonical text carries 32 hex characters: two per stored byte. */
#define QRMEM_UUID_TEXT_NIBBLES (QRMEM_UUID_BYTES * 2u)

/* Record identity: a UUIDv4, stored as 16 RAW BYTES.
 *
 * This was a 32-bit integer the caller invented, and that was two jobs in one
 * field: a record's name and a writer's label. It produced real damage. Two
 * agents on different screens both wrote 1031 and reasonably concluded they had
 * named the same record; non-numeric ids were silently coerced to zero, so a
 * malformed call looked like a successful write of an id nobody chose; and
 * nothing on the surface distinguished which record a value named from where it
 * lived. The split is now explicit:
 *
 *     (screen, block, slot)  WHERE a record currently lives
 *     id (UUIDv4)            WHICH record it is
 *
 * Address moves with a qrmem_move; identity does not. Storing the raw bytes
 * rather than the 36-character text keeps five punctuation characters out of
 * every record and every link, and makes byte comparison of identity a
 * comparison of identity rather than of spelling. The text form exists only at
 * the MCP boundary: parse in, render out.
 *
 * The nil UUID - sixteen zero bytes - is not a valid v4 (its version nibble is
 * 0), so it doubles as "no identity given" without a separate flag. */
typedef struct {
    unsigned char b[QRMEM_UUID_BYTES];
} qrmem_uuid_t;

#define QRMEM_CELL_LINKS 4u
#define QRMEM_CELL_BODY 240u
/* Bounded inverted index, one table per screen, after the plane. */
#define QRMEM_INDEX_ENTRIES 512u

/* The control region occupies the first pages: a fixed header, then one
 * two-cache-line control block per screen. Cells start after it. */
#define QRMEM_HDR_BYTES 4096u
#define QRMEM_SCREEN_CTL_BYTES 256u
#define QRMEM_CTL_REGION_BYTES \
    (QRMEM_HDR_BYTES + QRMEM_SCREENS * QRMEM_SCREEN_CTL_BYTES)
#define QRMEM_CELLS_REGION_OFF 8192u

/* Byte-order tags. Written once by the creator; every attacher compares
 * against its own native order and refuses on mismatch. A single shared image
 * with mismatched participant byte orders is out of scope and is refused at
 * attach rather than half supported. */
#define QRMEM_ORDER_LE 0x0102u
#define QRMEM_ORDER_BE 0x0201u

/* Publication ordering, in one place so the test suite can weaken it.
 *
 * QRMEM_WEAKEN_RELEASE is a TEST-ONLY switch. tests/test_qrmem.sh builds with it
 * and asserts the result FAILS. A gate that has never been seen to fail is not
 * evidence, it is decoration. Never define this in a production build.
 *
 * It deliberately weakens QRMEM_SEQLOCK_ORDER, and that choice is itself a
 * finding worth recording. The switch used to weaken the `state` store, and
 * after the cell was made atomic that build turned out to be HARMLESS: the
 * sequence lock, not the state word, is what makes a read correct, so a gate
 * aimed at `state` was testing a switch that no longer mattered and would have
 * passed forever while proving nothing. The load-bearing edges are:
 *
 *   writer  version -> even  (release)  ... read by the reader's first sample
 *   writer  version -> odd   (acq_rel)  ... keeps field stores above it
 *   reader  field loads, then an acquire fence, then the closing sample
 *
 * so that is what the weakened build removes. */
#ifdef QRMEM_WEAKEN_RELEASE
#define QRMEM_PUBLISH_ORDER memory_order_relaxed
#define QRMEM_DRAIN_ORDER memory_order_relaxed
#define QRMEM_SEQLOCK_ORDER memory_order_relaxed
#else
#define QRMEM_PUBLISH_ORDER memory_order_release
#define QRMEM_DRAIN_ORDER memory_order_acquire
#define QRMEM_SEQLOCK_ORDER memory_order_release
#endif

/* Cell publication states. The state word is the publication point. */
#define QRMEM_CELL_FREE 0u /* never written, or reclaimed */
#define QRMEM_CELL_LIVE 1u /* published; body and links are readable */
#define QRMEM_CELL_TOMB 2u /* superseded; body retained until reuse */

/* Cell record types. */
#define QRMEM_CT_EMPTY 0u
#define QRMEM_CT_WORD 1u /* id, text or tokens */
#define QRMEM_CT_IDEA 2u /* subject, tokens, status, links */
#define QRMEM_CT_FACT 3u /* subject, relation, object, status, source */
#define QRMEM_CT_PTR 4u  /* screen, x, y, generation */
#define QRMEM_CT_TOMB 5u

/* Body TLV tags. A new field is a new TLV, never a new offset - the
 * inherited discipline from the JANUS2026 upstream wire. `bytes` counts its
 * own 4-byte header. */
#define QRMEM_TLV_HDR 4u

/* Caller TEXT capacity: what one text payload may occupy inside a cell,
 * including its own 4-byte TLV header.
 *
 * Three things come out of the 240-byte body:
 *   - 12 bytes for the always-present publication timestamp: 4 header + u64
 *   - 4 bytes for the caller's own text TLV header
 *   - the rest is the text itself
 *
 * The middle term is the one that is easy to miss, and it was missed: deriving
 * the budget as body-minus-timestamp gives 228, which the codec then refuses
 * with "no room for the publication timestamp" - a limit the surface states and
 * the store does not honour. A quoted number that disagrees with the encoder is
 * worse than no number, so it is derived from all three terms instead.
 *
 * Caller payloads with other shapes (tokens, links, the index key) each consume
 * their own header too, so a record carrying several fields has less text room
 * than this. That is inherent to a fixed-size cell and is the same bargain the
 * body limit always was.
 */
#define QRMEM_CELL_CALLER_BYTES \
    (QRMEM_CELL_BODY - (QRMEM_TLV_HDR + 8u) - QRMEM_TLV_HDR)
#define QRMEM_TLV_TEXT 1u    /* utf-8, not NUL-terminated */
#define QRMEM_TLV_TOKENS 2u  /* u32 array, token ids */
#define QRMEM_TLV_LINK 3u    /* 16 raw bytes per entry, record UUIDs */
#define QRMEM_TLV_STATUS 4u  /* u8 enum */
#define QRMEM_TLV_SUBJECT 5u /* u32 */
#define QRMEM_TLV_RELATION 6u
#define QRMEM_TLV_OBJECT 7u
#define QRMEM_TLV_SOURCE 8u
#define QRMEM_TLV_SCREEN 9u /* u8 */
/* Where a record sits. ABI 3 addresses a record by its place in the code
 * plane's structure - which block, which slot in that block - and NOT by plane
 * x/y, which are a property of how the block is drawn rather than of where the
 * record lives. The names follow that: BLOCK/SLOT. The numeric tags are
 * unchanged, so an older peer reading a 3-fabric sees the same numbers it
 * always did rather than mistaking them for coordinates. */
#define QRMEM_TLV_BLOCK 10u /* u32, which 128x128 block of the screen */
#define QRMEM_TLV_SLOT 11u  /* u32, which of the records inside it */
#define QRMEM_TLV_GEN 12u   /* u32 */
/* 16 raw bytes, not text and not a u32: the successor is identified by UUID
 * like every other record, so it is stored the same way. A u32 successor was
 * only ever as meaningful as whatever numbering convention produced it. */
#define QRMEM_TLV_SUCCESSOR 13u /* 16 raw bytes, UUID of the successor */
/* The lookup key this record was published under, as UTF-8 text.
 *
 * This exists because the index is DERIVED state. The index table itself lives
 * in the aperture, which a reboot empties, while the key is the only durable
 * evidence that a record was ever meant to be findable. Without this tag a
 * restored record came back with its content and its identity but silently lost
 * its discovery handle: still readable by coordinate, invisible to qrmem_index.
 *
 * So the key is persisted WITH the record and the table is rebuilt from it on
 * restore, rather than persisting a second independently mutable structure that
 * could disagree with the records it points at. One key per record, matching the
 * one-key-per-write rule the index already enforces. */
#define QRMEM_TLV_INDEX_KEY 14u /* utf-8; read with qrmem_rec_get_text_tag */

/* When this record was published, in CLOCK_REALTIME nanoseconds.
 *
 * FRESHNESS, NOT AUTHORSHIP. This answers exactly one question - "how old is
 * this record?" - and deliberately does NOT record who wrote it. Lease identity
 * is ephemeral by design, and putting it on a record would invite callers to
 * treat it as durable provenance, which is the exact mistake this fabric spends
 * its fencing machinery preventing. Durable attribution belongs to the record's
 * own UUID plus whatever evidence the caller keeps elsewhere.
 *
 * REALTIME, NOT MONOTONIC. A monotonic stamp is unanswerable after exactly the
 * event this fabric now handles routinely: a daemon restart wipes /dev/shm and
 * resets the monotonic clock to zero, so every restored record would report an
 * unknown age. The question is "how old is this after reboot?", and only a wall
 * clock survives a reboot to answer it. Do not describe this as a monotonic
 * timestamp anywhere; it is wall-clock time, on purpose.
 *
 * The cost is that this clock is not trustworthy in the way authority is: NTP
 * corrections and manual changes can move it. So it is ADVISORY. A caller who
 * needs ordering rather than freshness should use the UUID and the screen
 * generation, neither of which depends on any clock.
 *
 * ALWAYS PRESENT ON NEW RECORDS. The write path reserves these bytes before
 * accepting any caller TLVs, so a near-full record cannot silently lose its
 * freshness field. A record with no timestamp is therefore a LEGACY record,
 * written by a build predating this tag - which is a fact an agent can act on,
 * unlike "sometimes there is one".
 *
 * In the BODY rather than a cell field on purpose: no ABI change, the integrity
 * witness already covers it, and the durable snapshot already copies the body
 * byte for byte, so timestamps survive a restart with no extra work.
 */
#define QRMEM_TLV_WRITTEN_NS 15u /* u64, CLOCK_REALTIME ns */

#define QRMEM_STATUS_UNKNOWN 0u
#define QRMEM_STATUS_WITNESSED 1u
#define QRMEM_STATUS_SUPPORTED 2u
#define QRMEM_STATUS_REFUTED 3u

#define QRMEM_AGENT_MAX 60u
/* Agent names are bounded because the registry lives inside the header page:
 * a hash-derived slot would be shorter still, and it was tried and rejected.
 * Deriving a slot from a hash of the name means two different identities that
 * collide become ONE identity, and the second agent then silently passes the
 * "already mine" idempotence check and writes another agent's tile. Names are
 * therefore matched exactly and assigned a slot of their own. */
#define QRMEM_AGENT_NAME_MAX 40u
/* Longest authority hostname kept for presence, including NUL. Descriptive
 * only: never identity-bearing, never fenced. */
#define QRMEM_AUTHORITY_HOST_MAX 64u
/* Where a lease comes from, as known by the authority that granted it.
 * UNKNOWN means no origin was recorded (older aperture, or a slot that was
 * never claimed since this field existed). LOCAL means the daemon granted the
 * lease itself over its control socket. A future remote carrier adds kinds
 * here whose value is verified by the authority (TLS client identity handed to
 * a local proxy) - never a string supplied by the client being identified. */
#define QRMEM_ORIGIN_UNKNOWN 0u
#define QRMEM_ORIGIN_LOCAL 1u
/* Project labels are descriptive metadata, never authority. A screen carries
 * at most one, written by the claiming agent, readable by everyone. Fixed
 * size so no registry is needed to save bytes: overlength is refused, never
 * truncated. Immutable once the screen holds its first published record. */
#define QRMEM_PROJECT_MAX 64u

/* Screen control block. Two cache lines, one writer.
 *
 * Ownership is a fenced triple, never a bare slot number:
 * (owner_authority_gen, owner, owner_agent_gen). A slot reused under a new
 * allocation carries a new agent generation, so it cannot inherit a screen
 * claimed by whoever held the number before it. A daemon restart bumps the
 * authority generation, which retires every previous lease by definition.
 * A stale slot number alone can never grant authority; every rule below
 * compares all three, or it is not a rule.
 *
 * project[] is descriptive metadata, never authority: what this screen's
 * page belongs to, readable by everyone, written by the claiming agent.
 * Immutable once the screen holds its first published record; while empty,
 * correcting it is harmless. Overlength is refused, never truncated. It
 * lives here rather than in a registry so no second structure can drift
 * out of agreement with ownership. Written before owner is published, so
 * any reader that sees a nonzero owner also sees the project. */
typedef struct {
    _Atomic uint64_t generation;   /* bumped once per completed operation */
    _Atomic uint64_t write_count;  /* total published cells, monotonic */
    _Atomic uint32_t owner;        /* 0 = unclaimed, else 1+agent slot */
    _Atomic uint32_t owner_era;    /* fabric era the claim was made in */
    _Atomic uint32_t owner_authority_gen; /* daemon incarnation at claim */
    _Atomic uint32_t owner_agent_gen;     /* slot allocation count at claim */
    _Atomic uint64_t heartbeat_ns; /* writer liveness, CLOCK_MONOTONIC */
    _Atomic uint32_t notify;       /* doorbell counter, read with generation */
    _Atomic uint32_t project_len;  /* bytes used of project[], 0 = unset */
    char project[QRMEM_PROJECT_MAX]; /* UTF-8, not NUL-terminated */
    /* Claim serialisation. Two agents that see one free screen at the same
     * moment both start writing metadata before either publishes an owner;
     * without a lock the loser's project label and triple can outlive its
     * failed compare-and-swap, leaving a screen owned by one agent and
     * labelled with another. Claiming is rare, so a spin lock costs nothing
     * that matters and removes that whole class of torn state. */
    _Atomic uint32_t claim_lock;  /* 0 = free, else held; not an authority */
    /* Blue-plane baseline.  A CHANGE bit means this screen's tile was written
     * after this declared screen generation; it never means merely "recent". */
    _Atomic uint64_t baseline_generation;
    /* Padded to two cache lines so two screens never share one. The count is
     * derived from the fields above, not guessed: a wrong pad silently cost a
     * false-sharing bug that only shows up under load. The aperture refuses to
     * open if it does not come out at exactly QRMEM_SCREEN_CTL_BYTES. Fields
     * above total 116 bytes; three 32-bit pads make 128 with no reliance on
     * implicit tail padding. */
    uint32_t pad[(QRMEM_SCREEN_CTL_BYTES - 128u) / 4u];
} qrmem_screen_ctl_t;

/* Aperture header. Page zero. Native-width atomics, never byte-swapped. */
typedef struct {
    uint32_t magic;
    uint16_t abi_major;
    uint16_t abi_minor;
    uint32_t hdr_bytes;
    uint16_t byte_order;
    uint16_t reserved0;
    uint32_t screen_count;
    uint32_t plane_dim;
    uint32_t block_dim;
    uint32_t slots_per_block;
    uint32_t plane_count; /* named one-bit planes per screen */
    uint64_t total_bytes;
    _Atomic uint64_t fabric_epoch; /* bumped by the creator on restart */
    _Atomic uint64_t heartbeat_seq; /* participant liveness */
    _Atomic uint32_t handle_era;    /* ABA boundary: era + sequence */
    _Atomic uint32_t handle_seq;
    _Atomic uint32_t agent_count;   /* slots currently claimed */
    /* Authority incarnation. Bumped by the daemon exactly once per successful
     * bind, so a daemon restart IS a lease boundary: every lease, screen
     * claim and client handle from a previous incarnation is stale by
     * definition, regardless of what its counters say. Replaces reserved1
     * and reserved2 byte-for-byte, so the agent array below does not move. */
    _Atomic uint64_t authority_gen;
    /* FABRIC IDENTITY: minted once, when this aperture is created, and never
     * changed. A qrmem screen number is meaningless outside the fabric that
     * produced it, so a coordinate that leaves this process has to carry the
     * fabric it came from. The qualified address is (fabric_id, screen) and
     * only that pair is identity-bearing; host, aperture path and project are
     * descriptive and may all change.
     *
     * Deliberately NOT derived from anything: not the hostname, not the uid,
     * not the aperture pathname, not a hash of screen contents. All four were
     * tempting and all four are wrong. The aperture pathname is IDENTICAL on
     * three different machines, so deriving from it would give three fabrics
     * the same identity and make "which fabric is this" unanswerable at exactly
     * the moment it matters. Hostname is descriptive and renameable, uid is
     * shared by every process on the host, and screen contents change as
     * people write. An identity that moves when the thing it identifies moves
     * is not an identity. So it is a random UUIDv4 from getrandom(2), which is
     * the only source that is actually independent of all of the above.
     *
     * DELIBERATELY OUTSIDE THE SNAPSHOT PAYLOAD. The snapshot holds record
     * CONTENT and is designed to be copied; the fabric identity is who this
     * fabric is. If the id travelled in the snapshot, copying a snapshot to
     * another machine would clone the identity and leave two simultaneously
     * live fabrics both claiming to be the same namespace - and every
     * qualified address written before the copy would then resolve, wrongly, to
     * the copy. That is a namespace collision manufactured by a backup, which
     * is about the worst place to create one.
     *
     * Consequence, stated plainly: a fabric whose /dev/shm segment is lost has
     * a NEW identity, and historical references to the old one stop resolving.
     * That is the honest outcome - the old fabric genuinely no longer exists.
     * Migrating a fabric is therefore an explicit operator operation, never an
     * accidental consequence of copying a snapshot. */
    qrmem_uuid_t fabric_id;
    /* The agent array below starts 8-byte aligned (authority_gen ends at a
     * multiple of 8): its entries hold a _Atomic uint64_t, and an array of
     * misaligned 64-bit atomics is not merely untidy - it is a lock-free
     * assumption this header would be making on the compiler's behalf. */
    /* Agent registry, in the header's own padding. `in_use` is the
     * publication word and is written LAST, so a reader that sees a slot in
     * use also sees its name. */
    struct {
        _Atomic uint32_t in_use;
        /* When this slot was first LEASED in this allocation.
         *
         * It replaces `era`, which was written on allocation and never read by
         * anything - a dead field that looked load-bearing. Presence needs to
         * answer "how long has this agent been here", and reusing a field
         * rather than growing the entry keeps the 64-byte stride that the header
         * padding arithmetic depends on. Growing it would mean shrinking
         * QRMEM_AGENT_MAX, and 60 is a product decision, not a layout detail.
         *
         * CLOCK_MONOTONIC seconds since this slot's lease first went nonzero,
         * so it is meaningful only as a DIFFERENCE against the reader's own
         * monotonic clock on the same machine - exactly the local-host caveat
         * that already applies to last_seen_ns. 0 means never leased. */
        _Atomic uint32_t connected_since;
        /* THE LEASE. Count of live control connections this agent holds.
         *
         * A nonzero lease means the process is here NOW, because the kernel
         * closes the descriptor when it exits or crashes - so the daemon learns
         * about death from the operating system rather than from a timeout
         * guessing at it. Silence is not death: a connected agent may sit idle
         * for hours and keeps its screen for every one of them.
         *
         * Zero does not mean dead, only unleased. A slot can be unleased
         * because its owner has not connected yet, which is why the reclaim
         * sweep still consults last_seen_ns as a grace period rather than
         * freeing every unleased slot on sight. */
        _Atomic uint32_t lease_hold;
        /* Allocation generation. Incremented on EVERY allocation of this
         * slot, fresh or name-matched. Two sequential occupants of one
         * slot therefore never share a generation, even inside one
         * handle era. Stored into screen ownership at claim time, so a
         * reused slot number cannot inherit a previous occupant's tile:
         * the triple (authority_gen, slot, alloc_gen) must match exactly
         * or it is not your screen. */
        _Atomic uint32_t alloc_gen;
        /* Diagnostic only: when this agent was last seen. It is no longer the
         * authority on liveness - lease_hold is - but it is how the sweep
         * decides that an unleased slot is abandoned rather than young, and it
         * is worth showing an operator.
         *
         * CLOCK_MONOTONIC, local-host only: every attacher on one machine
         * shares a monotonic clock, which is the whole basis of the comparison.
         * If the remote leg lands this becomes invalid across hosts and MUST be
         * replaced by the authority's own arrival timestamps - the trap JANUS
         * STAGE0-SPEC rule 7 records, that an initiator's absolute monotonic
         * nanoseconds mean nothing to another participant. Remote clients will
         * need an explicit lease and heartbeat, because a network failure does
         * not hand you the same local certainty. */
        _Atomic uint64_t last_seen_ns;
        char name[QRMEM_AGENT_NAME_MAX];
    } agents[QRMEM_AGENT_MAX];
    /* Authority-known origin, for presence.
     *
     * authority_host is the daemon's own hostname, written by the daemon at
     * bind. It answers "which machine's authority granted these leases" and is
     * what lets two same-labelled agents on two hosts be told apart once a
     * remote leg exists. It is descriptive: a host can be renamed, so it never
     * participates in fencing or identity.
     *
     * agent_origin_kind[i] says where slot i's lease comes from, as recorded by
     * whoever granted it. Every claim path in this build is a local control
     * socket, so the aperture layer stamps LOCAL itself; there is no client
     * string to trust and none is accepted. A remote proxy will stamp its own
     * kind with an identity it verified, through a new claim path - not by
     * passing a hostname through the existing one.
     *
     * Both live in header padding, so the agent array does not move and the
     * header stays exactly 4096 bytes. */
    char authority_host[QRMEM_AUTHORITY_HOST_MAX];
    uint8_t agent_origin_kind[QRMEM_AGENT_MAX];
    /* fabric_id consumed 16 of the previous slack, keeping the agent
     * array 8-byte aligned and the header at 4096 bytes. Origin consumed a
     * further 124; what remains is still padding, not a field. */
    uint8_t pad[QRMEM_HDR_BYTES - 104u - QRMEM_AGENT_MAX * 64u -
                QRMEM_AUTHORITY_HOST_MAX - QRMEM_AGENT_MAX];
} qrmem_hdr_t;

/* One cell. Fixed size, so a reader never allocates to inspect memory.
 *
 * Every field is atomic, and `version` is a sequence lock. Both were added
 * because the first version of this file was wrong in a way that only showed up
 * under load, and the wrongness was NOT a missing release/acquire pair:
 *
 *   - A writer unpublished with store(state=FREE, release) and then began
 *     rewriting fields. A reader that had already incremented `readers` and
 *     loaded state could still read the OLD LIVE, because a release store does
 *     not force the store to become visible to another core. The reader then
 *     read fields the writer was rewriting underneath it. Observed directly:
 *     a record whose id came from one publish and whose body came from another,
 *     roughly 3 times per 200k writes.
 *
 * The fix has two halves, and both are load-bearing:
 *
 *   1. Every field is atomic, so a concurrent read is DEFINED rather than a data
 *      race. No UB, and ThreadSanitizer has nothing to complain about.
 *   2. `version` is odd while a write is in progress. A reader samples it
 *      before and after its field reads and rejects the record if it moved. This
 *      is what actually closes the window: without it, "no UB" would still mean
 *      "a plausible mix of two publishes".
 *
 * The `readers` drain stays because it is a cheap optimisation that makes the
 * common case conflict-free, so retries are rare. It is not what makes the read
 * correct.
 */
typedef struct {
    _Atomic uint32_t state;   /* publication word */
    _Atomic uint32_t readers; /* readers currently inside this cell */
    _Atomic uint32_t version; /* sequence lock: odd means a write is in flight */
    _Atomic uint16_t type;
    _Atomic uint16_t body_len;
    /* Identity is 16 raw bytes, not text and not a u32. Written as a byte
     * array rather than a struct so the atomic publication of 16 bytes is a
     * fixed-size copy with no padding to reason about. */
    _Atomic unsigned char id[QRMEM_UUID_BYTES];
    _Atomic unsigned char links[QRMEM_CELL_LINKS][QRMEM_UUID_BYTES];
    _Atomic uint16_t n_links;
    _Atomic uint16_t generation;
    _Atomic uint32_t witness; /* FNV-1a over the record, NOT a CRC-32 */
    _Atomic unsigned char body[QRMEM_CELL_BODY];
} qrmem_cell_t;

/* Record stride on the shared surface.
 *
 * This is deliberately NOT sizeof(qrmem_cell_t). The struct is 284 bytes and the
 * stride is 288, because the layout wants records on a multiple of 8. Indexing
 * a `qrmem_cell_t *` with `[]` advances by sizeof, so every record after the
 * first was addressed 4 bytes early: adjacent records overlapped, a record read
 * back as a corrupted neighbour, and the code plane faithfully drew the wrong
 * bytes. Address the region through qrmem_cell_at, which does the stride in
 * bytes, and never index ap->cells directly. */
#define QRMEM_CELL_BYTES 344u

/* The stride and the struct have to agree about alignment, or the record region
 * would be interpreted differently by different compilers on the same bytes. */
_Static_assert(QRMEM_CELL_BYTES >= sizeof(qrmem_cell_t),
               "record stride must not be smaller than the struct");
_Static_assert(QRMEM_CELL_BYTES % _Alignof(qrmem_cell_t) == 0u,
               "record stride must keep the struct's alignment");
/* Identity has to survive a round trip byte-for-byte, so the raw UUID must be
 * addressable as bytes and must not be widened by alignment. */
_Static_assert(sizeof(((qrmem_uuid_t *)0)->b) == QRMEM_UUID_BYTES,
               "a UUID is 16 raw bytes");
/* id 4 -> 16 and links 16 -> 64 together add 60 bytes, so the record grew from
 * 284 to 344 and the stride from 288 to 344. Five records must still fit one
 * block's payload frame; that is checked, not assumed - see the plane gate. */
_Static_assert(sizeof(qrmem_cell_t) == 344u,
               "the struct changed size; re-derive QRMEM_CELL_BYTES and re-run "
               "the aperture gate before trusting any offset");

/* Aperture layout, in order. Every region is page-aligned so a reader can
 * map any one of them alone, and every region is self-describing enough that a
 * wrong offset shows up as a refusal rather than as garbage. */
#define QRMEM_RECORDS_REGION_OFF 8192u
#define QRMEM_RECORDS_BYTES \
    ((size_t)QRMEM_SCREENS * QRMEM_RECORDS_PER_SCREEN * QRMEM_CELL_BYTES)
#define QRMEM_PLANE_REGION_OFF \
    (QRMEM_RECORDS_REGION_OFF + \
     ((QRMEM_RECORDS_BYTES + 4095u) & ~(size_t)4095u))
#define QRMEM_INDEX_REGION_OFF \
    (QRMEM_PLANE_REGION_OFF + \
     (size_t)QRMEM_SCREENS * QRMEM_PLANES_SCREEN_BYTES)
#define QRMEM_APERTURE_BYTES \
    (QRMEM_INDEX_REGION_OFF + \
     (size_t)QRMEM_SCREENS * QRMEM_INDEX_ENTRIES * QRMEM_INDEX_ENT_BYTES)

/* One index entry: a key hash and the cell it points at. The key is written
 * AFTER the cell it names, so a reader that follows an entry always finds the
 * cell published. key_hash 0 is reserved for "empty slot". */
typedef struct {
    _Atomic uint32_t key_hash;
    _Atomic uint32_t cell_index; /* record index: block * SLOTS + slot */
} qrmem_index_ent_t;

#define QRMEM_INDEX_ENT_BYTES ((sizeof(qrmem_index_ent_t) + 7u) & ~7u)

/* An attached aperture. self_agent is the 1+ slot of the calling identity, or
 * 0 when the process has not claimed one. */
typedef struct {
    unsigned char *base;
    size_t bytes;
    int fd;      /* shm fd, -1 once unmapped */
    int creator; /* 1 if this process created the segment */
    qrmem_hdr_t *hdr;
    qrmem_screen_ctl_t *screens;
    qrmem_cell_t *cells;   /* the record store, QRMEM_RECORDS_PER_SCREEN each */
    _Atomic unsigned char *plane; /* the code plane, one bit per module */
    qrmem_index_ent_t *index;
    uint32_t self_agent;
    char path[512];
} qrmem_ap_t;

/* Aperture naming.
 *
 * shm_open takes a NAME, not a path: it prepends /dev/shm itself and rejects
 * anything with more than one slash. So the name here is "/saphira-qrmem-1000"
 * and the filesystem path is "/dev/shm/saphira-qrmem-1000". Passing the full
 * path to shm_open yields EINVAL and looks like a permissions problem, which is
 * a wasted afternoon.
 *
 * qrmem_ap_path_of renders the name as the path an operator will recognise. */
#define QRMEM_SHM_DIR "/dev/shm"
void qrmem_ap_path_of(const char *name, char *out, size_t out_len);
/* Reduce a user-supplied --aperture value to a shm name: a full /dev/shm path
 * is stripped, anything else must already be a bare name. Returns 0 or -1. */
int qrmem_ap_name_of(const char *given, char *out, size_t out_len);

/* Aperture lifecycle. `err` never contains a secret; there are none here. */
int qrmem_aperture_create(qrmem_ap_t *ap, const char *path, char *err,
                          size_t errlen);
int qrmem_aperture_attach(qrmem_ap_t *ap, const char *path, char *err,
                          size_t errlen);
int qrmem_aperture_detach(qrmem_ap_t *ap);
void qrmem_aperture_unlink(const char *path);
/* Bump the epoch. Creator-only, on every daemon start, so anything in flight
 * from a previous incarnation is provably stale rather than mysteriously wrong. */
void qrmem_aperture_bump_epoch(qrmem_ap_t *ap);

/* Fenced identity. A slot number alone is never authority: every rule that
 * grants, checks or releases write access compares all three fields, or it
 * is not a rule. (authority_gen, slot, agent_gen) names exactly one
 * allocation of one slot in one daemon incarnation. A reused slot carries a
 * new agent_gen; a restarted daemon carries a new authority_gen. Either
 * change retires every previous triple by definition. */
typedef struct {
    uint64_t authority_gen;
    uint32_t slot;      /* 1-based registry slot, 0 = none */
    uint32_t agent_gen; /* alloc_gen at the time this identity was issued */
} qrmem_id_t;

/* Claim a screen for an agent. First come; a claim by the current owner is
 * idempotent iff the full triple matches. 0 ok, -1 refused with err.
 * project is descriptive metadata (may be NULL/empty); it is stored only
 * when the screen holds no published records yet. */
int qrmem_screen_claim(qrmem_ap_t *ap, uint32_t screen, qrmem_id_t id,
                       const char *project, char *err, size_t errlen);
int qrmem_screen_release(qrmem_ap_t *ap, uint32_t screen, qrmem_id_t id,
                         char *err, size_t errlen);
/* TRUE when `id` may write `screen`. Readers never ask. */
int qrmem_screen_writable(const qrmem_ap_t *ap, uint32_t screen,
                          qrmem_id_t id);
/* The single-writer gate every mutating tile op calls first. */
int qrmem_require_owner(const qrmem_ap_t *ap, uint32_t screen, qrmem_id_t id,
                        char *err, size_t errlen);

/* ---- Operator recovery (src/qrmem_recover.c) --------------------------------
 *
 * The only write path that touches durable metadata directly, and deliberately
 * NOT reachable from the MCP surface - running it requires the same access as
 * starting the fabric.
 *
 * A page's project label is immutable once it has published records. That rule is
 * one-directional on purpose and it stays that way for agents: a label other
 * agents may already have found is not a writer's private scratch. But holding
 * "the right default" and "the only possible thing" at once was a mistake, because
 * a real defect damaged a label and there was no way to fix it that did not
 * involve deleting records.
 *
 * So this is the operator path, and it differs from the agent path in what it
 * may do and in what it must not:
 *
 *   - It NEVER touches a record. Metadata-only by construction: the signature
 *     takes a screen and a string, and nothing here can address a cell.
 *   - It requires the screen to be UNOWNED. Repairing a label out from under a
 *     live writer would change what the screen means to a process actively using
 *     it. This check IS enforced, unlike the published-records rule it omits.
 *   - It refuses to CLEAR a label. An unlabelled page cannot be found by
 *     project, which is an orphan; that is a repair request to name the label it
 *     should have, not a way to delete one.
 *   - It logs every repair: screen, old label, new label, write count and the
 *     wall-clock time. A silent metadata edit on a shared surface is exactly the
 *     class of change nobody can reconstruct afterwards.
 *
 * Returns 0 on repair, -1 with err otherwise. The read-only inspector is the
 * triage half, so an operator can see a screen's metadata before deciding. */
/* dry_run: validate and report, write nothing. Runs every check a real repair
 * runs, so its output is a faithful preview. */
int qrmem_recover_project(qrmem_ap_t *ap, uint32_t screen, const char *project,
                          const char *log_path, int dry_run, char *err,
                          size_t errlen);
int qrmem_recover_inspect(const qrmem_ap_t *ap, uint32_t screen,
                          char *project_out, size_t project_outlen,
                          uint64_t *writes_out, uint32_t *owner_out,
                          uint64_t *generation_out, uint64_t *index_used_out,
                          char *err, size_t errlen);

/* ---- Reboot survival (src/qrmem_persist.c) -------------------------------
 *
 * /dev/shm is memory, not storage, so a reboot empties the fabric. Page CONTENT
 * is the agent's thinking and must survive; AUTHORITY is a statement about which
 * live process may write and must not.
 *
 * So a snapshot restores the latest live records and their project labels, and
 * restores NO screen owner, NO lease, and no authority generation. Continuity
 * without resurrection: the same page, new authority, no dead writers. A format
 * that had a field for an owner could eventually be asked to restore one, so the
 * format has no way to express it.
 *
 * Returns 1 if anything was restored, 0 if there was nothing to restore, and -1
 * if a snapshot exists and is unusable - which is deliberately distinct from
 * "empty", because a corrupt snapshot is something an operator needs told. */
int qrmem_snapshot_save(const qrmem_ap_t *ap, const char *path, char *err,
                        size_t errlen);
int qrmem_snapshot_load(qrmem_ap_t *ap, const char *path, char *err,
                        size_t errlen);

/* ---- Record identity (src/qrmem_uuid.c) -----------------------------------
 *
 * Strict, one-directional, and enforced before any mutation. Canonical form is
 * lowercase 8-4-4-4-12 with version nibble 4 and variant nibble in [89ab].
 * Uppercase is refused rather than normalised: two spellings of one identity is
 * the ambiguity this type exists to remove. */

/* 0 and fills *out, or -1 with err. Leaves *out nil on every failure. */
int qrmem_uuid_parse(const char *text, qrmem_uuid_t *out, char *err,
                     size_t errlen);
/* Canonical lowercase text, always 36 chars plus a NUL. */
int qrmem_uuid_text(const qrmem_uuid_t *u, char *out, size_t cap);
/* Fresh v4 from kernel entropy. Refuses rather than minting a guessable id. */
int qrmem_uuid_mint(qrmem_uuid_t *out, char *err, size_t errlen);
int qrmem_uuid_equal(const qrmem_uuid_t *a, const qrmem_uuid_t *b);
int qrmem_uuid_is_nil(const qrmem_uuid_t *u);
/* Short stable tag for logs and captions. Never use to test record identity. */
uint32_t qrmem_uuid_tag(const qrmem_uuid_t *u);

/* Cell codec. Every decode REJECTS a malformed record; none of them repair or
 * clamp one, because a silently repaired cell makes a fabric bug look like a
 * working system. */
typedef struct {
    uint16_t type;
    qrmem_uuid_t id;
    qrmem_uuid_t links[QRMEM_CELL_LINKS];
    uint16_t n_links;
    unsigned char body[QRMEM_CELL_BODY];
    uint16_t body_len;
    uint16_t generation; /* screen generation at the write, part of the witness */
} qrmem_rec_t;

/* FNV-1a, 32-bit. Named for what it is.
 *
 * This was called qrmem_crc32, which was a lie: it is FNV-1a (offset basis
 * 0x811C, prime 0x01000193) and never was CRC-32 (reflected, poly 0xEDB88320).
 * Nothing in the fabric needs CRC-32's error-detection strength - the field is
 * an accidental-corruption witness, not a transport checksum - so the algorithm
 * did not change, only the name. A function called crc32 that is not CRC-32 is a
 * landmine for whoever reaches for it next expecting CRC properties, and PNG
 * chunk CRCs are exactly that reach. */
uint32_t qrmem_fnv1a32(const void *data, size_t len);
/* The accidental-corruption witness over one record, identity and links
 * included. Exposed so the gate can prove the witness actually covers the
 * identity bytes rather than merely asserting that it does. */
uint32_t qrmem_rec_witness(const qrmem_rec_t *r);
void qrmem_rec_init(qrmem_rec_t *r, uint16_t type, qrmem_uuid_t id);
int qrmem_rec_add_text(qrmem_rec_t *r, const char *s, size_t len);
/* Text under an arbitrary tag, for a second string-valued field. Never reuse
 * QRMEM_TLV_TEXT for this: it is the payload, and two values under one tag means
 * a reader gets whichever it finds first. */
int qrmem_rec_add_text_tag(qrmem_rec_t *r, uint16_t tag, const char *s,
                           size_t len);
int qrmem_rec_add_u32(qrmem_rec_t *r, uint16_t tag, uint32_t v);
/* Publication timestamp. Set by the write path, never by a caller: there is no
 * argument to backdate a record or forge its freshness. */
int qrmem_rec_stamp_written(qrmem_rec_t *r, uint64_t unix_ns);
/* 0 means a legacy record written before the field existed. */
uint64_t qrmem_rec_written_ns(const qrmem_rec_t *r);
int qrmem_rec_add_u8(qrmem_rec_t *r, uint16_t tag, uint8_t v);
int qrmem_rec_add_u32_array(qrmem_rec_t *r, uint16_t tag, const uint32_t *v,
                            size_t n);
/* A fixed-length raw byte value, used to carry a UUID inside the body without
 * spending 36 characters of text on five hyphens. */
int qrmem_rec_add_bytes(qrmem_rec_t *r, uint16_t tag, const unsigned char *v,
                        size_t n);
int qrmem_rec_get_bytes(const qrmem_rec_t *r, uint16_t tag,
                        unsigned char *out, size_t cap, size_t *n_out);
int qrmem_rec_link(qrmem_rec_t *r, qrmem_uuid_t id);
/* Body readers. Return 0 and set *out, or -1 when the tag is absent. A present
 * but wrong-sized tag is an error, never a short read. */
int qrmem_rec_get_u32(const qrmem_rec_t *r, uint16_t tag, uint32_t *out);
int qrmem_rec_get_u8(const qrmem_rec_t *r, uint16_t tag, uint8_t *out);
int qrmem_rec_get_text(const qrmem_rec_t *r, const char **out, size_t *out_len);
/* The same, under an arbitrary tag. qrmem_rec_get_text is QRMEM_TLV_TEXT
 * specifically; a second string-valued field needs this. */
int qrmem_rec_get_text_tag(const qrmem_rec_t *r, uint16_t tag,
                           const char **out, size_t *out_len);
int qrmem_rec_get_u32_array(const qrmem_rec_t *r, uint16_t tag, uint32_t *out,
                            size_t cap, size_t *n_out);

/* Encode into a cell, publishing with a release store. The caller must hold
 * write ownership of the screen. Returns 0, or -1 with err. */
/* A canonical, sequence-locked byte image of one record for the code plane to
 * encode. `readers` and the stride padding are zeroed; see the implementation for
 * why. This is the ONLY supported way to look at a record's raw bytes. */
int qrmem_cell_snapshot(const qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                        uint32_t slot, unsigned char *out, size_t cap);

int qrmem_cell_publish(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                       uint32_t slot, const qrmem_rec_t *r, char *err,
                       size_t errlen);
/* Read one cell. Acquire-loads the publication word before reading anything.
 * Returns 0, or -1 when the cell is not published (FREE) or is malformed. */
int qrmem_cell_read(const qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                    uint32_t slot, qrmem_rec_t *out, char *err,
                    size_t errlen);
/* Structural validation of an encoded body, no cell required. Fuzz gate. */
int qrmem_cell_validate(const unsigned char *body, size_t len);
/* Clear one cell (write ownership required). */
int qrmem_cell_clear(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                     uint32_t slot, char *err, size_t errlen);
/* Mark a cell superseded without discarding its record. */
int qrmem_cell_tomb(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                    uint32_t slot, char *err, size_t errlen);

/* Screen generation. Bumped exactly once per completed mutating operation,
 * after every cell that operation published. This is the value a reader
 * watches to know something changed. */
uint64_t qrmem_generation(const qrmem_ap_t *ap, uint32_t screen);
uint64_t qrmem_epoch(const qrmem_ap_t *ap);
uint64_t qrmem_write_count(const qrmem_ap_t *ap, uint32_t screen);
uint32_t qrmem_screen_owner(const qrmem_ap_t *ap, uint32_t screen);
/* RAII-style operation scope: begin stamps the pre-generation, end bumps and
 * publishes the doorbell. Every mutating op runs inside one. */
int qrmem_op_begin(qrmem_ap_t *ap, uint32_t screen, uint32_t *gen_out);
void qrmem_op_end(qrmem_ap_t *ap, uint32_t screen);

/* The six tile verbs. Each mutating verb requires write ownership of every
 * screen it touches; READ requires none, because every reader may read every
 * screen. That asymmetry is the fabric. */
int qrmem_tile_read(const qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                    uint32_t slot, qrmem_rec_t *out, char *err, size_t errlen);
int qrmem_tile_write(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                     uint32_t slot, qrmem_id_t id, const qrmem_rec_t *r,
                     char *err, size_t errlen);
int qrmem_tile_link(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                    uint32_t slot, qrmem_id_t id, qrmem_uuid_t target_id,
                    char *err, size_t errlen);
int qrmem_tile_copy(qrmem_ap_t *ap, uint32_t src_screen, uint32_t src_block,
                    uint32_t src_slot, uint32_t dst_screen, uint32_t dst_block,
                    uint32_t dst_slot, qrmem_id_t id, char *err,
                    size_t errlen);
int qrmem_tile_move(qrmem_ap_t *ap, uint32_t src_screen, uint32_t src_block,
                    uint32_t src_slot, uint32_t dst_screen, uint32_t dst_block,
                    uint32_t dst_slot, qrmem_id_t id, char *err,
                    size_t errlen);
/* `by_id` is the UUID of the record that replaced this one, or the nil UUID to
 * record no successor. The nil UUID is not a valid v4, so "no successor" can
 * never be confused with a real record. */
int qrmem_tile_supersede(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                         uint32_t slot, qrmem_id_t id, qrmem_uuid_t by_id,
                         char *err, size_t errlen);

/* Index. Lookups return only indexed cells and NEVER fall back to a scan: a
 * scan fallback is precisely the cost the index exists to avoid, so an index
 * miss is reported as a miss. */
/* `agent` is explicit rather than read from ap->self_agent.
 *
 * That used to be ambient, and ambient identity is exactly the shape of the bug
 * fixed in d46f305: a mutable identity field that anything can change and
 * everything depends on. With a shared listener serving many agents it is worse
 * than a bug, because ap->self_agent would be written by every connection and
 * read by every other one. Ownership is passed in, like every other mutating
 * verb. */
int qrmem_index_put(qrmem_ap_t *ap, uint32_t screen, qrmem_id_t id,
                    const char *key, uint32_t block, uint32_t slot, char *err,
                    size_t errlen);
/* Rebuild one index entry from a record that carries its own lookup key.
 *
 * DERIVED STATE, so this needs no ownership: the restore path runs before any
 * agent exists, and it is rebuilding the table from the record that owns the
 * key rather than from a second structure that could disagree with it. Not
 * exposed on the agent surface, and not a flag on qrmem_index_put, so there is
 * no path by which an agent can widen what a lookup finds on a screen it does
 * not own. */
int qrmem_index_restore(qrmem_ap_t *ap, uint32_t screen, const char *key,
                        uint32_t block, uint32_t slot);
int qrmem_index_drop_cell(qrmem_ap_t *ap, uint32_t screen, uint32_t block,
                          uint32_t slot);
int qrmem_index_drop_key(qrmem_ap_t *ap, uint32_t screen, const char *key);
int qrmem_index_lookup(qrmem_ap_t *ap, uint32_t screen, const char *key,
                       uint32_t cap, uint32_t *out_block, uint32_t *out_slot,
                       size_t *n_out, char *err, size_t errlen);
uint32_t qrmem_index_used(const qrmem_ap_t *ap, uint32_t screen);

/* Addressing.
 *
 * A record is named by (screen, block, slot). It is NOT named by plane
 * coordinates: plane coordinates describe where the record's ENCODING sits, and
 * conflating the two is how a record and a coded block get confused. The viewer
 * converts one to the other for display and nothing else does.
 *
 * Every accessor validates before it computes, so an out-of-range block or slot
 * can never index outside the aperture. */
static inline int qrmem_screen_valid(uint32_t s) {
    return s < QRMEM_SCREENS;
}
static inline int qrmem_block_valid(uint32_t b) {
    return b < QRMEM_BLOCKS_PER_SCREEN;
}
static inline int qrmem_slot_valid(uint32_t s) {
    return s < QRMEM_SLOTS_PER_BLOCK;
}
/* Where a block sits in the plane, so a viewer can find its modules. */
static inline uint32_t qrmem_record_index(uint32_t b, uint32_t s) {
    return b * QRMEM_SLOTS_PER_BLOCK + s;
}
static inline uint32_t qrmem_record_row(uint32_t block, uint32_t slot) {
    return qrmem_record_index(block, slot) / 10u;
}
static inline uint32_t qrmem_record_col(uint32_t block, uint32_t slot) {
    return qrmem_record_index(block, slot) % 10u;
}
/* Ten columns cover 4096 display pixels through exact integer bounds: each
 * viewport is 409 or 410 pixels wide, without a fractional-pixel fiction. */
static inline uint32_t qrmem_viewport_x0(uint32_t col) {
    return (col * QRMEM_PLANE_DIM) / 10u;
}
static inline uint32_t qrmem_viewport_x1(uint32_t col) {
    return ((col + 1u) * QRMEM_PLANE_DIM) / 10u;
}
static inline uint32_t qrmem_viewport_y0(uint32_t row) { return row * 512u; }
static inline uint32_t qrmem_viewport_y1(uint32_t row) { return (row + 1u) * 512u; }
static inline qrmem_cell_t *qrmem_cell_at(const qrmem_ap_t *ap, uint32_t sc,
                                          uint32_t block, uint32_t slot) {
    size_t idx = (size_t)sc * QRMEM_RECORDS_PER_SCREEN +
                 qrmem_record_index(block, slot);
    /* Byte arithmetic on purpose: ap->cells is a qrmem_cell_t *, and plain []
     * would step by sizeof(qrmem_cell_t) rather than by the shared stride. */
    return (qrmem_cell_t *)(void *)((unsigned char *)(void *)ap->cells +
                                   idx * QRMEM_CELL_BYTES);
}

/* Code plane module access. Modules are one bit, packed eight to a byte.
 *
 * A module is read with a single atomic byte load and a shift, which is why
 * packing them is still safe: no reader can observe a half-written byte, and a
 * module cannot straddle one. Writing a module therefore needs a CAS loop on
 * the containing byte, which is uncontended in practice because exactly one
 * agent owns a screen. */
static inline int qrmem_bitplane_get(const qrmem_ap_t *ap, uint32_t plane,
                                     uint32_t sc, uint32_t px, uint32_t py) {
    const _Atomic unsigned char *row;
    unsigned char b;
    if (!ap || !ap->plane || plane >= QRMEM_PLANE_COUNT || !qrmem_screen_valid(sc) || px >= QRMEM_PLANE_DIM ||
        py >= QRMEM_PLANE_DIM)
        return 0;
    row = ap->plane + ((size_t)sc * QRMEM_PLANE_COUNT + plane) * QRMEM_PLANE_SCREEN_BYTES +
          (size_t)py * QRMEM_PLANE_ROW_BYTES + (px >> 3);
    b = atomic_load_explicit(row, memory_order_acquire);
    return (int)((b >> (7u - (px & 7u))) & 1u);
}
static inline void qrmem_bitplane_set(qrmem_ap_t *ap, uint32_t plane,
                                      uint32_t sc, uint32_t px,
                                      uint32_t py, int v) {
    _Atomic unsigned char *cell;
    unsigned char cur, want;
    if (!ap || !ap->plane || plane >= QRMEM_PLANE_COUNT || !qrmem_screen_valid(sc) || px >= QRMEM_PLANE_DIM ||
        py >= QRMEM_PLANE_DIM)
        return;
    cell = ap->plane + ((size_t)sc * QRMEM_PLANE_COUNT + plane) * QRMEM_PLANE_SCREEN_BYTES +
           (size_t)py * QRMEM_PLANE_ROW_BYTES + (px >> 3);
    cur = atomic_load_explicit(cell, memory_order_acquire);
    for (;;) {
        want = (unsigned char)(v ? (cur | (1u << (7u - (px & 7u))))
                                 : (cur & (unsigned char) ~(1u << (7u - (px & 7u)))));
        if (cur == want)
            return;
        if (atomic_compare_exchange_weak_explicit(cell, &cur, want,
                                                  memory_order_acq_rel,
                                                  memory_order_acquire))
            return;
    }
}
static inline int qrmem_plane_get(const qrmem_ap_t *ap, uint32_t sc, uint32_t px,
                                  uint32_t py) {
    return qrmem_bitplane_get(ap, QRMEM_PLANE_QR, sc, px, py);
}
static inline void qrmem_plane_set(qrmem_ap_t *ap, uint32_t sc, uint32_t px,
                                   uint32_t py, int v) {
    qrmem_bitplane_set(ap, QRMEM_PLANE_QR, sc, px, py, v);
}

/* Code plane. See qrmem_plane.c for the block layout.
 *
 * Deterministic in both directions: given five records, exactly one pattern, and
 * given the pattern, the records. The plane is DERIVED from the record store -
 * it is never the thing an agent writes - so a damaged plane costs a redraw and
 * a damaged record costs data. */
int qrmem_plane_encode_block(const qrmem_ap_t *ap, uint32_t screen,
                             uint32_t block, unsigned char *out);
int qrmem_plane_store_block(qrmem_ap_t *ap, uint32_t screen, uint32_t block);

/* Draw the whole fabric's structure. Called at creation so the surface exists
 * before anything is written to it. */
int qrmem_plane_init(qrmem_ap_t *ap);
/* Declare the current coherent screen state as the blue-plane baseline. */
int qrmem_plane_set_baseline(qrmem_ap_t *ap, uint32_t screen);
/* Mark exactly one post-baseline mutation blue after its operation generation
 * has been published.  Renderers never infer dirty state from an old cell. */
void qrmem_plane_mark_changed(qrmem_ap_t *ap, uint32_t screen,
                              uint32_t block, uint32_t slot);
/* Lossless portable bitmap export. QR tiles are exported from plane 0 alone;
 * callers must not composite occupancy/change into a scanner input. */
int qrmem_plane_export_tile_pbm(const qrmem_ap_t *ap, uint32_t screen,
                                uint32_t block, uint32_t slot, const char *path,
                                char *err, size_t errlen);
/* Decode a block straight out of the packed plane and prove it still matches the
 * record store. Returns 0 when it round-trips, 1 when it does not, with the
 * reason in `err`. This is the check that makes a viewer trustworthy: it never
 * re-renders, so a damaged plane is reported instead of repaired. */
int qrmem_plane_verify_block(const qrmem_ap_t *ap, uint32_t screen,
                             uint32_t block, char *err, size_t errlen);

int qrmem_plane_render(const qrmem_ap_t *ap, uint32_t screen, uint32_t x0,
                       uint32_t y0, uint32_t w, uint32_t h, char *out,
                       size_t out_len, size_t *n_out, char *err, size_t errlen);

/* Agent registry. The daemon owns it; slots are 1+ and stable for the life of
 * the aperture, so a stale handle from a dead era never names a live agent. */
int qrmem_agent_claim(qrmem_ap_t *ap, const char *agent_id, uint32_t *slot_out,
                      uint32_t *gen_out, char *err, size_t errlen);
void qrmem_agent_release(qrmem_ap_t *ap, uint32_t slot);
/* Record that this slot's owner is still here. Cheap, and called on every
 * request rather than only on writes, because an agent can be perfectly alive
 * and simply not have written anything for minutes. */
void qrmem_agent_touch(qrmem_ap_t *ap, uint32_t slot);
/* Lease accounting. A lease is held for as long as a control connection is
 * open, and released when the kernel closes it.
 *
 * qrmem_agent_lease is called by the fabric daemon when a client says HELLO.
 * qrmem_agent_unlease is called when that client's connection ends, for any
 * reason including a crash, and the last release frees the agent along with
 * every screen it held.
 *
 * Clients never call these. A client holds a connection; it does not assert
 * that it is alive. */
void qrmem_agent_lease(qrmem_ap_t *ap, uint32_t slot);
void qrmem_agent_unlease(qrmem_ap_t *ap, uint32_t slot);
uint32_t qrmem_agent_lease_held(const qrmem_ap_t *ap, uint32_t slot);
/* The allocation generation this slot holds. Never derive it from the slot
 * number; 0 means the slot is unallocated. */
uint32_t qrmem_agent_generation_of(const qrmem_ap_t *ap, uint32_t slot);
/* This fabric's identity: a UUIDv4 minted once by the creator of the aperture.
 *
 * Stable for the life of the fabric. NOT a daemon restart, NOT authority_gen,
 * NOT the hostname, NOT the uid, NOT the aperture pathname (which is identical
 * on every host), and NOT derived from screen contents. An aperture with no
 * valid id is refused at attach rather than adopted, because attach is what
 * every other agent does while a fabric is live.
 *
 * Deliberately absent from the snapshot payload. The snapshot carries content
 * and is meant to be copied; this says who the fabric is. Carried in the
 * snapshot, a copied snapshot would clone the identity and leave two live
 * fabrics claiming one namespace. */
int qrmem_fabric_id(const qrmem_ap_t *ap, qrmem_uuid_t *out);

/* Whether a fenced triple is still recognised by this fabric, split by cause so
 * a caller can tell "my lease is stale" from "the aperture was replaced" from
 * "someone else holds that slot now". `generation_ok` is only meaningful when
 * `slot_ok` is true. Lives here, not in the MCP layer, so it can be tested
 * against forged stale state. */
void qrmem_agent_enrollment_check(const qrmem_ap_t *ap, uint32_t slot,
                                  uint64_t authority_gen, uint32_t agent_gen,
                                  int *authority_ok, int *slot_ok,
                                  int *generation_ok, uint32_t *live_gen);

/* Seconds this agent has held a lease, against the caller's monotonic clock.
 * 0 when unleased. Local-host only, like last_seen_ns. */
uint32_t qrmem_agent_connected_seconds(const qrmem_ap_t *ap, uint32_t slot);
/* Reclaim slots whose owner has not been seen for max_age_ns, and drop the
 * screen ownership they held.
 *
 * This exists because agent slots were never reclaimed: the registry filled
 * with every process that had ever attached, and at 64 it refused everyone.
 * Found by looking at the live MCP surface, which reported agents=18/64 after
 * nothing more than a handful of test invocations.
 *
 * Releasing a slot RELEASES ITS SCREENS FIRST. A slot number is reused by the
 * next allocation, so a reclaim that left `owner` pointing at the dead slot
 * would silently hand the previous holder's write authority to whoever drew
 * that number next. The screen is dropped rather than transferred, because the
 * tile's contents stay readable by everyone regardless. */
uint32_t qrmem_agent_sweep(qrmem_ap_t *ap, uint64_t max_age_ns);
/* Reap only slots that are unleased AND long unseen. A leased slot is never
 * touched, however old its heartbeat, because the connection is the proof. */
/* How many slots the next sweep would reclaim. Read-only, for --doctor and
 * qrmem_status, so an operator can see the registry filling before it refuses. */
uint32_t qrmem_agent_reclaimable(const qrmem_ap_t *ap, uint64_t max_age_ns);
int qrmem_agent_name(const qrmem_ap_t *ap, uint32_t slot, char *out,
                     size_t out_len);
/* Where slot's lease comes from, as the authority recorded it:
 * QRMEM_ORIGIN_UNKNOWN or QRMEM_ORIGIN_LOCAL. Out-of-range slots and a
 * detached fabric report UNKNOWN rather than failing, because presence must
 * degrade to "unknown" rather than invent a source. */
uint32_t qrmem_agent_origin_kind(const qrmem_ap_t *ap, uint32_t slot);
/* The authority's own hostname, as it wrote it at bind. Returns -1 when there
 * is none to report. Descriptive only; never use it to decide identity. */
int qrmem_authority_host(const qrmem_ap_t *ap, char *out, size_t cap);
uint32_t qrmem_agent_count(const qrmem_ap_t *ap);
uint32_t qrmem_era(const qrmem_ap_t *ap);
/* Mint a fresh opaque handle: era in the high half, sequence in the low.
 * A sequence lap forces a new era, which invalidates every earlier handle at
 * once rather than resurrecting a wrapped one. */
uint64_t qrmem_handle_mint(qrmem_ap_t *ap);
int qrmem_handle_valid(const qrmem_ap_t *ap, uint64_t h);
void qrmem_handle_split(uint64_t h, uint32_t *era, uint32_t *seq);

#endif
