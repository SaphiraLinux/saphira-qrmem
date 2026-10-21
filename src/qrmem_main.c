/* Saphira Memory - qrmem: the tile fabric daemon and its MCP window.
 *
 * One binary, two modes, chosen by flag:
 *
 *   --stdio   the MCP window. Speaks newline-delimited JSON-RPC on stdio and
 *             exposes the tile verbs. Holds NO database and NO credential, so
 *             it has its own stdio loop rather than reusing src/stdio.c: that
 *             loop re-authenticates a session JWE against the database on every
 *             data-plane call, and a fabric that reached the database to prove
 *             who is asking would no longer be a fabric.
 *
 *   --serve   the fabric daemon. Owns the aperture and serves a control
 *             socket. Still holds no SQL.
 *
 * The MCP surface is the CONTROL PLANE: view a tile, decode a region, inspect a
 * record, watch generations. It is deliberately not on the hot path. A process
 * in this uid reads cells directly through the mapping instead.
 */
#include "qrmem.h"

#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef SAPHIRA_VERSION
#define SAPHIRA_VERSION "0.1.0"
#endif

/* Per-call ceiling on records returned by an inspection verb. An agent asked for
 * a full 128x128 screen once and would have received 16384 records, which is a
 * payload designed to detonate in a caller's context rather than inform it. */
#define QRMEM_DECODE_MAX 512

/* How long a registry slot may go unseen before it is reclaimed.
 *
 * Five minutes is a judgement, and it is biased towards keeping slots: reclaiming
 * one that is still in use would drop a live agent's tile. Too short a window
 * would reclaim an agent that is merely mid-thought, and a restart always draws
 * a NEW identity, so the reclaimed slot would not even be the one it came back
 * for. Five minutes of total silence on a fabric is a gone process. */
#define QRMEM_AGENT_STALE_NS (300ull * 1000000000ull)

#define QRMEM_SERVER_NAME "saphira-qrmem"
#define QRMEM_MCP_PROTOCOL_VERSION "2025-06-18"

/* Exit codes, matching the family convention. */
enum {
    QRMEM_EXIT_OK = 0,
    QRMEM_EXIT_USAGE = 2,
    QRMEM_EXIT_CONFIG = 3
};

static volatile sig_atomic_t g_stop = 0;
/* Set when the lease connection ends. A client whose lease is gone is reading an
 * orphaned mapping: the segment still exists in this process's address space but
 * the daemon that owned it has gone, so nothing can reach it and nothing can
 * arbitrate who writes. The client must stop rather than serve a private idea of
 * a shared fabric. */
static volatile sig_atomic_t g_lease_lost = 0;

int saphira_should_stop(void) { return g_stop != 0; }

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

/* Per-process identity.
 *
 * Found by review, in production, by another agent: the opencode config names
 * `--agent opencode`, so EVERY session on the host started with the same
 * identity and the fabric assigned them all ONE slot. Two sessions therefore
 * shared write authority over each other's screens - the one-writer rule is
 * enforced per slot, so a shared slot voids it - and neither could address the
 * other, because "slot 1" meant both of them. The symptom was an agent finding
 * records on a screen it had never joined, under its own slot, written by a
 * session it could not see.
 *
 * So `--agent` is a LABEL, and the identity the fabric registers is the label
 * plus a suffix minted fresh for each process incarnation:
 *
 *     opencode#a3f19c2b
 *
 * Two sessions with the same label are still distinguishable, and each is its
 * own writer. An operator who needs a STABLE identity across restarts (a
 * daemon, a supervised service) passes --agent-id, which bypasses the suffix.
 * An ordinary interactive session should not: a restart genuinely IS a new
 * writer, and the old one is not coming back to contest the tile. */
static void mint_identity(char *out, size_t outlen, const char *label,
                          const char *stable) {
    unsigned char raw[4] = {0, 0, 0, 0};
    if (stable && stable[0]) {
        snprintf(out, outlen, "%s", stable);
        return;
    }
    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            ssize_t got = read(fd, raw, sizeof raw);
            close(fd);
            if (got != (ssize_t)sizeof raw)
                memset(raw, 0, sizeof raw);
        }
    }
    if (raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0) {
        /* No urandom: fall back to pid and the clock. Weaker, but a collision
         * here costs two sessions a shared screen, not a security property, so
         * best-effort is the right size for this fallback. */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        raw[0] = (unsigned char)(getpid() & 0xFF);
        raw[1] = (unsigned char)((getpid() >> 8) & 0xFF);
        raw[2] = (unsigned char)(ts.tv_nsec & 0xFF);
        raw[3] = (unsigned char)((ts.tv_nsec >> 8) & 0xFF);
    }
    snprintf(out, outlen, "%s#%02x%02x%02x%02x", label, raw[0], raw[1], raw[2],
             raw[3]);
}

static void install_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

static void set_err(char *err, size_t errlen, const char *fmt, ...) {
    if (!err || !errlen)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

/* Fabric location.
 *
 * The aperture lives in /dev/shm, which is a tmpfs: it is memory, it is
 * private to this machine, and it is wiped on reboot. The aperture is still
 * deliberately short-lived - it is scratch - but "wiped on reboot" used to mean
 * an agent's live page just VANISHED, with nothing to distinguish that from the
 * page never having existed. Once agents depend on the fabric, losing an
 * agent's work to a reboot is a defect, so the aperture stays in /dev/shm and
 * its durable shadow lives here.
 *
 * The name is namespaced by uid on purpose. The daemon runs as one user today
 * and may run as another tomorrow, and a per-uid name means the change is a
 * service-user edit rather than a fight over one shared segment. */
static void default_aperture_path(char *buf, size_t len) {
    snprintf(buf, len, "/%s-%u", QRMEM_DEFAULT_NAME, (unsigned)getuid());
}

/* Where the durable shadow of the aperture lives.
 *
 * Beside the aperture's own configuration, not beside the segment: /dev/shm is
 * a tmpfs, so anything written beside the aperture would itself vanish on the
 * same reboot this is meant to survive. Namespaced by uid for the same reason
 * the aperture name is.
 *
 * This is a RESTORE point, not an archive. It answers "what did this machine
 * know when it stopped" and is overwritten each save by atomic rename. Long-term
 * page history is a separate, larger question (see docs/PRODUCT-qrmem.md) and
 * is deliberately not faked here. */
#define QRMEM_SNAPSHOT_MAX_PATH 1024

/* Where the restore point goes when the operator has not said otherwise.
 *
 * XDG_STATE_HOME, then ~/.local/state. NOT the daemon's own /etc configuration
 * directory: that tree belongs to the service user and is mode 0750 owned by it,
 * so a fabric daemon running as an ordinary user cannot write there at all. The
 * first attempt at this put the snapshot under /etc/saphira/memoryd/qrmem and
 * the daemon refused its own restore point with a permission error at startup -
 * which is at least a loud failure, but it would have meant every unprivileged
 * deployment saving nothing while believing it had.
 *
 * A restore point is per-uid state about that uid's fabric, and the aperture
 * name is already uid-namespaced, so per-user state is where it belongs. The
 * directory is created on demand with 0700: it holds every page this user ever
 * had open. */
static void default_snapshot_path(const char *aperture, char *buf, size_t len) {
    /* The aperture name is "/saphira-qrmem-1000"; strip the leading slash and
     * keep the rest, so each uid gets its own restore point.
     *
     * The name segment is bounded rather than trusted: --aperture is
     * operator-supplied and the destination is a fixed buffer, so the precision
     * is what stops a long name from becoming a silent truncation that writes
     * two fabrics' pages to one restore point. */
    const char *base = (aperture && aperture[0] == '/') ? aperture + 1
                                                        : (aperture ?
                                                               aperture
                                                           : "saphira-qrmem");
    const char *state = getenv("XDG_STATE_HOME");
    /* `dir` is generously oversized relative to `buf` so the compiler can see
     * that the assembled state prefix plus the fixed suffix plus the bounded
     * aperture name always fits the destination. Without that margin the
     * truncation cannot be proved and -Werror=format-truncation stops the
     * build; the alternative was to trust it, which is how the previous
     * /etc-relative version shipped. */
    char dir[QRMEM_SNAPSHOT_MAX_PATH * 2];
    if (!state || !state[0]) {
        const char *home = getenv("HOME");
        if (home && home[0])
            snprintf(dir, sizeof dir, "%.*s/.local/state",
                     512, home);
        else
            snprintf(dir, sizeof dir, "/tmp");
    } else {
        snprintf(dir, sizeof dir, "%.*s", 512, state);
    }
    /* Every %s here carries an explicit precision, and the numbers add up to
     * less than `len`, so the total is bounded by construction rather than by
     * hope about what an operator put in XDG_STATE_HOME. 700 + 15 + 200 + 10
     * is well inside the 1024-byte destination. */
    snprintf(buf, len, "%.700s/saphira/qrmem/%.*s.snapshot", dir, 200, base);
}

/* Create the restore point's directory, 0700, if it is not there.
 *
 * Best effort by design: a failure here is not fatal to the daemon, because the
 * fabric still works and the operator can pass --snapshot somewhere writable.
 * It is reported rather than swallowed, so "my pages are not surviving" is
 * visible at startup instead of discovered after a reboot. */
static void ensure_snapshot_dir(const char *snapshot_path) {
    char dir[QRMEM_SNAPSHOT_MAX_PATH];
    char *slash;
    snprintf(dir, sizeof dir, "%s", snapshot_path);
    slash = strrchr(dir, '/');
    if (!slash || slash == dir)
        return;
    *slash = '\0';
    /* mkdir is not recursive, and XDG_STATE_HOME may not exist yet on a fresh
     * account. Creating parents one level at a time is the whole difference
     * between a restore point that works and a daemon that warns on every
     * start forever. Each component is created 0700: this tree holds every page
     * the user had open. */
    {
        char *p2 = dir;
        /* Skip the LEADING slash: cutting there leaves an empty path, and
         * mkdir("") fails ENOENT with an error message naming nothing. */
        while (*p2 == '/')
            p2++;
        while (*p2) {
            if (*p2 == '/') {
                *p2 = '\0';
                if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
                    fprintf(stderr,
                            "%s: cannot create %s: %s\n", QRMEM_SERVER_NAME,
                            dir, strerror(errno));
                    *p2 = '/';
                    return;
                }
                *p2 = '/';
            }
            p2++;
        }
    }
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        fprintf(stderr,
                "%s: cannot create the restore point directory %s: %s; pages "
                "will not survive a reboot unless --snapshot names somewhere "
                "writable\n",
                QRMEM_SERVER_NAME, dir, strerror(errno));
}

/* Client side of the lease.
 *
 * The connection is opened ONCE, used to say hello, and then held open and never
 * written again. The daemon learns about this process being alive from the
 * descriptor staying open, so the client does not assert liveness - it just
 * keeps the descriptor. Exit or crash closes it and the kernel does the rest.
 *
 * Data does NOT travel here. Tool calls read shared memory directly, which is
 * the hot path; this socket is liveness only, and the two planes are kept apart
 * deliberately so a slow control round trip can never stand between an agent and
 * its own memory. */
/* Frame codec, defined with the socket server. The lease client needs it too,
 * because the greeting travels the same wire. */
static int read_frame(int fd, char *buf, size_t cap);
static int write_frame(int fd, const char *body, size_t len);

static char g_client_identity[QRMEM_AGENT_NAME_MAX] = "opencode";
static int g_lease_fd = -1;

/* `aperture_out` receives the fabric NAME the daemon says it is serving, so the
 * caller can check it against the segment it actually opened. */
static int lease_connect(const char *sockpath, uint32_t *slot_out,
                         uint32_t *gen_out, uint32_t *auth_out,
                         char *aperture_out, size_t aperture_outlen, char *err,
                         size_t errlen) {
    int fd;
    struct sockaddr_un sa;
    char buf[1024];
    char *text;
    int n;
    if (strlen(sockpath) >= sizeof sa.sun_path) {
        set_err(err, errlen, "lease socket path is too long");
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        set_err(err, errlen, "lease socket: %s", strerror(errno));
        return -1;
    }
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    snprintf(sa.sun_path, sizeof sa.sun_path, "%.*s",
             (int)sizeof sa.sun_path - 1, sockpath);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        set_err(err, errlen, "lease connect %s: %s", sockpath, strerror(errno));
        close(fd);
        return -1;
    }
    {
        char hello[512];
        int hl = snprintf(hello, sizeof hello,
                          "{\"op\":\"hello\",\"agent\":\"%s\"}",
                          g_client_identity);
        if (hl <= 0 || hl >= (int)sizeof hello) {
            set_err(err, errlen, "identity is too long to greet with");
            close(fd);
            return -1;
        }
        if (write_frame(fd, hello, (size_t)hl) != 0) {
            set_err(err, errlen, "lease hello did not send");
            close(fd);
            return -1;
        }
    }
    n = read_frame(fd, buf, sizeof buf);
    if (n <= 0) {
        set_err(err, errlen, "the fabric daemon did not answer the greeting");
        close(fd);
        return -1;
    }
    text = buf;
    if (strstr(text, "\"ok\":true") == NULL) {
        set_err(err, errlen, "the fabric refused this identity: %s", text);
        close(fd);
        return -1;
    }
    {
        /* The literal is 7 bytes:  " s l o t " :   Skipping 8 ate the first
         * digit, so a slot of 1 parsed as 0 and every client silently became the
         * "no identity" sentinel - which reads as "you never joined" rather than
         * as a parsing mistake. Offsets into a serialised string are counted,
         * never guessed. */
        static const char kSlot[] = "\"slot\":";
        const size_t klen = sizeof kSlot - 1u;
        const char *s2 = strstr(text, kSlot);
        if (!s2) {
            set_err(err, errlen,
                    "the daemon greeted us but named no slot: %s", text);
            close(fd);
            return -1;
        }
        *slot_out = (uint32_t)strtoul(s2 + klen, NULL, 10);
        if (*slot_out == 0u) {
            set_err(err, errlen, "the daemon offered agent slot zero: %s", text);
            close(fd);
            return -1;
        }
    }
    {
        /* The generation rides the same reply: a slot number without its
         * allocation generation is not an identity. Same counted-offset
         * discipline as above. Absent means an older daemon; refuse
         * rather than assume generation zero, which would match nothing
         * real and fail confusingly later. */
        static const char kGen[] = "\"agent_gen\":";
        const size_t glen = sizeof kGen - 1u;
        const char *g2 = strstr(text, kGen);
        if (!g2) {
            set_err(err, errlen,
                    "the daemon greeted us without an agent generation: %s",
                    text);
            close(fd);
            return -1;
        }
        if (gen_out)
            *gen_out = (uint32_t)strtoul(g2 + glen, NULL, 10);
        if (gen_out && *gen_out == 0u) {
            set_err(err, errlen,
                    "the daemon offered agent generation zero: %s", text);
            close(fd);
            return -1;
        }
    }
    {
        /* Which fabric answered. Counted offset, same discipline as the fields
         * above: the literal is 12 bytes including the colon. */
        static const char kAp[] = "\"aperture\":\"";
        const size_t alen2 = sizeof kAp - 1u;
        const char *a3 = strstr(text, kAp);
        if (!a3) {
            set_err(err, errlen,
                    "the daemon greeted us without naming its fabric: %s", text);
            close(fd);
            return -1;
        }
        a3 += alen2;
        {
            const char *end = strchr(a3, '"');
            size_t want;
            if (!end) {
                set_err(err, errlen,
                        "the daemon named a fabric with no closing quote: %s",
                        text);
                close(fd);
                return -1;
            }
            want = (size_t)(end - a3);
            if (aperture_out) {
                size_t w = 0;
                /* Unescape while copying. json-c emits "\/" for a solidus even
                 * though JSON does not require it, and a shm name always starts
                 * with one, so a naive copy of the raw substring compares as
                 * "\/qrmem-truth" against "/qrmem-truth" and reports a mismatch
                 * for two identical fabrics. Only the escapes that can actually
                 * occur in a name are handled; anything else is copied through,
                 * and a name containing them is refused at aperture setup rather
                 * than silently reinterpreted here. */
                const char *q = a3;
                const char *lim = a3 + want;
                while (q < lim && w + 1u < aperture_outlen) {
                    if (*q == '\\' && q + 1 < lim) {
                        char e = q[1];
                        if (e == '/' || e == '"' || e == '\\') {
                            aperture_out[w++] = e;
                            q += 2;
                            continue;
                        }
                        if (e == 'n') {
                            aperture_out[w++] = '\n';
                            q += 2;
                            continue;
                        }
                    }
                    aperture_out[w++] = *q++;
                }
                aperture_out[w] = '\0';
            }
        }
    }
    {
        /* The authority generation completes the fence. (authority_gen,
         * slot, agent_gen) names exactly one agent incarnation; any two of
         * the three can be reused by a later arrival. Without this field a
         * restarted daemon looks like the same authority and an old client
         * would silently keep writing under a dead incarnation. Absent means
         * an older daemon, so refuse rather than assume. */
        static const char kAuth[] = "\"authority_gen\":";
        const size_t alen = sizeof kAuth - 1u;
        const char *a2 = strstr(text, kAuth);
        if (!a2) {
            set_err(err, errlen,
                    "the daemon greeted us without an authority generation: "
                    "%s",
                    text);
            close(fd);
            return -1;
        }
        if (auth_out)
            *auth_out = (uint32_t)strtoul(a2 + alen, NULL, 10);
        if (auth_out && *auth_out == 0u) {
            set_err(err, errlen,
                    "the daemon offered authority generation zero: %s", text);
            close(fd);
            return -1;
        }
    }
    return fd;
}

/* Watch the lease. Returns as soon as the descriptor reports end-of-file, which
 * is what the kernel does when the daemon dies. */
static void *lease_watch(void *arg) {
    int fd = (int)(intptr_t)arg;
    char sink[256];
    for (;;) {
        ssize_t n = read(fd, sink, sizeof sink);
        if (n <= 0)
            break;
        /* The daemon never writes unsolicited to a lease connection, so
         * anything arriving is not something we asked for and not something to
         * act on. Drain and keep waiting. */
    }
    g_lease_lost = 1;
    return NULL;
}

/* The control socket lives in a per-user runtime directory.
 *
 * Resolution order, and the reason for each step:
 *
 *   1. $XDG_RUNTIME_DIR, if set and writable. The specification's answer, and
 *      the right one wherever a session manager provides it.
 *   2. /run/user/<uid>, when it exists and is writable. This is what
 *      $XDG_RUNTIME_DIR normally points at.
 *   3. /tmp/.saphira-qrmem-<uid>, created 0700 by us.
 *
 * Step 3 exists because steps 1 and 2 both fail on a host with no session
 * manager and no root: XDG_RUNTIME_DIR is unset and /run/user is not creatable
 * by an unprivileged user. That is not an exotic case - it is any VM or
 * appliance-style host - and the original build simply refused to start there
 * with "XDG_RUNTIME_DIR is unset", which is a correct error and a useless
 * answer. The socket is mode 0600 inside a 0700 directory we create, so the
 * fallback is no weaker than the preferred location.
 *
 * Which directory was chosen is printed at startup and reported by --doctor,
 * because a socket path nobody can predict is a socket path nobody debugs. */
static int runtime_dir(char *out, size_t len) {
    const char *xdg = getenv("XDG_RUNTIME_DIR");
    char fallback[512];
    if (xdg && xdg[0] && access(xdg, W_OK | X_OK) == 0) {
        snprintf(out, len, "%s", xdg);
        return 0;
    }
    snprintf(fallback, sizeof fallback, "/run/user/%u", (unsigned)getuid());
    if (access(fallback, W_OK | X_OK) == 0) {
        snprintf(out, len, "%s", fallback);
        return 0;
    }
    snprintf(fallback, sizeof fallback, "/tmp/.saphira-qrmem-%u",
             (unsigned)getuid());
    if (mkdir(fallback, 0700) != 0 && errno != EEXIST) {
        snprintf(out, len, "%s", fallback);
        return -1;
    }
    /* mkdir honours the umask, so tighten it explicitly: anyone who can list
     * this directory can see the socket name. */
    if (chmod(fallback, 0700) != 0) {
        snprintf(out, len, "%s", fallback);
        return -1;
    }
    if (access(fallback, W_OK | X_OK) != 0) {
        snprintf(out, len, "%s", fallback);
        return -1;
    }
    snprintf(out, len, "%s", fallback);
    return 0;
}

static int default_socket_path(char *buf, size_t len) {
    char dir[512];
    if (runtime_dir(dir, sizeof dir) != 0)
        return -1;
    /* Both sources are bounded explicitly rather than with "%s": the directory
     * can be up to 511 bytes and gcc cannot see that the result still fits, and
     * -Werror=format-truncation is not something to silence with a pragma. */
    snprintf(buf, len, "%.*s/%s.sock", (int)(len > 24 ? len - 24 : 0), dir,
             QRMEM_DEFAULT_NAME);
    return 0;
}

/* ---------------------------------------------------------------- JSON helpers */

static struct json_object *tool_desc(const char *name, const char *desc) {
    struct json_object *t = json_object_new_object();
    json_object_object_add(t, "name", json_object_new_string(name));
    json_object_object_add(t, "description", json_object_new_string(desc));
    return t;
}

static struct json_object *strprop(const char *desc) {
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "type", json_object_new_string("string"));
    if (desc)
        json_object_object_add(o, "description", json_object_new_string(desc));
    return o;
}

static struct json_object *intprop(const char *desc) {
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "type", json_object_new_string("integer"));
    if (desc)
        json_object_object_add(o, "description", json_object_new_string(desc));
    return o;
}

/* A screen argument.
 *
 * The description is built from QRMEM_SCREENS rather than written out. The
 * schema said "0..7" while the fabric had sixteen screens, so every agent was
 * told eight screens existed and ten of them were undiscoverable from
 * tools/list. A range stated in prose is a range that goes stale. */
static struct json_object *screen_prop(const char *what) {
    char desc[160];
    snprintf(desc, sizeof desc, "%s, 0..%u.", what ? what : "Screen",
             QRMEM_SCREENS - 1u);
    {
        struct json_object *o = intprop(desc);
        json_object_object_add(o, "minimum", json_object_new_int(0));
        json_object_object_add(o, "maximum",
                               json_object_new_int((int)QRMEM_SCREENS - 1));
        return o;
    }
}

/* A UUIDv4 argument: JSON string only.
 *
 * The pattern is stated in the schema on purpose. An agent reading tools/list
 * should learn that an id is a 36-character lowercase string before it invents
 * an integer, because the alternative - discovering it from a refusal - means
 * one wasted round trip and a record that was not written. */
static struct json_object *uuid4_prop(const char *desc) {
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "type", json_object_new_string("string"));
    json_object_object_add(
        o, "pattern", json_object_new_string(
                            "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]"
                            "{3}-[0-9a-f]{12}$"));
    if (desc)
        json_object_object_add(o, "description", json_object_new_string(desc));
    return o;
}

/* An array of UUIDv4 references. */
static struct json_object *uuid4_array_prop(const char *desc, int max) {
    struct json_object *o = json_object_new_object();
    struct json_object *items = json_object_new_object();
    json_object_object_add(o, "type", json_object_new_string("array"));
    json_object_object_add(items, "type", json_object_new_string("string"));
    json_object_object_add(
        items, "pattern",
        json_object_new_string("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab]"
                               "[0-9a-f]{3}-[0-9a-f]{12}$"));
    json_object_object_add(o, "items", items);
    json_object_object_add(o, "maxItems", json_object_new_int(max));
    if (desc)
        json_object_object_add(o, "description", json_object_new_string(desc));
    return o;
}

/* Every array in this surface is fully typed, including its element shape.
 * That is not tidiness: the reference implementation's data corruption began
 * exactly where a parameter advertised "items": {}, because that tells a client
 * anything goes. A bounded integer array says what it holds. */
static struct json_object *u32_array_prop(const char *desc, unsigned cap,
                                          const char *suffix) {
    struct json_object *o = json_object_new_object();
    struct json_object *items = json_object_new_object();
    (void)suffix;
    json_object_object_add(o, "type", json_object_new_string("array"));
    json_object_object_add(o, "maxItems", json_object_new_int((int)cap));
    if (desc)
        json_object_object_add(o, "description", json_object_new_string(desc));
    json_object_object_add(items, "type", json_object_new_string("integer"));
    json_object_object_add(items, "minimum", json_object_new_int(0));
    json_object_object_add(o, "items", items);
    return o;
}

static struct json_object *bounded_prop(const char *desc, unsigned max) {
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "type", json_object_new_string("integer"));
    json_object_object_add(o, "minimum", json_object_new_int(0));
    json_object_object_add(o, "maximum", json_object_new_int((int)max - 1u));
    if (desc)
        json_object_object_add(o, "description", json_object_new_string(desc));
    return o;
}
static struct json_object *block_prop(const char *desc) {
    return bounded_prop(desc, QRMEM_BLOCKS_PER_SCREEN);
}
static struct json_object *slot_prop(const char *desc) {
    return bounded_prop(desc, QRMEM_SLOTS_PER_BLOCK);
}
static struct json_object *planeprop(const char *desc) {
    return bounded_prop(desc, QRMEM_PLANE_DIM);
}


static void finish_tool(struct json_object *t, struct json_object *props,
                        const char **req, int nreq) {
    struct json_object *schema = json_object_new_object();
    json_object_object_add(schema, "additionalProperties",
                           json_object_new_boolean(0));
    json_object_object_add(schema, "properties", props);
    if (nreq) {
        struct json_object *ra = json_object_new_array();
        for (int i = 0; i < nreq; i++)
            json_object_array_add(ra, json_object_new_string(req[i]));
        json_object_object_add(schema, "required", ra);
    }
    json_object_object_add(schema, "type", json_object_new_string("object"));
    json_object_object_add(t, "inputSchema", schema);
}

static struct json_object *err_obj(const char *fmt, ...) {
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "error", json_object_new_string(msg));
    return o;
}

static const char *arg_str(struct json_object *a, const char *k,
                           const char *dflt) {
    struct json_object *v = NULL;
    if (a && json_object_object_get_ex(a, k, &v) &&
        json_object_get_type(v) == json_type_string)
        return json_object_get_string(v);
    return dflt;
}

static int arg_int(struct json_object *a, const char *k, long dflt,
                   long *out) {
    struct json_object *v = NULL;
    if (a && json_object_object_get_ex(a, k, &v) &&
        (json_object_get_type(v) == json_type_int ||
         json_object_get_type(v) == json_type_double)) {
        *out = (long)json_object_get_int64(v);
        return 1;
    }
    *out = dflt;
    return 0;
}


/* ------------------------------------------------------------------ tool list */

/* The tile verbs, from the design brief: join, list, read, write, link, move,
 * copy, supersede, decode a region, view a tile, index, and prepare a durable
 * payload. Nothing here writes SQL, and nothing here writes to the database at
 * all: commit_payload only PREPARES a payload for the agent to hand to the
 * SHAMPOO tools. */
static const char *help_topic_list(void);

static struct json_object *tools_list(void) {
    struct json_object *arr = json_object_new_array();
    struct json_object *t, *p;
    const char *r[6];
    char hdesc[1024];

    snprintf(hdesc, sizeof hdesc,
             "How this fabric works: one focused brief per topic.\n\n"
             "Read this before writing anything. Every refusal this server "
             "produces is explained under topic='troubleshooting'. The answer "
             "also states which screens you own and which are free, so it is "
             "safe to call at any time, and it never returns the whole "
             "manual - ask for one topic at a time.\n\n"
             "Topics: %s.", help_topic_list());

    t = tool_desc("qrmem_help", hdesc);
    p = json_object_new_object();
    json_object_object_add(
        p, "topic",
        strprop(help_topic_list()));
    finish_tool(t, p, NULL, 0);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_status",
                  "Fabric status: aperture path, epoch, era, agent slot, and "
                  "per-screen owner, generation, index occupancy and RGB-plane "
                  "geometry.\n\n"
                  "Pure reads, zero writes. Start here: a screen with no owner "
                  "is a screen nobody has joined yet.");
    p = json_object_new_object();
    finish_tool(t, p, NULL, 0);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_mark_baseline",
                  "Declare the current state of a screen as the blue CHANGE "
                  "plane baseline. Existing blue pixels are cleared; later "
                  "writes to that screen mark only their own viewport blue. "
                  "Requires ownership and does not change any record or QR.");
    p = json_object_new_object();
    json_object_object_add(p, "screen", screen_prop("Screen to baseline"));
    r[0] = "screen";
    finish_tool(t, p, r, 1);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_join",
                  "Join the fabric and claim a tile.\n\n"
                  "Claims `screen` for this agent id. One writer per screen: a "
                  "claim on a screen someone else owns is refused, not queued. "
                  "Claiming a screen you already own is idempotent, so a "
                  "reconnecting agent does not have to remember. Joining does "
                  "not wipe the screen: an agent that joins later immediately "
                  "reads what earlier agents wrote.");
    p = json_object_new_object();
/* No `agent` argument. Identity comes from the lease this process holds,
     * never from a name in the call: a caller-supplied agent name was a way to
     * CLAIM an identity rather than prove one, and it is the same confusion the
     * fenced (authority_gen, slot, agent_gen) triple exists to remove. */
    json_object_object_add(p, "screen", screen_prop("Screen to claim"));
    json_object_object_add(p, "project",
                           strprop("Project label for this page. Mutable "
                                   "only while the page has no published "
                                   "records."));
    r[0] = "screen";
    r[1] = "project";
    finish_tool(t, p, r, 2);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_leave",
                  "Release a tile this agent owns. The cells stay readable; "
                  "only the right to write goes away.");
    p = json_object_new_object();
    json_object_object_add(p, "screen", screen_prop("Screen to release"));
    r[0] = "screen";
    finish_tool(t, p, r, 1);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_write",
                  "Publish one record into a tile you own.\n\n"
                  "The cell is published atomically: a reader sees the whole "
                  "record or none of it, never a half-written one. `type` is "
                  "word | idea | fact | ptr. Text is UTF-8. Tokens are token "
                  "ids. A fact additionally carries subject/relation/object and "
                  "a status.");
    p = json_object_new_object();
    json_object_object_add(p, "screen", screen_prop("Screen to write"));
    json_object_object_add(p, "block", block_prop("Coded block, 0..15."));
    json_object_object_add(p, "slot", slot_prop("Slot within the block, 0..4."));
    json_object_object_add(
        p, "type",
        strprop("word | idea | ptr. `fact` is part of the vocabulary but is "
                "REFUSED before any write: its subject/relation/object token "
                "semantics are not yet defined, and a stored triple of "
                "meaningless integers is indistinguishable from a real "
                "assertion. Use word or idea."));
    json_object_object_add(p, "id",
                           uuid4_prop("Canonical UUIDv4 identifying this "
                                      "record. Omit to have one minted."));
    json_object_object_add(p, "text", strprop("UTF-8 text payload."));
    json_object_object_add(
        p, "tokens", u32_array_prop("Token ids, bounded by the cell.", 48, ""));
    json_object_object_add(
        p, "subject",
        intprop("fact only, and fact is currently refused: subject token."));
    json_object_object_add(
        p, "relation",
        intprop("fact only, and fact is currently refused: relation token."));
    json_object_object_add(
        p, "object",
        intprop("fact only, and fact is currently refused: object token."));
    json_object_object_add(
        p, "status",
        strprop("unknown | witnessed | supported | refuted."));
    json_object_object_add(p, "source", intprop("Provenance token."));
    json_object_object_add(
        p, "links",
        uuid4_array_prop("Canonical UUIDv4s of linked records.", 4));
    json_object_object_add(p, "index",
                           strprop("Optional lookup key. Indexing this record "
                                   "makes it findable by qrmem_index. One key "
                                   "per write."));
    r[0] = "screen";
    r[1] = "block";
    r[2] = "slot";
    r[3] = "type";
    /* `id` is NOT required, and that was a real defect rather than a style
     * preference. The server mints a canonical UUIDv4 when `id` is omitted, and
     * the help says so - but the schema listed id as required, and a client
     * generates its calls from the SCHEMA rather than from the prose. So the
     * published contract told every schema-driven agent to do the work the
     * server was offering to do, and left it free to invent a non-canonical id
     * and eat the refusal. Prose and runtime agreed; the schema was the outlier
     * and the schema is what gets believed. */
    finish_tool(t, p, r, 4);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_read",
                  "Read one cell. Every agent may read every screen.\n\n"
                  "Returns the record with its decoded fields. A cell that was "
                  "never written, or has been cleared, reports empty rather "
                  "than inventing a value.");
    p = json_object_new_object();
    json_object_object_add(p, "screen", screen_prop("Screen"));
    json_object_object_add(p, "block", block_prop("Coded block, 0..15."));
    json_object_object_add(p, "slot", slot_prop("Slot within the block, 0..4."));
    r[0] = "screen";
    r[1] = "block";
    r[2] = "slot";
    finish_tool(t, p, r, 3);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_decode_region",
                  "Decode a rectangular window of a screen.\n\n"
                  "The inspection verb: returns every published record in the "
                  "window with its block and slot, so a reader can see a region "
                  "rather than guess which records to ask for.\n\n"
                  "The window is measured in RECORDS from (block, slot) onwards, "
                  "in record order, wrapping into the next block at the end of a "
                  "block. These are not plane coordinates: use qrmem_view_tile to "
                  "look at where a block is drawn.");
    p = json_object_new_object();
    json_object_object_add(p, "screen", screen_prop("Screen"));
    json_object_object_add(p, "block", block_prop("First block of the window, 0..15."));
    json_object_object_add(p, "slot", slot_prop("First slot of the window, 0..4."));
    json_object_object_add(p, "width", intprop("Window width in records."));
    json_object_object_add(p, "height", intprop("Window height in records."));
    r[0] = "screen";
    r[1] = "block";
    r[2] = "slot";
    r[3] = "width";
    r[4] = "height";
    finish_tool(t, p, r, 5);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_view_tile",
                  "Render a window of the red QR plane as text, one character "
                  "per display pixel.\n\n"
                  "Each screen is a 4096x4096 one-bit plane. Eighty records "
                  "occupy a deterministic 10-column by 8-row grid: one genuine "
                  "QR Code per (block, slot). '.' is white and '#' is black. "
                  "This view is for diagnostics; export the red plane alone for "
                  "a phone scanner.\n\n"
                  "Window coordinates are PLANE MODULES, which is a different "
                  "space from the block/slot coordinates records are addressed "
                  "by. To read a record use qrmem_read; to list a region use "
                  "qrmem_decode_region.");
    p = json_object_new_object();
    json_object_object_add(p, "screen", screen_prop("Screen"));
    json_object_object_add(p, "x", planeprop("Window origin column in display pixels, 0..4095."));
    json_object_object_add(p, "y", planeprop("Window origin row in display pixels, 0..4095."));
    json_object_object_add(p, "width", intprop("Window width in display pixels; 4096 output characters maximum."));
    json_object_object_add(p, "height", intprop("Window height in display pixels; 4096 output characters maximum."));
    r[0] = "screen";
    r[1] = "x";
    r[2] = "y";
    r[3] = "width";
    r[4] = "height";
    finish_tool(t, p, r, 3);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_link",
                  "Add a link from a record to another record id, in a tile you "
                  "own.\n\n"
                  "A cell holds at most four links. A full link set is refused "
                  "rather than silently dropping one.");
    p = json_object_new_object();
    json_object_object_add(p, "screen", screen_prop("Screen"));
    json_object_object_add(p, "block", block_prop("Coded block, 0..15."));
    json_object_object_add(p, "slot", slot_prop("Slot within the block, 0..4."));
    json_object_object_add(p, "target_id",
                           strprop("Canonical UUIDv4 of the record to link "
                                   "to."));
    r[0] = "screen";
    r[1] = "block";
    r[2] = "slot";
    r[3] = "target_id";
    finish_tool(t, p, r, 4);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_copy",
                  "Copy a record between two cells you own.\n\n"
                  "Both screens must be yours: a copy out of another agent's "
                  "tile would land in your tile under your authorship, which is "
                  "precisely what the one-writer rule exists to prevent.\n\n"
                  "A COPY MINTS A NEW IDENTITY and links the record it was "
                  "copied from, so no two live records ever share a UUIDv4. The "
                  "reply names the new id and the link. If you expected the id "
                  "to be preserved, use qrmem_move instead.");
    p = json_object_new_object();
    json_object_object_add(p, "from_screen", screen_prop("Source screen"));
    json_object_object_add(p, "from_block", block_prop("Source block."));
    json_object_object_add(p, "from_slot", slot_prop("Source slot."));
    json_object_object_add(p, "to_screen", intprop("Destination screen."));
    json_object_object_add(p, "to_block", block_prop("Destination block."));
    json_object_object_add(p, "to_slot", slot_prop("Destination slot."));
    r[0] = "from_screen";
    r[1] = "from_block";
    r[2] = "from_slot";
    r[3] = "to_screen";
    r[4] = "to_block";
    r[5] = "to_slot";
    finish_tool(t, p, r, 6);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_move",
                  "Move a record between two cells you own.\n\n"
                  "The destination is published before the source is marked "
                  "superseded, so an interrupted move leaves the record in "
                  "exactly one place rather than none.\n\n"
                  "A MOVE PRESERVES IDENTITY: it is the same record at a new "
                  "address, so (screen, block, slot) changes and the UUIDv4 does "
                  "not. The reply confirms the id survived. Use qrmem_copy when "
                  "you want a NEW record rather than the same one elsewhere.");
    p = json_object_new_object();
    json_object_object_add(p, "from_screen", screen_prop("Source screen"));
    json_object_object_add(p, "from_block", block_prop("Source block."));
    json_object_object_add(p, "from_slot", slot_prop("Source slot."));
    json_object_object_add(p, "to_screen", intprop("Destination screen."));
    json_object_object_add(p, "to_block", block_prop("Destination block."));
    json_object_object_add(p, "to_slot", slot_prop("Destination slot."));
    r[0] = "from_screen";
    r[1] = "from_block";
    r[2] = "from_slot";
    r[3] = "to_screen";
    r[4] = "to_block";
    r[5] = "to_slot";
    finish_tool(t, p, r, 6);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_supersede",
                  "Mark a record superseded in place.\n\n"
                  "The cell keeps answering with its id, so a reader can tell "
                  "'superseded' from 'never existed'. Pass successor_id to "
                  "record what replaced it.");
    p = json_object_new_object();
    json_object_object_add(p, "screen", screen_prop("Screen"));
    json_object_object_add(p, "block", block_prop("Coded block, 0..15."));
    json_object_object_add(p, "slot", slot_prop("Slot within the block, 0..4."));
    json_object_object_add(
        p, "successor_id",
        uuid4_prop("Canonical UUIDv4 of the record that replaced this one. "
                   "Omit to record no successor."));
    r[0] = "screen";
    r[1] = "block";
    r[2] = "slot";
    finish_tool(t, p, r, 3);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_index",
                  "Look up indexed cells by key.\n\n"
                  "Reads the screen's bounded key table rather than scanning "
                  "cells, and never falls back to a scan: a miss is reported as "
                  "a miss. A scan is the cost the index exists to avoid, and a "
                  "helpful fallback would quietly reintroduce it.");
    p = json_object_new_object();
    json_object_object_add(p, "screen", screen_prop("Screen"));
    json_object_object_add(p, "key", strprop("Key to look up."));
    json_object_object_add(
        p, "limit", intprop("Maximum cells to return. Default 16."));
    r[0] = "screen";
    r[1] = "key";
    finish_tool(t, p, r, 2);
    json_object_array_add(arr, t);

    t = tool_desc("qrmem_commit_payload",
                  "Prepare a durable SHAMPOO payload from a cell, WITHOUT "
                  "writing anything.\n\n"
                  "The fabric holds no database, so it cannot make a fact "
                  "durable. This reads a record and returns the entity name, "
                  "observations and project you should pass to the ordinary "
                  "memory tools. Promotion is an explicit agent decision: "
                  "scratch stays scratch until you make it.");
    p = json_object_new_object();
    json_object_object_add(p, "screen", screen_prop("Screen"));
    json_object_object_add(p, "block", block_prop("Coded block, 0..15."));
    json_object_object_add(p, "slot", slot_prop("Slot within the block, 0..4."));
    json_object_object_add(
        p, "entity_name",
        strprop("Entity name to record this fact under."));
    json_object_object_add(p, "project", strprop("Project tag."));
    r[0] = "screen";
    r[1] = "block";
    r[2] = "slot";
    finish_tool(t, p, r, 3);
    json_object_array_add(arr, t);

    return arr;
}


/* Descriptive host name for human-readable qualified addresses.
 *
 * Falls back to the kernel hostname when --host is not given. It is NEVER used
 * to decide identity: a host can be renamed, and the aperture pathname is
 * identical across machines, so anything derived from here would collide. The
 * fabric_id is the only thing that distinguishes two fabrics. */
static void host_default(char *out, size_t cap) {
    if (gethostname(out, cap) != 0)
        snprintf(out, cap, "unknown");
    out[cap - 1] = '\0';
}

/* The session context. Declared before qrmem_help because help answers with
 * which screens the caller owns, which is a question about this struct. */
typedef struct {
    qrmem_ap_t ap;
    uint32_t agent;
    uint32_t agent_gen; /* allocation generation: slot alone is not identity */
    uint32_t authority_gen; /* daemon incarnation at the moment of leasing */
    char agent_name[QRMEM_AGENT_NAME_MAX]; /* the unique identity */
    char agent_label[QRMEM_AGENT_NAME_MAX]; /* what the operator asked for */
    char agent_host[256]; /* descriptive only: never identity-bearing */
    char aperture[512];  /* shm NAME, e.g. /saphira-qrmem-1000 */
    char aperture_path[600]; /* the same segment as an operator sees it */
    char snapshot[QRMEM_SNAPSHOT_MAX_PATH]; /* empty disables saving */
} qrmem_ctx_t;

/* This session's fenced identity.
 *
 * authority_gen is the value learned when the lease was taken, NOT the live
 * header value. Reading it live would erase the fence: a restarted daemon
 * raises the header's authority_gen, and a client that adopted the new number
 * would carry on writing as if nothing happened, which is precisely the dead
 * incarnation the fence exists to refuse. Holding the old number means every
 * operation fails closed and the client re-hellos. */
static qrmem_id_t ctx_id(const qrmem_ctx_t *c) {
    qrmem_id_t id;
    id.authority_gen = c ? c->authority_gen : 0u;
    id.slot = c ? c->agent : 0u;
    id.agent_gen = c ? c->agent_gen : 0u;
    return id;
}

/* ------------------------------------------------------------------- qrmem_help
 *
 * A help TOOL rather than only server instructions, for two reasons.
 *
 *  1. Server instructions are returned once, in initialize, and they compete for
 *     attention with everything else in the session. A tool is callable at the
 *     moment the question actually arises.
 *  2. One brief per topic instead of one wall. The decode_region cap exists
 *     because a tool that returns a whole screen floods the caller; a help tool
 *     that returned the whole manual would commit the same offence against the
 *     agent that most needs to read it.
 *
 * The corpus is deliberately concrete: what to do, which invariant matters, and
 * what will be refused. Every refusal quoted under troubleshooting is one this
 * codebase actually produces.
 */

/* Help briefs are BUILT FROM THE CONSTANTS, not written as prose.
 *
 * Every number an agent reads here used to be a literal in a string. The schema
 * said "0..7" while the fabric had sixteen screens, so ten screens were
 * undiscoverable from tools/list; the help said the index held 2048 entries
 * while the header allocated 512; and both said connected agents expired after
 * five minutes, which is not a thing that ever happened - lease_hold has been the
 * authority on liveness since the descriptor became the lease, and a connected
 * agent may sit idle for hours without losing anything.
 *
 * Those are not typos. They are the predictable consequence of stating a fact in
 * two places: the code changes and the prose does not. So the numbers below are
 * formatted from the same constants the geometry is computed from, and a help
 * text that disagrees with the fabric is no longer expressible.
 *
 * The %u arguments are supplied once, in help_topics_init(), which runs before
 * the first help call. Help is read far more often than the fabric is rebuilt, so
 * building the corpus once is not a measurable cost and it keeps every caller from
 * having to pass seven arguments.
 *
 * The corpus is deliberately concrete: what to do, which invariant matters, and
 * what will be refused. Every refusal quoted under troubleshooting is one this
 * codebase actually produces.
 */
typedef struct {
    const char *topic;
    char brief[8192];
} qrmem_help_topic_t;

/* The topic list, in reading order. The corpus itself is filled in by
 * help_topics_init() because it needs the constants. */
static qrmem_help_topic_t qrmem_help_topics[] = {
    {"overview", {0}},   {"getting-started", {0}}, {"ownership", {0}},
    {"records", {0}},    {"indexing", {0}},        {"projects", {0}},
    {"presence", {0}},   {"qualifying", {0}},     {"durability", {0}},
    {"troubleshooting", {0}},
};

static const size_t qrmem_help_ntopics =
    sizeof qrmem_help_topics / sizeof qrmem_help_topics[0];

static int qrmem_help_ready;

/* The `instructions` field every client receives at initialize, generated from
 * the same sources as help and status.
 *
 * This existed as a hand-written literal and was wrong three ways while qrmem_help
 * had already been corrected: it said "Eight screens" against a fabric of 16, it
 * listed 7 topics against 9 real ones, and it claimed the fabric holds NO durable
 * state when there is a restore point that returns content and labels on every
 * start. The drift was not carelessness so much as two surfaces with no shared
 * source: fixing help could not fix instructions, and nobody noticed until an
 * agent bootstrapped from instructions and repeated beliefs that had already been
 * corrected elsewhere.
 *
 * So the screen count, the topic list and the durability sentence are all derived
 * from the constants and the topic table. There is no longer a number in prose
 * that can disagree with the number in the binary. */
static void instructions_text(char *out, size_t outlen) {
    char topics[256];
    size_t n = 0;
    topics[0] = '\0';
    for (size_t i = 0; i < qrmem_help_ntopics; i++) {
        const char *name = qrmem_help_topics[i].topic;
        size_t len = strlen(name);
        if (n + len + 2u >= sizeof topics)
            break;
        n += (size_t)snprintf(topics + n, sizeof topics - n, "%s%s",
                              i ? ", " : "", name);
    }
    snprintf(out, outlen,
             "Saphira tile fabric. %u screens of shared memory. One agent owns "
             "each screen and is its only writer; every agent can read every "
             "screen live, with no publish step and no waiting.\n\n"
             "CALL qrmem_help FIRST. It has one focused brief per topic "
             "(%s) and it answers with which screens you own and which are "
             "free, so start with topic='overview' and then 'getting-started'. "
             "Everything below assumes you have.\n\n"
             "The three things that surprise people:\n"
             "  - Reads are never gated; writes always are. Another agent's "
             "screen is fully readable but refusing to write to.\n"
             "  - Your identity is not your --agent label. Each process mints "
             "a unique identity from it (opencode#a3f19c2b), so two sessions "
             "with the same label are different writers.\n"
             "  - This fabric holds NO database, and it keeps no database. It "
             "DOES keep a durable restore point: record content, project "
             "labels and the writes counter return across a restart, while "
             "authority, ownership and leases are always re-minted and never "
             "restored. So a screen you were writing to yesterday needs "
             "re-joining today. See topic='durability'.\n\n"
             "This surface is the CONTROL PLANE: it inspects and administers "
             "the fabric. A process in this uid can read cells straight out of "
             "shared memory instead, at no token cost; that is the hot path "
             "and this is not it.",
             (unsigned)QRMEM_SCREENS, topics);
}



/* Read a screen's project label for the readable part of an address. Returns
 * "" for an unlabelled screen rather than failing: the label is descriptive,
 * and a missing label must not stop a reference from being qualified. */
static void screen_project(const qrmem_ctx_t *c, uint32_t screen, char *out,
                           size_t cap) {
    uint32_t plen = 0;
    if (out && cap)
        out[0] = '\0';
    if (!out || !cap || screen >= QRMEM_SCREENS)
        return;
    plen = atomic_load_explicit(&c->ap.screens[screen].project_len,
                                memory_order_acquire);
    if (plen > QRMEM_PROJECT_MAX)
        plen = QRMEM_PROJECT_MAX;
    if (plen == 0u)
        return;
    memcpy(out, c->ap.screens[screen].project, plen);
    out[plen] = '\0';
    out[cap - 1] = '\0';
}

/* A screen reference, qualified.
 *
 * A qrmem screen number is LOCAL. "screen 14" names a cell in whichever fabric
 * the reader happens to be attached to, so on its own it is not an address at
 * all - it is a number that will silently resolve to somebody else's cell on a
 * different machine. That is fine for talking to the fabric you are attached
 * to, which is all a bare number is ever good for, and fatal the moment the
 * reference is written somewhere durable and read by an agent attached to a
 * DIFFERENT fabric.
 *
 * The qualified address is (fabric_id, screen), and only that pair is
 * identity-bearing. host, aperture and project travel with it because they are
 * what makes the reference readable to a person, and all three can change:
 * a host can be renamed, an aperture moved, a project relabelled by an
 * operator. None of them may be used to decide whether two references are the
 * same place.
 *
 * Attached to every response that returns a screen coordinate, so an agent
 * never has to remember to qualify. The alternative - qualifying in help and
 * hoping - is how a bare number reached durable storage in the first place. */
static int screen_ref_json(struct json_object *o, const qrmem_ctx_t *c,
                           uint32_t screen, const char *project) {
    qrmem_uuid_t fid;
    char idtxt[40];
    if (qrmem_fabric_id(&c->ap, &fid) != 0 ||
        qrmem_uuid_text(&fid, idtxt, sizeof idtxt) != 0)
        return -1;
    json_object_object_add(o, "fabric_id", json_object_new_string(idtxt));
    json_object_object_add(o, "screen", json_object_new_int64((int64_t)screen));
    {
        /* One string an operator or agent can read whole, with the descriptive
         * metadata clearly marked as descriptive. */
        /* Sized from the fields rather than guessed, because a guessed one
         * becomes a truncation warning or, worse, a silently clipped
         * aperture name - and a clipped fabric id is worse than none. */
        char addr[QRMEM_UUID_TEXT_LEN + 256u + 512u +
                    QRMEM_PROJECT_MAX + 96u];
        snprintf(addr, sizeof addr,
                 "fabric=%s host=%s aperture=%s screen=%u%s%s",
                 idtxt, c->agent_host[0] ? c->agent_host : "?",
                 c->aperture[0] ? c->aperture : "?", (unsigned)screen,
                 (project && project[0]) ? " project=" : "",
                 (project && project[0]) ? project : "");
        json_object_object_add(o, "address", json_object_new_string(addr));
    }
    if (project && project[0])
        json_object_object_add(o, "project", json_object_new_string(project));
    return 0;
}

/* The topic set, as one string, generated from the topic table.
 *
 * The tool description and the "Topics:" line used to hand-list the topics, and
 * they had already drifted once: a `qualifying` brief was added to the table
 * while this list still described the old set. Help text that enumerates its
 * own topics is a list that has to be maintained by hand, and it will be wrong
 * again. There is now no place to forget. */
static const char *help_topic_list(void) {
    static char buf[512];
    size_t n = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < qrmem_help_ntopics; i++) {
        const char *nm = qrmem_help_topics[i].topic;
        size_t len = strlen(nm);
        if (n + len + 2u >= sizeof buf)
            break;
        n += (size_t)snprintf(buf + n, sizeof buf - n, "%s%s", i ? ", " : "", nm);
    }
    return buf;
}

/* Fill topic `i`. Split out so the corpus reads as prose rather than as a wall of
 * printf arguments. */
static void help_body(size_t i, char *out, size_t outlen, unsigned screens,
                      unsigned plane_dim, unsigned block_dim,
                      unsigned blocks_per_screen, unsigned slots_per_block,
                      unsigned records_per_screen, unsigned cell_body,
                      unsigned cell_links, unsigned index_entries,
                      unsigned agent_max, unsigned project_max,
                      unsigned uuid_bytes, unsigned cell_bytes) {
    switch (i) {
    case 0: /* overview */
        snprintf(out, outlen,
                 "A tile fabric is shared memory divided into %u screens. Each "
                 "screen is a %ux%u module CODE PLANE holding %u %ux%u coded "
                 "blocks, and each block holds %u records, so a screen is %u "
                 "records. One agent OWNS each screen and is its only writer. "
                 "Every agent may read every screen, live, without asking.\n\n"
                 "Two coordinate spaces, and confusing them is the main way to "
                 "get this wrong:\n"
                 "  - RECORDS are addressed by (screen, block, slot): block "
                 "0..%u, slot 0..%u.\n"
                 "  - the PLANE is addressed in modules, 0..%u each way, and "
                 "says where a block is DRAWN.\n"
                 "Plane coordinates are not a record address. qrmem_read takes "
                 "block/slot; qrmem_view_tile takes plane x/y.\n\n"
                 "A record has TWO separate names, and keeping them apart is the "
                 "whole trick:\n"
                 "  (screen, block, slot) is WHERE it lives RIGHT NOW.\n"
                 "  id is a UUIDv4 - WHICH record it is, wherever it goes.\n"
                 "A move changes the address and keeps the id. A copy mints a new "
                 "id and links the record it came from, so no two live records "
                 "ever share one identity.\n\n"
                 "The rule that makes it work: a tile belongs to ONE writer, but "
                 "its contents are live to every reader. So you never wait for "
                 "another agent to publish anything - you read their tile "
                 "whenever you like.\n\n"
                 "A record holds: type word | idea | ptr, a UUIDv4 id, up to %u "
                 "bytes of TLV body, and up to %u links. Records are published "
                 "atomically, so a reader sees the whole record or none of it - "
                 "%u bytes per cell, %u padded for alignment.\n\n"
                 "Every record is also DRAWN: the records of a block become the "
                 "block's %u bits, one bit per module, and decoding the block "
                 "reproduces the records byte for byte. The picture is not a "
                 "summary of memory, it is the memory, drawn.",
                 screens, plane_dim, plane_dim, blocks_per_screen, block_dim,
                 block_dim, slots_per_block, records_per_screen,
                 blocks_per_screen - 1u, slots_per_block - 1u, plane_dim - 1u,
                 cell_body, cell_links, cell_bytes, cell_bytes,
                 block_dim * block_dim);
        break;
    case 1: /* getting-started */
        snprintf(out, outlen,
                 "1. qrmem_status. Look at the screens array. It reports every "
                 "screen's owner, its project label, and how many records have "
                 "been written to it. Pick a screen whose owner is null.\n"
                 "2. qrmem_join that screen, with a project label: "
                 "qrmem_join(screen=N, project=\"my-work\"). The project is "
                 "optional and grants nothing - it is a description of what the "
                 "page is about, nothing more.\n"
                 "3. qrmem_write into it: (screen, block, slot, type, text). Omit "
                 "id and the fabric mints a UUIDv4 for you; pass one yourself if "
                 "you need to choose it.\n"
                 "4. qrmem_read or qrmem_decode_region to see it. Pass "
                 "index=<key> on the write if you want it findable by "
                 "qrmem_index.\n\n"
                 "Coordinates are yours to choose within your own screen. There "
                 "is no allocator: a screen is %u blocks of %u slots and you "
                 "address cells directly. Nothing is overwritten unless you "
                 "write the same cell twice.",
                 blocks_per_screen, slots_per_block);
        break;
    case 2: /* ownership */
        snprintf(out, outlen,
                 "One writer per screen. A claim on a screen someone else owns "
                 "is REFUSED, not queued. Re-claiming a screen you already own "
                 "is idempotent, so a reconnecting agent does not have to "
                 "remember whether it already joined.\n\n"
                 "YOUR IDENTITY IS NOT YOUR LABEL. Each process mints a unique "
                 "identity from its --agent label, looking like "
                 "opencode#a3f19c2b, and that is what the fabric registers. Two "
                 "sessions with the same label are different agents with "
                 "different screens. This matters because the one-writer rule is "
                 "enforced per identity: sessions sharing an identity would also "
                 "share write authority, and the rule would be void.\n\n"
                 "A process holds exactly one identity, taken from its lease with "
                 "the daemon. There is no agent argument anywhere in this API: a "
                 "caller that could name who it acts as could act as anyone.\n\n"
                 "IDENTITY IS LEASE-SCOPED, AND THAT IS CORRECT. The invariant "
                 "is: one live lease has one stable identity; a new lease, a "
                 "reconnect, or a daemon restart is allowed a new one. Seeing "
                 "opencode#a3f19c2b become opencode#7c2e91f4 is not a bug - it "
                 "is three lease incarnations.\n\n"
                 "What was wrong was never that identity changed. It was that "
                 "identity was ever treated as a durable agent handle. Do not: "
                 "attribute durable work to it. A record's own UUID is durable; "
                 "an identity is a property of a connection.\n\n"
                 "WRITE AUTHORITY IS A FENCED TRIPLE: "
                 "(authority_gen, slot, agent_gen). All three must match "
                 "exactly. The slot number alone is not authority, and this is "
                 "not pedantry - it is what stops a reclaimed slot from handing "
                 "its predecessor's screen to whoever draws the number next.\n\n"
                 "authority_gen is the DAEMON'S INCARNATION. When the daemon "
                 "restarts it increments, and every identity leased from the old "
                 "one becomes unable to write. That is the point: after a restart "
                 "there are no live writers, and an agent that survived the "
                 "restart must re-lease rather than carry on writing under a "
                 "dead authority. qrmem_status reports authority_gen and "
                 "authority_current so you can see whether you are current.\n\n"
                 "CONNECTION IS THE LEASE, NOT A TIMEOUT. The daemon learns an "
                 "agent is alive because its control socket is open; the kernel "
                 "closes that descriptor on exit or crash. A connected agent may "
                 "sit idle for as long as it likes and keeps its screen the whole "
                 "time - there is no inactivity expiry to work around, and no "
                 "heartbeat you have to send.\n\n"
                 "An UNLEASED registry slot is not a dead agent, only one that "
                 "has not connected yet, so the reclaim sweep also consults a "
                 "last-seen grace period before freeing it. If a join fails with "
                 "the registry full (%u slots), that sweep is what is happening.",
                 agent_max);
        break;
    case 3: /* records */
        snprintf(out, outlen,
                 "Three writable types, differing only in which fields you "
                 "bother to fill:\n"
                 "  word  - text or tokens. The common case.\n"
                 "  idea  - a hypothesis. Add status=unknown|witnessed|"
                 "supported|refuted.\n"
                 "  ptr   - a pointer to another cell, for building "
                 "structures.\n\n"
                 "A fourth, `fact`, is part of the vocabulary and is REFUSED "
                 "before anything is written. It would carry subject + relation "
                 "+ object as token ids, and the token vocabulary does not exist "
                 "yet - there is no way to mint a meaningful one. Storing three "
                 "integers that mean nothing would look exactly like a real "
                 "assertion, and a reader could not tell it from a sourced fact. "
                 "So qrmem_write refuses it before touching the cell and points "
                 "you at word or idea.\n\n"
                 "The cell body is %u bytes. %u of those are reserved for the "
                 "publication timestamp every record carries, so a text payload "
                 "may be up to %u bytes - fewer if the same record also carries "
                 "tokens, links, a status or an index key, each of which claims "
                 "its own header. A payload that does not fit is REFUSED, never "
                 "truncated, and the refusal quotes the caller limit rather than "
                 "the raw body size. Write several short records and link them "
                 "instead of one long one.\n\n"
                 "The timestamp is WALL-CLOCK CLOCK_REALTIME, not a monotonic "
                 "reading, so every record also reports written_unix and "
                 "age_seconds. Two honest limits on that: a clock stepped "
                 "backwards reports age_seconds null rather than a negative "
                 "age, and a record from before this field existed reports null "
                 "for both. `age_seconds` is ADVISORY - it answers HOW STALE "
                 "THIS IS and nothing stronger - and is not evidence of "
                 "when anything actually "
                 "happened. A caller cannot supply or override it.\n\n"
                 "IDS ARE UUIDS, NOT LABELS. `id` is a canonical lowercase "
                 "UUIDv4 (%u raw bytes stored), version nibble 4 and variant "
                 "nibble [89ab] both checked. Uppercase is refused rather than "
                 "normalised, because two spellings of one identity is the "
                 "ambiguity this exists to remove. Integers and labels are not "
                 "ids at all: `id: 1031` is refused, and it was accepted "
                 "before.\n\n"
                 "Omit id and the fabric mints one, so you never have to "
                 "generate a v4 yourself.\n\n"
                 "COPY MINTS, MOVE PRESERVES. qrmem_copy gives you a NEW record "
                 "with a new id, linked to the record it came from. qrmem_move "
                 "keeps the id and changes only the address. Both say which they "
                 "did in their reply, because an agent that assumed a copy keeps "
                 "the id would go on to link the original and find two live "
                 "records sharing one reference.\n\n"
                 "SUPERSEDE means 'this conclusion was retired'. The cell keeps "
                 "answering with its id and records the UUID of what replaced "
                 "it, so a reader can tell superseded from never-existed. Prefer "
                 "it over overwriting a record whose id other agents may already "
                 "have cited.\n\n"
                 "Links are references, not enforced references: you may link to "
                 "an id that does not exist yet, or ever. Nothing tells you it "
                 "is dangling, so if that matters, check the target yourself.",
                 cell_body, (unsigned)QRMEM_TLV_HDR + 8u,
                 (unsigned)QRMEM_CELL_CALLER_BYTES, uuid_bytes);
        break;
    case 4: /* indexing */
        snprintf(out, outlen,
                 "Each screen has a bounded key table, %u entries, holding "
                 "key-hash to cell pointers. qrmem_index reads that table instead "
                 "of scanning cells, and there is NO scan fallback: a miss is "
                 "reported as a miss. That is deliberate - a fallback scan would "
                 "reintroduce exactly the cost the index exists to avoid.\n\n"
                 "Pass index=<key> on qrmem_write and the record becomes "
                 "findable. One key per write.\n\n"
                 "A full table REFUSES the insert rather than evicting an entry "
                 "some other reader may be about to follow. Evicting would turn a "
                 "capacity limit into a wrong answer.\n\n"
                 "Worth internalising: a record you never indexed is invisible "
                 "to lookups, even though other agents can read it perfectly "
                 "well by coordinate. If you want something findable, index it at "
                 "write time.\n\n"
                 "To explore an area without knowing keys, use "
                 "qrmem_decode_region (records with coordinates) or "
                 "qrmem_view_tile (a compact glyph map).",
                 index_entries);
        break;
    case 7: /* qualifying a reference */
        snprintf(out, outlen,
                 "A SCREEN NUMBER IS LOCAL. \"screen 14\" names a cell in "
                 "whichever fabric the reader is attached to, so on its own it "
                 "is not an address - it is a number that will quietly resolve "
                 "to somebody else's cell on a different machine. Every "
                 "response that returns a screen coordinate also returns "
                 "fabric_id and a qualified `address` string, so you never have "
                 "to remember to qualify.\n\n"
                 "THE QUALIFIED ADDRESS IS (fabric_id, screen), and only that "
                 "pair is identity-bearing. host, aperture and project travel "
                 "alongside it because they make the reference readable to a "
                 "person, and all three can change: a host can be renamed, an "
                 "aperture moved, a project relabelled by an operator. Never "
                 "use them to decide whether two references name the same "
                 "place.\n\n"
                 "The fabric_id is minted once, from kernel entropy, when a "
                 "fabric is created. It is not derived from the hostname, the "
                 "uid, or the aperture path - the aperture path is IDENTICAL on "
                 "every host, so an id derived from it would give different "
                 "fabrics the same name. It survives a daemon restart and it "
                 "does NOT change when authority_gen changes: a restart retires "
                 "every lease, and the namespace it left behind is the same "
                 "namespace.\n\n"
                 "RULE FOR DURABLE KNOWLEDGE\n"
                 "A bare screen number MUST NOT be persisted into shared or "
                 "durable knowledge as an actionable reference. Write the "
                 "qualified address instead. If you read a reference that "
                 "carries only a screen number, you may READ it as history, but "
                 "you must NOT resolve that number against your own aperture - "
                 "it names a cell in someone else's fabric, and resolving it "
                 "locally is not a small error, it is an authorisation bug that "
                 "targets another agent's cell with total confidence and no "
                 "error at all.\n\n"
                 "Fabric identity is deliberately NOT in the snapshot. Copying a "
                 "snapshot to another machine would otherwise clone the "
                 "identity and leave two live fabrics claiming one namespace. "
                 "Migrating a fabric is an explicit operator action "
                 "(--recreate), never a side effect of copying a file.");
        break;
    case 5: /* projects */
        snprintf(out, outlen,
                 "Each screen may carry a PROJECT LABEL: up to %u bytes of "
                 "description, set by qrmem_join. It grants nothing and is not "
                 "an ACL. Two screens with the same label mean 'these are the "
                 "current pages for that project'.\n\n"
                 "It is mutable only while the screen holds no published "
                 "records. An empty page can be relabelled freely - correcting a "
                 "typo is harmless - but once a page has content, changing its "
                 "label would rewrite what it was about under every agent that "
                 "had found it. That is refused, and the fix is to open a new "
                 "page.\n\n"
                 "Overlength is refused, never truncated. A label that is quietly "
                 "cut to fit is a label two agents will disagree about.\n\n"
                 "qrmem_status reports the label of every screen. An unlabelled "
                 "screen reports project: null, which is a real state: not every "
                 "page belongs to a project.\n\n"
                 "The label is durable across a reboot, along with the page's "
                 "records. A label with no way to find its page would be an "
                 "orphan, so it is restored whenever the page is.",
                 project_max);
        break;
    case 6: /* presence */
        snprintf(out, outlen,
                 "qrmem_status reports `participants`: who is on this fabric "
                 "right now, and what each one owns.\n\n"
                 "Three fields per participant that are NOT interchangeable:\n"
                 "  label      the caller-chosen descriptor passed to --agent.\n"
                 "             Stable if you pass the same string, and worthless\n"
                 "             for attribution: every session launched as\n"
                 "             `opencode` carries the same one.\n"
                 "  identity   an EPHEMERAL LEASE INCARNATION. Changes across a\n"
                 "             reconnect or a daemon restart, by design.\n"
                 "  agent_gen  the fencing generation: the third element of\n"
                 "             (authority_gen, slot, agent_gen). Increments on\n"
                 "             every allocation, so two sequential occupants of\n"
                 "             one slot never share one.\n\n"
                 "Attribute durable work to the RECORD's UUID, which is durable, "
                 "and never to the identity that happened to be connected when it "
                 "was written.\n\n"
                 "It is presence, and nothing more. For each participant: "
                 "identity, label, slot, allocation generation, how many seconds "
                 "it has held its lease, which screens it owns, and where the "
                 "lease comes from (source_kind/source_host). Read-only - "
                 "there are no read receipts, no read tracking, and no social "
                 "graph. Nothing about a record says who looked at it, because "
                 "that turns a shared surface into a surveillance record and "
                 "changes how agents use it.\n\n"
                 "SOURCE IS AUTHORITY-KNOWN, NOT CALLER-CHOSEN. source_kind is "
                 "\"local\" for leases this daemon granted over its own control "
                 "socket, stamped at claim time - never read from the greeting, "
                 "because --agent and --host are caller-chosen and a source "
                 "derived from either would let any client claim any origin. "
                 "source_host is the authority's own hostname when the kind is "
                 "local, null otherwise. Today every lease is local, so a "
                 "remote participant is not merely unseen but impossible, and "
                 "the field says so by never varying. When a remote carrier "
                 "exists, its proxy will stamp its own kind with an identity it "
                 "verified (TLS client identity), through a new claim path - "
                 "not by passing a hostname through this one.\n\n"
                 "PARTICIPANTS AND OWNERS ARE DIFFERENT THINGS, and the report "
                 "keeps them apart:\n"
                 "  - a participant holds a lease, meaning its control socket is "
                 "open right now.\n"
                 "  - an owner holds write authority to a screen, which may "
                 "survive the owner disconnecting.\nAn agent can own a screen "
                 "while absent, and can be present while owning none. Each screen "
                 "reports owner.lease_held so you can tell an owner that is "
                 "actually here from one that is not.\n\n"
                 "AND THERE IS NO DELIVERY. There is no notify, no publish step, "
                 "and no read receipt. A sender cannot distinguish \"nobody has "
                 "read this\" from \"nobody is there\", and that is a real limit "
                 "rather than a bug to be fixed by instrumenting readers: a "
                 "sender that could confirm a read would change how agents use a "
                 "shared surface, and the cost of that is paid by everyone who "
                 "just wanted somewhere to think.\n\n"
                 "The honest workaround is a channel with actual reach. Writing a "
                 "message into shared memory is not the same as reaching an agent: "
                 "an agent that polls will eventually see it, and an agent that "
                 "does not poll never will. If you need to be sure a human or an "
                 "agent has your message, use a channel they already read at "
                 "session start, and put the screen coordinates in it so the two "
                 "worlds point at each other.\n\n"
                 "connected_seconds is measured against CLOCK_MONOTONIC and is "
                 "therefore local to this machine. It is the same caveat the "
                 "fabric's liveness accounting carries, and it is why presence "
                 "will need to come from the authority's own arrival timestamps "
                 "once remote agents are possible.");
        break;
    case 8: /* durability */
        snprintf(out, outlen,
                 "The fabric holds no database and no SQL - by design, and "
                 "asserted by the build and test gates.\n\n"
                 "PERSISTENCE. The aperture lives in /dev/shm, which is a tmpfs: "
                 "memory, wiped on reboot. The daemon therefore keeps a durable "
                 "restore point and reloads it at startup.\n\n"
                 "EXACTLY WHAT SURVIVES A RESTART:\n"
                 "  SURVIVES  record content, byte for byte\n"
                 "  SURVIVES  each record's UUIDv4 identity, so links and "
                 "supersessions still resolve\n"
                 "  SURVIVES  each record's index key, and the index table is "
                 "REBUILT from it\n"
                 "  SURVIVES  the project label on every page\n"
                 "  SURVIVES  each screen's generation and published-record "
                 "count, which is what makes a restored page\n"
                 "            immediately relabel-proof rather than looking empty\n"
                 "  DOES NOT SURVIVE  screen ownership. No agent is restored as "
                 "an owner.\n"
                 "  DOES NOT SURVIVE  leases. Every lease_hold is zeroed.\n"
                 "  DOES NOT SURVIVE  authority_gen. A fresh one is minted.\n"
                 "  DOES NOT SURVIVE  agent identities or agent_gen values. The "
                 "registry is empty.\n"
                 "  DOES NOT SURVIVE  tombstones. A supersession is a decision "
                 "made by an agent while\n"
                 "            alive, referencing a successor that will not be "
                 "there; restoring it would\n"
                 "            leave a reader following a reference into "
                 "nothing.\n\n"
                 "That asymmetry is the design, not an oversight. Restoring an "
                 "owner would hand WRITE AUTHORITY to whichever agent drew that "
                 "slot number next - the one failure the one-writer rule exists to "
                 "prevent, arriving through the durability path instead of the "
                 "leak path. So a reboot gives you the same pages and no dead "
                 "writers.\n"
                 "After a restart, every page needs re-joining, and every agent "
                 "needs a new identity.\n\n"
                 "The index key is worth one more sentence because it is a "
                 "derived-state decision. The index table lives in the aperture "
                 "and dies with it, so persisting it would mean persisting a "
                 "second structure that could disagree with the records it points "
                 "at. Instead the KEY is stored inside the record and the table is "
                 "rebuilt from it on restore. One source of truth. An earlier "
                 "version stored keys only in the table, and a restored record came "
                 "back readable by coordinate and invisible to qrmem_index - a "
                 "silent loss of its discovery handle.\n\n"
                 "The restore point is a restore point, not an archive: it "
                 "answers 'what did this machine know when it stopped' and is "
                 "replaced on each save. Long-term page history is a separate "
                 "question and is not faked here.\n\n"
                 "PROMOTION IS AN EXPLICIT DECISION. Being in the fabric is not "
                 "being in memory. The sequence is:\n\n"
                 "1. qrmem_read the cell, or qrmem_commit_payload which "
                 "assembles the payload for you.\n"
                 "2. Call the ORDINARY memory tools with it: create_entities for "
                 "the entity, add_observations for the body, and record the task "
                 "or note.\n\n"
                 "qrmem_commit_payload does step 1 only. It returns entity_name, "
                 "observations and project, and reports write_performed: false - "
                 "it prepares, it does not save. The fabric cannot make a fact "
                 "durable in the authoritative store, so that decision is "
                 "yours.\n\n"
                 "commit_payload refuses a superseded cell and tells you to "
                 "promote its successor instead; the successor id is in the "
                 "tomb's successor_id.");
        break;
    default: /* troubleshooting */
        snprintf(out, outlen,
                 "Every message below is one this server actually produces, with "
                 "its real numbers.\n\n"
                 "'screen N does not exist (0..%u)' - there are %u screens.\n\n"
                 "'block B does not exist (0..%u)' - a screen has %u blocks. "
                 "Those are RECORD coordinates, not plane coordinates.\n\n"
                 "'slot S does not exist (0..%u)' - a block holds %u records.\n\n"
                 "'window (X,Y WxH) does not fit a %ux%u plane' - that is a "
                 "PLANE window, so coordinates are 0..%u.\n\n"
                 "'screen N is not yours to write' - another agent owns it. Pick "
                 "a screen whose owner is null, or leave first. This is the "
                 "one-writer rule working, not a bug. The same refusal after a "
                 "daemon restart means your lease predates the current authority: "
                 "restart your session.\n\n"
                 "'screen N already has a writer; a tile belongs to one writer' - "
                 "same cause, at claim time.\n\n"
                 "'id must be a canonical UUIDv4 string ...' - your id was an "
                 "integer, a label, uppercase, or a non-v4 UUID. Omit it and one "
                 "will be minted.\n\n"
                 "'fact records are temporarily unavailable ... No record was "
                 "written.' - use word or idea.\n\n"
                 "'the fields of this record do not fit: %u bytes are left "
                 "for the caller after the publication timestamp is reserved' "
                 "- that budget is shared by text, tokens, links, status and the "
                 "index key, each of which claims its own header. Write shorter "
                 "records, or fewer links per record.\n\n"
                 "'record ... already carries %u links' - a cell holds that "
                 "many.\n\n"
                 "'the fabric already has %u agents' - the registry filled. It "
                 "self-sweeps unleased slots that have gone quiet, and "
                 "qrmem_status reports agents_reclaimable. A CONNECTED agent is "
                 "never swept: the socket is the lease.\n\n"
                 "'cell ... did not settle after 64 attempts; its writer is still "
                 "publishing' - a write was in flight every time you looked. "
                 "Read again. The fabric declines to invent a record rather than "
                 "hand you a partial one.\n\n"
                 "'fabric byte order 0x...., this host is 0x....' or 'fabric ABI "
                 "major N' - the segment belongs to a different build. Ask the "
                 "daemon owner to restart it; do not delete it.\n\n"
                 "'the stored record identity is not a canonical UUIDv4' - a cell "
                 "written by a pre-ABI-4 build, or corrupted. The content is "
                 "readable but that record cannot be linked to or superseded by "
                 "id.",
                 screens - 1u, screens, blocks_per_screen - 1u,
                 blocks_per_screen, slots_per_block - 1u, slots_per_block,
                 plane_dim, plane_dim, plane_dim - 1u,
                 (unsigned)QRMEM_CELL_CALLER_BYTES, cell_links, agent_max);
        break;
    }
}

static void help_topics_init(void) {
    unsigned screens = QRMEM_SCREENS;
    unsigned plane_dim = QRMEM_PLANE_DIM;
    unsigned block_dim = QRMEM_BLOCK_DIM;
    unsigned blocks_per_screen = QRMEM_BLOCKS_PER_SCREEN;
    unsigned slots_per_block = QRMEM_SLOTS_PER_BLOCK;
    unsigned records_per_screen = QRMEM_RECORDS_PER_SCREEN;
    unsigned cell_body = QRMEM_CELL_BODY;
    unsigned cell_links = QRMEM_CELL_LINKS;
    unsigned index_entries = QRMEM_INDEX_ENTRIES;
    unsigned agent_max = QRMEM_AGENT_MAX;
    unsigned project_max = QRMEM_PROJECT_MAX;
    unsigned uuid_bytes = QRMEM_UUID_BYTES;
    unsigned cell_bytes = QRMEM_CELL_BYTES;
    size_t i;
    if (qrmem_help_ready)
        return;
    for (i = 0; i < qrmem_help_ntopics; i++)
        help_body(i, qrmem_help_topics[i].brief,
                  sizeof qrmem_help_topics[i].brief, screens, plane_dim,
                  block_dim, blocks_per_screen, slots_per_block,
                  records_per_screen, cell_body, cell_links, index_entries,
                  agent_max, project_max, uuid_bytes, cell_bytes);
    qrmem_help_ready = 1;
}

static struct json_object *call_help(qrmem_ctx_t *c, struct json_object *a) {
    const char *topic = arg_str(a, "topic", "overview");
    struct json_object *o = json_object_new_object();
    struct json_object *avail = json_object_new_array();
    size_t i;
    int matched = 0;
    /* Before the topic list is walked, so available_topics and brief both come
     * from the built corpus rather than from a half-initialised one. */
    help_topics_init();
    for (i = 0; i < qrmem_help_ntopics; i++) {
        json_object_array_add(
            avail, json_object_new_string(qrmem_help_topics[i].topic));
        if (!strcmp(topic, qrmem_help_topics[i].topic)) {
            json_object_object_add(o, "topic",
                                   json_object_new_string(topic));
            json_object_object_add(o, "brief",
                                   json_object_new_string(
                                       qrmem_help_topics[i].brief));
            matched = 1;
        }
    }
    if (!matched) {
        json_object_object_add(o, "topic", json_object_new_string(topic));
        json_object_object_add(
            o, "error",
            json_object_new_string("unknown help topic; see available_topics"));
        json_object_object_add(o, "available_topics", avail);
        return o;
    }
    json_object_object_add(o, "available_topics", avail);
    /* Always answer with where this fabric actually is, so help never leaves
     * the caller without the one fact every next step depends on. */
    {
        struct json_object *here = json_object_new_object();
        struct json_object *yours = json_object_new_array();
        uint32_t mine = 0;
        json_object_object_add(here, "you",
                               json_object_new_string(c->agent_name));
        json_object_object_add(here, "your_slot",
                               json_object_new_int64((int64_t)c->agent));
        for (uint32_t s = 0; s < QRMEM_SCREENS; s++)
            if (qrmem_screen_owner(&c->ap, s) == c->agent) {
                json_object_array_add(yours, json_object_new_int((int)s));
                mine++;
            }
        json_object_object_add(here, "screens_you_own", yours);
        if (mine == 0) {
            struct json_object *free_list = json_object_new_array();
            for (uint32_t s = 0; s < QRMEM_SCREENS; s++)
                if (qrmem_screen_owner(&c->ap, s) == 0)
                    json_object_array_add(free_list,
                                          json_object_new_int((int)s));
            json_object_object_add(here, "free_screens", free_list);
            json_object_object_add(
                here, "next_step",
                json_object_new_string(
                    "you own no screen yet: qrmem_join with one from "
                    "free_screens"));
        }
        json_object_object_add(o, "here", here);
    }
    return o;
}

/* -------------------------------------------------------------------- dispatch */



static uint16_t type_from_name(const char *s) {
    if (!s)
        return QRMEM_CT_WORD;
    if (!strcmp(s, "idea"))
        return QRMEM_CT_IDEA;
    if (!strcmp(s, "fact"))
        return QRMEM_CT_FACT;
    if (!strcmp(s, "ptr"))
        return QRMEM_CT_PTR;
    return QRMEM_CT_WORD;
}

static const char *type_name(uint16_t t) {
    switch (t) {
    case QRMEM_CT_WORD:
        return "word";
    case QRMEM_CT_IDEA:
        return "idea";
    case QRMEM_CT_FACT:
        return "fact";
    case QRMEM_CT_PTR:
        return "ptr";
    case QRMEM_CT_TOMB:
        return "tomb";
    default:
        return "empty";
    }
}

static uint8_t status_from_name(const char *s) {
    if (!s)
        return QRMEM_STATUS_UNKNOWN;
    if (!strcmp(s, "witnessed"))
        return QRMEM_STATUS_WITNESSED;
    if (!strcmp(s, "supported"))
        return QRMEM_STATUS_SUPPORTED;
    if (!strcmp(s, "refuted"))
        return QRMEM_STATUS_REFUTED;
    return QRMEM_STATUS_UNKNOWN;
}

static const char *status_name(uint8_t s) {
    switch (s) {
    case QRMEM_STATUS_WITNESSED:
        return "witnessed";
    case QRMEM_STATUS_SUPPORTED:
        return "supported";
    case QRMEM_STATUS_REFUTED:
        return "refuted";
    default:
        return "unknown";
    }
}

/* Wall-clock nanoseconds. Named to keep it distinct from the fabric's monotonic
 * clock: the two answer different questions, and record freshness needs the one
 * that survives a reboot. */
static uint64_t realtime_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0u;
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* Is this a well-formed v4? Version nibble 4, variant nibble in [89ab]. */
static int uuid_is_v4(const qrmem_uuid_t *u) {
    return u && !qrmem_uuid_is_nil(u) && (u->b[6] >> 4) == 4u &&
           (u->b[8] & 0xC0u) == 0x80u;
}

/* Render a decoded record as JSON. Text is emitted as a real JSON string with
 * its length honoured, so a payload containing a quote or a newline cannot
 * corrupt the envelope. */
/* How a read path reports a record whose stored identity is not a valid v4.
 *
 * This is the check that catches a fabric written by a PRE-ABI-4 build, or a
 * cell corrupted in place: such a record has bytes where its identity should be
 * that no parser would ever accept. Rendering it anyway would hand an agent an
 * id it cannot use for a link, and the failure would surface later as a dangling
 * reference rather than as the corruption it is. So a read path either renders a
 * valid identity or reports the record as corrupt.
 *
 * The record is NOT silently dropped: dropping it would make a corrupted cell
 * indistinguishable from an empty one, which is the exact confusion the tomb and
 * empty states exist to prevent. */
static struct json_object *rec_corrupt_json(const qrmem_rec_t *r, long block,
                                            long slot, uint64_t gen,
                                            const char *why) {
    struct json_object *o = json_object_new_object();
    json_object_object_add(o, "block", json_object_new_int(block));
    json_object_object_add(o, "slot", json_object_new_int(slot));
    json_object_object_add(o, "type", json_object_new_string(type_name(r->type)));
    json_object_object_add(o, "identity_invalid", json_object_new_boolean(1));
    json_object_object_add(o, "corrupt", json_object_new_string(why));
    json_object_object_add(o, "generation", json_object_new_int64((int64_t)gen));
    return o;
}

static struct json_object *rec_to_json(const qrmem_rec_t *r, long block,
                                       long slot, uint64_t gen) {
    struct json_object *o = json_object_new_object();
    const char *txt = NULL;
    size_t tlen = 0;
    uint32_t v = 0;
    uint8_t sv = 0;
    char id_txt[QRMEM_UUID_TEXT_LEN + 1];
    /* Identity crosses this boundary as canonical lowercase text and nowhere
     * else. The fabric holds 16 raw bytes; the hyphenated form exists purely so
     * an agent has something to read and copy. */
    qrmem_uuid_text(&r->id, id_txt, sizeof id_txt);
    json_object_object_add(o, "block", json_object_new_int(block));
    json_object_object_add(o, "slot", json_object_new_int(slot));
    json_object_object_add(o, "type",
                           json_object_new_string(type_name(r->type)));
    json_object_object_add(o, "id", json_object_new_string(id_txt));
    json_object_object_add(o, "generation", json_object_new_int64((int64_t)gen));
    if (r->n_links) {
        struct json_object *la = json_object_new_array();
        for (uint16_t i = 0; i < r->n_links; i++) {
            char lt[QRMEM_UUID_TEXT_LEN + 1];
            qrmem_uuid_text(&r->links[i], lt, sizeof lt);
            json_object_array_add(la, json_object_new_string(lt));
        }
        json_object_object_add(o, "links", la);
    }
    if (qrmem_rec_get_text(r, &txt, &tlen) == 0)
        json_object_object_add(o, "text", json_object_new_string_len(txt,
                                                                     (int)tlen));
    {
        uint32_t toks[64];
        size_t n = 0;
        if (qrmem_rec_get_u32_array(r, QRMEM_TLV_TOKENS, toks, 64, &n) == 0) {
            struct json_object *ta = json_object_new_array();
            for (size_t i = 0; i < n; i++)
                json_object_array_add(ta, json_object_new_int64(toks[i]));
            json_object_object_add(o, "tokens", ta);
        }
    }
    if (qrmem_rec_get_u32(r, QRMEM_TLV_SUBJECT, &v) == 0)
        json_object_object_add(o, "subject", json_object_new_int64(v));
    if (qrmem_rec_get_u32(r, QRMEM_TLV_RELATION, &v) == 0)
        json_object_object_add(o, "relation", json_object_new_int64(v));
    if (qrmem_rec_get_u32(r, QRMEM_TLV_OBJECT, &v) == 0)
        json_object_object_add(o, "object", json_object_new_int64(v));
    if (qrmem_rec_get_u32(r, QRMEM_TLV_SOURCE, &v) == 0)
        json_object_object_add(o, "source", json_object_new_int64(v));
    {
        unsigned char sb[QRMEM_UUID_BYTES];
        size_t got = 0;
        if (qrmem_rec_get_bytes(r, QRMEM_TLV_SUCCESSOR, sb, sizeof sb, &got) ==
                0 &&
            got == QRMEM_UUID_BYTES) {
            qrmem_uuid_t su;
            char su_txt[QRMEM_UUID_TEXT_LEN + 1];
            memcpy(su.b, sb, QRMEM_UUID_BYTES);
            qrmem_uuid_text(&su, su_txt, sizeof su_txt);
            json_object_object_add(o, "successor_id",
                                   json_object_new_string(su_txt));
        }
    }
    if (qrmem_rec_get_u8(r, QRMEM_TLV_STATUS, &sv) == 0)
        json_object_object_add(o, "status",
                               json_object_new_string(status_name(sv)));
    /* Freshness. Advisory wall-clock, and a ZERO age_seconds means the answer
     * is genuinely unknown rather than zero seconds - which happens for a
     * legacy record with no timestamp, and for the case the wall clock cannot
     * answer: now < written, meaning the clock moved backwards since the write.
     * That is reported as unknown rather than as a negative or a wrapped huge
     * number, because both of those read as confident and are neither. */
    {
        uint64_t written = qrmem_rec_written_ns(r);
        if (written == 0u) {
            json_object_object_add(o, "written_unix", json_object_new_null());
            json_object_object_add(o, "age_seconds", json_object_new_null());
        } else {
            uint64_t now = realtime_ns();
            json_object_object_add(
                o, "written_unix",
                json_object_new_int64((int64_t)(written / 1000000000ull)));
            if (now >= written)
                json_object_object_add(
                    o, "age_seconds",
                    json_object_new_int64(
                        (int64_t)((now - written) / 1000000000ull)));
            else
                json_object_object_add(o, "age_seconds", json_object_new_null());
        }
    }
    /* The lookup key is part of the record now, so it is part of what a read
     * reports. An agent that can see its own discovery handle does not have to
     * guess at it after a restart.
     *
     * A SEPARATE buffer from `txt`. Sharing one pair of variables across two
     * different tags is a trap worth naming: an earlier version of this
     * function read INDEX_KEY into `txt` and emitted it under the key "text",
     * which silently removed the payload from every read - and no test caught
     * it, because every gate checked record counts and identities rather than
     * whether a payload came back out. */
    {
        const char *ikey = NULL;
        size_t ilen = 0;
        if (qrmem_rec_get_text_tag(r, QRMEM_TLV_INDEX_KEY, &ikey, &ilen) == 0)
            json_object_object_add(o, "index_key",
                                   json_object_new_string_len(ikey, (int)ilen));
    }
    return o;
}

/* Every read path renders records through this, so the identity check cannot be
 * forgotten on one of them. A record whose stored id is not a valid v4 is
 * reported as corrupt rather than rendered with an unusable id. */
static struct json_object *rec_render(const qrmem_rec_t *r, long block,
                                      long slot, uint64_t gen) {
    if (!uuid_is_v4(&r->id)) {
        return rec_corrupt_json(
            r, block, slot, gen,
            "the stored record identity is not a canonical UUIDv4; this cell "
            "was written by a pre-ABI-4 build or corrupted in place. Its "
            "content is still readable but it cannot be linked to, superseded "
            "by, or used as an id.");
    }
    return rec_to_json(r, block, slot, gen);
}


/* Resolve and range-check a record address: (screen, block, slot).
 *
 * A record is NOT addressed by plane coordinates. It lives at a block and a slot
 * within it, and the plane is where its ENCODING appears. Callers that want a
 * position to show a human convert here and nowhere else. */
static struct json_object *coords_ok(qrmem_ctx_t *c, struct json_object *a,
                                     long *screen, long *block, long *slot,
                                     char *err, size_t errlen) {
    arg_int(a, "screen", -1, screen);
    arg_int(a, "block", -1, block);
    arg_int(a, "slot", -1, slot);
    if (*screen < 0 || (uint32_t)*screen >= QRMEM_SCREENS) {
        set_err(err, errlen, "screen %ld does not exist (0..%u)", *screen,
                QRMEM_SCREENS - 1u);
        return NULL;
    }
    if (*block < 0 || (uint32_t)*block >= QRMEM_BLOCKS_PER_SCREEN) {
        set_err(err, errlen, "block %ld does not exist (0..%u): a screen is %ux%u",
                *block, QRMEM_BLOCKS_PER_SCREEN - 1u, QRMEM_PLANE_DIM,
                QRMEM_PLANE_DIM);
        return NULL;
    }
    if (*slot < 0 || (uint32_t)*slot >= QRMEM_SLOTS_PER_BLOCK) {
        set_err(err, errlen, "slot %ld does not exist (0..%u)", *slot,
                QRMEM_SLOTS_PER_BLOCK - 1u);
        return NULL;
    }
    (void)c;
    return (struct json_object *)c;
}

static struct json_object *call_tool(qrmem_ctx_t *c, const char *tool,
                                     struct json_object *a) {
    char err[512] = "";
    long screen = 0, x = 0, y = 0, w = 0, h = 0;
    long block = 0, slot = 0;
    struct json_object *res;

    if (!strcmp(tool, "qrmem_help"))
        return call_help(c, a);

    if (!strcmp(tool, "qrmem_status")) {
        struct json_object *o = json_object_new_object();
        struct json_object *screens = json_object_new_array();
        json_object_object_add(o, "aperture",
                               json_object_new_string(c->aperture_path));
        json_object_object_add(o, "agent",
                               json_object_new_string(c->agent_name));
        json_object_object_add(o, "agent_label",
                               json_object_new_string(c->agent_label));
        json_object_object_add(o, "agent_slot",
                               json_object_new_int64((int64_t)c->agent));
        json_object_object_add(o, "agents",
                               json_object_new_int64(
                                   (int64_t)qrmem_agent_count(&c->ap)));
        json_object_object_add(o, "agents_capacity",
                               json_object_new_int64((int64_t)QRMEM_AGENT_MAX));
        json_object_object_add(
            o, "agents_reclaimable",
            json_object_new_int64((int64_t)qrmem_agent_reclaimable(
                &c->ap, QRMEM_AGENT_STALE_NS)));
        /* The authority generation is what makes every other identity claim on
         * this surface meaningful, so status reports it rather than leaving an
         * agent to infer it. An agent that restarted and got a new one can see
         * that here; one that kept its old one can see that its lease predates
         * this authority. */
        json_object_object_add(
            o, "authority_gen",
            json_object_new_int64((int64_t)c->authority_gen));
        /* Whether the lease this process holds is still the current authority.
         * Reported explicitly because every fenced operation fails closed on
         * this, and "why did my write stop working" is otherwise unanswerable
         * from the outside. */
        {
            uint32_t live = (c->ap.hdr) ?
                atomic_load_explicit(&c->ap.hdr->authority_gen,
                                     memory_order_acquire) : 0u;
            json_object_object_add(
                o, "authority_current",
                json_object_new_boolean(c->authority_gen != 0u &&
                                        c->authority_gen == live));
        }
        json_object_object_add(
            o, "lease_held",
            json_object_new_boolean(c->agent != 0u &&
                                    qrmem_agent_lease_held(&c->ap, c->agent) !=
                                        0u));
        /* ENROLLED: is this process's full fenced triple still recognised by the
         * fabric it is reading?
         *
         * `agent_slot` is a client-local integer captured once at hello. After an
         * aperture is replaced under a running client - which `--recreate`, an
         * upgrade, or an operator does legitimately - that integer refers to a
         * registry that no longer exists, and a newly joined agent can be issued
         * the same number. Status would then print `agent_slot: 2, agents: 0` side
         * by side: a self-contradiction the tool was asking the caller to
         * reconcile unaided.
         *
         * So the fabric is asked directly, on the FULL triple rather than the
         * slot: authority_gen matching, the slot still allocated, and alloc_gen
         * matching. Any one of those failing means this process is not enrolled
         * and every fenced operation it attempts will be refused - which is the
         * correct behaviour, made legible instead of mysterious.
         *
         * Three reasons rather than one boolean, because the remedy differs: a
         * dead lease means restart, a stale authority means the daemon restarted,
         * and an unrecognised slot means the aperture was replaced underfoot. */
        {
            int auth_ok = 0, slot_ok = 0, gen_ok = 0;
            uint32_t live_gen = 0;
            qrmem_agent_enrollment_check(&c->ap, c->agent, c->authority_gen,
                                         c->agent_gen, &auth_ok, &slot_ok,
                                         &gen_ok, &live_gen);
            json_object_object_add(o, "enrolled",
                                   json_object_new_boolean(auth_ok && gen_ok));
            json_object_object_add(
                o, "enrolled_authority_ok", json_object_new_boolean(auth_ok));
            json_object_object_add(
                o, "enrolled_slot_ok", json_object_new_boolean(slot_ok));
            json_object_object_add(
                o, "enrolled_generation_ok", json_object_new_boolean(gen_ok));
            json_object_object_add(o, "registry_generation",
                                   json_object_new_int64((int64_t)live_gen));
            if (!(auth_ok && gen_ok)) {
                json_object_object_add(
                    o, "enrolled_note",
                    json_object_new_string(
                        auth_ok
                            ? "your lease is not recognised by this fabric: the "
                              "aperture was probably replaced under you. Restart "
                              "the session to lease against the current one."
                            : "your lease predates the current daemon "
                              "authority_gen. Every fenced write will be refused "
                              "until you restart and re-lease."));
            }
        }
        json_object_object_add(o, "epoch",
                               json_object_new_int64((int64_t)qrmem_epoch(&c->ap)));
        json_object_object_add(o, "era",
                               json_object_new_int64((int64_t)qrmem_era(&c->ap)));
        json_object_object_add(o, "plane_dim",
                               json_object_new_int((int)QRMEM_PLANE_DIM));
        json_object_object_add(o, "plane_count",
                               json_object_new_int((int)QRMEM_PLANE_COUNT));
        json_object_object_add(o, "planes",
                               json_object_new_string("red=qr, green=occupancy, blue=change"));
        json_object_object_add(o, "tile_grid",
                               json_object_new_string("10 columns x 8 rows; one QR per record"));
        json_object_object_add(o, "blocks_per_screen",
                               json_object_new_int((int)QRMEM_BLOCKS_PER_SCREEN));
        json_object_object_add(o, "slots_per_block",
                               json_object_new_int((int)QRMEM_SLOTS_PER_BLOCK));
        json_object_object_add(o, "records_per_screen",
                               json_object_new_int((int)QRMEM_RECORDS_PER_SCREEN));
        json_object_object_add(o, "screens_total",
                               json_object_new_int((int)QRMEM_SCREENS));
        /* The fabric identity, stated first because every screen number below
         * is meaningless without it. Reported as a field AND as a readable
         * address so an agent can copy either without composing one. */
        {
            qrmem_uuid_t fid;
            char idtxt[QRMEM_UUID_TEXT_LEN + 1];
            if (qrmem_fabric_id(&c->ap, &fid) == 0 &&
                qrmem_uuid_text(&fid, idtxt, sizeof idtxt) == 0) {
                json_object_object_add(o, "fabric_id",
                                       json_object_new_string(idtxt));
                json_object_object_add(
                    o, "fabric_address",
                    json_object_new_string(idtxt));
            }
            json_object_object_add(o, "host",
                                   json_object_new_string(c->agent_host));
            json_object_object_add(o, "aperture",
                                   json_object_new_string(c->aperture));
            json_object_object_add(
                o, "address_note",
                json_object_new_string(
                    "A bare screen number is LOCAL to this fabric. Persist the "
                    "qualified address (fabric_id, screen), never the number "
                    "alone: another machine's screen 14 is a different cell "
                    "owned by a different agent."));
        }
        for (uint32_t s = 0; s < QRMEM_SCREENS; s++) {
            struct json_object *so = json_object_new_object();
            uint32_t owner = qrmem_screen_owner(&c->ap, s);
            json_object_object_add(so, "screen", json_object_new_int((int)s));
            /* Each screen entry is qualified too. status is the response an
             * agent is most likely to read in order to WRITE DOWN which screen
             * it is about to use, so it is the worst place to hand back a bare
             * number. The project label is attached inside this helper. */
            {
                char spl[QRMEM_PROJECT_MAX + 1];
                screen_project(c, s, spl, sizeof spl);
                screen_ref_json(so, c, s, spl);
            }
            json_object_object_add(
                so, "owner_slot",
                owner ? json_object_new_int64((int64_t)owner)
                      : json_object_new_null());
            /* An unowned screen is nobody's, including ours. Comparing the raw
             * slot numbers made every screen report "mine" to an agent holding
             * no slot at all, because 0 == 0. Ownership has to be asked of the
             * fabric, not inferred from two zeros agreeing. */
            /* `mine` is asked of the fabric with the FULL fenced triple, not
             * inferred from the slot number matching. A slot number alone can
             * agree while the generation does not - after a daemon restart, or
             * after the registry reclaimed a slot and handed the number to
             * somebody else - and reporting "mine" then would tell an agent it
             * has a tile it cannot write. */
            json_object_object_add(
                so, "mine",
                json_object_new_boolean(qrmem_screen_writable(&c->ap, s,
                                                              ctx_id(c))));
            /* The project label a page carries. It grants nothing, but without
             * it an agent cannot tell which page belongs to which piece of work,
             * and the fabric looks like sixteen anonymous screens. */
            {
                uint32_t plen = atomic_load_explicit(
                    &c->ap.screens[s].project_len, memory_order_acquire);
                char ptxt[QRMEM_PROJECT_MAX + 1];
                if (plen > QRMEM_PROJECT_MAX)
                    plen = QRMEM_PROJECT_MAX;
                if (plen > 0u) {
                    memcpy(ptxt, c->ap.screens[s].project, plen);
                    ptxt[plen] = '\0';
                    json_object_object_add(so, "project",
                                           json_object_new_string(ptxt));
                } else {
                    json_object_object_add(so, "project",
                                           json_object_new_null());
                }
            }
            /* The owner is only a writer while that process is actually alive.
             * A registry slot that still holds an owner after its process died
             * reads as "owned" forever until a sweep runs, which is how a screen
             * looked permanently blocked. */
            {
                json_object *p = json_object_new_object();
                json_object_object_add(p, "slot",
                                       owner ? json_object_new_int64(
                                                   (int64_t)owner)
                                             : json_object_new_null());
                json_object_object_add(
                    p, "lease_held",
                    json_object_new_boolean(
                        owner != 0u &&
                        qrmem_agent_lease_held(&c->ap, owner) != 0u));
                json_object_object_add(p, "present", json_object_new_boolean(
                                                    owner != 0u));
                json_object_object_add(so, "owner", p);
            }
            json_object_object_add(
                so, "generation",
                json_object_new_int64((int64_t)qrmem_generation(&c->ap, s)));
            json_object_object_add(
                so, "writes",
                json_object_new_int64((int64_t)qrmem_write_count(&c->ap, s)));
            json_object_object_add(
                so, "index_used",
                json_object_new_int64((int64_t)qrmem_index_used(&c->ap, s)));
            json_object_object_add(
                so, "index_capacity",
                json_object_new_int64((int64_t)QRMEM_INDEX_ENTRIES));
            json_object_array_add(screens, so);
        }
        json_object_object_add(o, "screens", screens);
        /* PARTICIPANTS: who is on this fabric right now.
         *
         * Presence and ownership are different facts and are reported
         * separately on purpose. A participant holds a lease - its control
         * socket is open - which is the only liveness signal that is not a
         * timeout guessing. An owner holds write authority to a screen, which
         * can outlive the owner disconnecting. An agent can therefore be present
         * and own nothing, or own a screen and be absent, and collapsing the two
         * into one field is how a screen looks permanently blocked.
         *
         * Deliberately NOT included, and this is a design boundary rather than an
         * oversight:
         *   - no read receipts. Nothing here says who has read a record. Tracking
         *     that turns a shared surface into a surveillance record and changes
         *     how agents use it.
         *   - no social graph. No "who follows whom", no visibility rules, no
         *     per-agent addressing. Every agent may read every screen; that is
         *     the model, and presence is here to explain the fabric's state, not
         *     to mediate access to it. */
        {
            struct json_object *people = json_object_new_array();
            for (uint32_t sl = 1; sl <= QRMEM_AGENT_MAX; sl++) {
                struct json_object *p;
                char name[QRMEM_AGENT_NAME_MAX + 1];
                uint32_t held, secs, ag;
                struct json_object *owned;
                uint32_t owned_n = 0;
                if (qrmem_agent_name(&c->ap, sl, name, sizeof name) != 0)
                    continue;
                held = qrmem_agent_lease_held(&c->ap, sl);
                secs = qrmem_agent_connected_seconds(&c->ap, sl);
                ag = qrmem_agent_generation_of(&c->ap, sl);
                p = json_object_new_object();
                json_object_object_add(p, "slot",
                                       json_object_new_int64((int64_t)sl));
                json_object_object_add(p, "identity",
                                       json_object_new_string(name));
                /* LABEL / IDENTITY / agent_gen, and the three are not
                 * interchangeable.
                 *
                 * label      the CALLER-CHOSEN descriptor: whatever was passed
                 *            to --agent. Stable across restarts if the operator
                 *            passes the same string, and meaningless for
                 *            attribution: every session launched as `opencode`
                 *            carries it.
                 * identity   an EPHEMERAL LEASE INCARNATION. Minted per process
                 *            and changing across a reconnect or a daemon
                 *            restart. It exists to make two same-labelled
                 *            sessions distinguishable, NOT to name an agent over
                 *            time.
                 * agent_gen  the FENCING GENERATION. Increments on every
                 *            allocation of this slot; the third element of
                 *            (authority_gen, slot, agent_gen). Two sequential
                 *            occupants of one slot never share one.
                 *
                 * Durable attribution must therefore use the RECORD's own UUID,
                 * which is durable, and never the identity of whoever happened to
                 * be connected when it was written. An observed transition
                 * opencode#5682fc3f -> #55c0de24 -> #9a5dc370 was reported as a
                 * possible identity-stability bug and is in fact correct: those
                 * are three lease incarnations, and the third coincided with a
                 * daemon restart. The defect was never that identity changed; it
                 * was that identity was ever presented as a handle. */
                {
                    const char *hash = strrchr(name, '#');
                    json_object_object_add(
                        p, "label",
                        hash ? json_object_new_string_len(name,
                                                          (int)(hash - name))
                             : json_object_new_string(name));
                }
                json_object_object_add(p, "agent_gen",
                                       json_object_new_int64((int64_t)ag));
                /* WHERE THIS LEASE COMES FROM, as the authority recorded it.
                 *
                 * source_kind is "local" for every lease the daemon granted
                 * itself over its control socket, and "unknown" otherwise. It
                 * is stamped by the claim path, never read from the hello
                 * greeting: the --agent label and --host flag are
                 * caller-chosen, and a source field derived from either would
                 * let any client claim any origin.
                 *
                 * source_host is the authority's own hostname when the kind is
                 * local, and null when the kind is unknown. It is what lets two
                 * same-labelled agents on two hosts be told apart once a
                 * remote leg exists - and what makes its absence honest today:
                 * every lease here is local, so a remote client is not merely
                 * unseen, it is impossible, and the field says so by never
                 * varying. */
                {
                    uint32_t kind = qrmem_agent_origin_kind(&c->ap, sl);
                    char ah[QRMEM_AUTHORITY_HOST_MAX];
                    json_object_object_add(
                        p, "source_kind",
                        json_object_new_string(
                            kind == QRMEM_ORIGIN_LOCAL ? "local" : "unknown"));
                    if (kind == QRMEM_ORIGIN_LOCAL &&
                        qrmem_authority_host(&c->ap, ah, sizeof ah) == 0 &&
                        ah[0])
                        json_object_object_add(p, "source_host",
                                               json_object_new_string(ah));
                    else
                        json_object_object_add(p, "source_host",
                                               json_object_new_null());
                }
                json_object_object_add(
                    p, "connected",
                    json_object_new_boolean(held != 0u));
                json_object_object_add(
                    p, "connected_seconds",
                    json_object_new_int64((int64_t)secs));
                json_object_object_add(p, "authority_gen",
                                       json_object_new_int64(
                                           (int64_t)c->authority_gen));
                json_object_object_add(
                    p, "authority_current",
                    json_object_new_boolean(c->authority_gen != 0u &&
                                            c->authority_gen ==
                                                (c->ap.hdr
                                                     ? atomic_load_explicit(
                                                           &c->ap.hdr
                                                                ->authority_gen,
                                                           memory_order_acquire)
                                                     : 0u)));
                json_object_object_add(
                    p, "is_you",
                    json_object_new_boolean(sl == c->agent));
                owned = json_object_new_array();
                for (uint32_t s = 0; s < QRMEM_SCREENS; s++) {
                    if (qrmem_screen_owner(&c->ap, s) != sl)
                        continue;
                    json_object_array_add(owned, json_object_new_int((int)s));
                    owned_n++;
                }
                json_object_object_add(p, "screens_owned", owned);
                json_object_object_add(
                    p, "screens_owned_count",
                    json_object_new_int64((int64_t)owned_n));
                json_object_array_add(people, p);
            }
            json_object_object_add(o, "participants", people);
            json_object_object_add(
                o, "participants_note",
                json_object_new_string(
                    "Presence only: connected means a control socket is open "
                    "now. It says nothing about who has read a record - there "
                    "are no read receipts - and every agent may read every "
                    "screen regardless. screens_owned is write authority, which "
                    "survives the owner disconnecting.\n\n"
                    "IDENTITY IS NOT A DURABLE HANDLE. Three fields above are "
                    "not interchangeable:\n"
                    "  label      caller-chosen descriptor from --agent. Stable "
                    "if you pass the\n"
                    "             same string, and worthless for attribution: "
                    "every session launched\n"
                    "             as `opencode` carries the same one.\n"
                    "  identity   ephemeral lease incarnation. Changes across a "
                    "reconnect or a\n"
                    "             daemon restart, by design. One live lease "
                    "has one identity; a new\n"
                    "             lease is allowed a new one.\n"
                    "  agent_gen  the fencing generation, third element of "
                    "(authority_gen, slot,\n"
                    "             agent_gen). Increments on every allocation.\n"
                    "Attribute durable work to the RECORD's UUID, which is "
                    "durable. Never attribute\n"
                    "it to the identity that happened to be connected when it "
                    "was written.\n\n"
                    "  source_kind  where the lease comes from, as the authority "
                    "recorded it:\n"
                    "             \"local\" for leases this daemon granted itself, "
                    "\"unknown\"\n"
                    "             otherwise. Stamped at claim time, never taken "
                    "from the\n"
                    "             greeting: --agent and --host are caller-chosen "
                    "and cannot\n"
                    "             attest origin.\n"
                    "  source_host  the authority's own hostname when the kind is "
                    "local,\n"
                    "             null otherwise. Descriptive, like every other "
                    "host\n"
                    "             string: it tells leases apart, it does not "
                    "identify anyone."));
        }
        return o;
    }

    if (!strcmp(tool, "qrmem_mark_baseline")) {
        qrmem_id_t id;
        arg_int(a, "screen", -1, &screen);
        if (screen < 0 || (uint32_t)screen >= QRMEM_SCREENS)
            return err_obj("screen %ld does not exist (0..%u)", screen, QRMEM_SCREENS - 1u);
        id = ctx_id(c);
        if (qrmem_require_owner(&c->ap, (uint32_t)screen, id, err, sizeof err) != 0)
            return err_obj("%s", err);
        if (qrmem_plane_set_baseline(&c->ap, (uint32_t)screen) != 0)
            return err_obj("could not establish blue-plane baseline");
        res = json_object_new_object();
        json_object_object_add(res, "screen", json_object_new_int(screen));
        json_object_object_add(res, "baseline_generation", json_object_new_int64(
            (int64_t)atomic_load_explicit(&c->ap.screens[screen].baseline_generation, memory_order_acquire)));
        json_object_object_add(res, "result", json_object_new_string(
            "blue change plane cleared at this declared baseline; records and red QR plane unchanged"));
        return res;
    }

    if (!strcmp(tool, "qrmem_join")) {
        /* Identity is IMMUTABLE for the life of this process. It is established
         * once at startup from --agent, and a join claims a screen on behalf
         * of that identity. There is no agent parameter: a caller that could
         * name who it acts as could act as anyone, and the three-attempt
         * onboarding dance that parameter caused is gone with it.
         *
         * project is descriptive metadata, never authority: what this
         * screen's page belongs to. Readable by everyone, granting nothing.
         * Immutable once the screen holds its first published record; while
         * empty, correcting it is harmless. */
        const char *project;
        qrmem_id_t id;
        arg_int(a, "screen", -1, &screen);
        if (screen < 0 || (uint32_t)screen >= QRMEM_SCREENS)
            return err_obj("screen %ld does not exist (0..%u)", screen,
                           QRMEM_SCREENS - 1u);
        project = arg_str(a, "project", "");
        c->ap.self_agent = c->agent;
        /* Reclaim the long-gone before allocating. Without this the registry is
         * append-only and the fabric eventually refuses every new agent. */
        {
            uint32_t swept = qrmem_agent_sweep(&c->ap, QRMEM_AGENT_STALE_NS);
            if (swept)
                qrmem_op_end(&c->ap, (uint32_t)screen);
        }
        id = ctx_id(c);
        if (id.slot == 0 || id.authority_gen == 0 || id.agent_gen == 0)
            return err_obj("no live lease: say hello before joining a tile");
        if (qrmem_screen_claim(&c->ap, (uint32_t)screen, id, project, err,
                               sizeof err) != 0)
            return err_obj("%s", err);
        res = json_object_new_object();
        json_object_object_add(res, "screen", json_object_new_int(screen));
        {
            char pl[QRMEM_PROJECT_MAX + 1];
            screen_project(c, screen, pl, sizeof pl);
            screen_ref_json(res, c, screen, pl);
        }
        json_object_object_add(res, "agent",
                               json_object_new_string(c->agent_name));
        json_object_object_add(res, "agent_slot",
                               json_object_new_int64((int64_t)c->agent));
        json_object_object_add(res, "agent_gen",
                               json_object_new_int64((int64_t)c->agent_gen));
        json_object_object_add(res, "generation",
                               json_object_new_int64(
                                   (int64_t)qrmem_generation(&c->ap,
                                                              (uint32_t)screen)));
        return res;
    }

    if (!strcmp(tool, "qrmem_leave")) {
        arg_int(a, "screen", -1, &screen);
        if (screen < 0 || (uint32_t)screen >= QRMEM_SCREENS)
            return err_obj("screen %ld does not exist (0..%u)", screen,
                           QRMEM_SCREENS - 1u);
        if (qrmem_screen_release(&c->ap, (uint32_t)screen, ctx_id(c), err,
                                 sizeof err) != 0)
            return err_obj("%s", err);
        res = json_object_new_object();
        json_object_object_add(res, "screen", json_object_new_int(screen));
        {
            char pl[QRMEM_PROJECT_MAX + 1];
            screen_project(c, screen, pl, sizeof pl);
            screen_ref_json(res, c, screen, pl);
        }
        json_object_object_add(res, "released",
                               json_object_new_boolean(1));
        return res;
    }

    if (!strcmp(tool, "qrmem_write")) {
        qrmem_rec_t r;
        qrmem_uuid_t rid;
        long subject = 0, relation = 0, object = 0, source = 0;
        struct json_object *jt = NULL;
        const char *idx = arg_str(a, "index", NULL);
        const char *dummy_key = NULL;
        size_t dummy_len = 0;
        const char *want_type = arg_str(a, "type", "word");
        if (!coords_ok(c, a, &screen, &block, &slot, err, sizeof err))
            return err_obj("%s", err);
        /* A FACT IS REFUSED BEFORE ANY MUTATION.
         *
         * `fact` stays in the schema because it is part of the vocabulary and
         * removing it would make an old client fail on a shape it was told was
         * valid. But its subject/relation/object are TOKEN IDS, and the token
         * vocabulary does not exist yet - there is no way to mint a meaningful
         * one. Accepting the record anyway would store three integers that
         * mean nothing while looking exactly like a real assertion, which is
         * worse than refusing: a reader cannot tell a fabricated fact from a
         * sourced one.
         *
         * Refused BEFORE the cell is touched, so nothing is written and no
         * generation is bumped. The message names the alternatives, because a
         * bare refusal would leave the agent guessing. */
        if (type_from_name(want_type) == QRMEM_CT_FACT) {
            return err_obj(
                "fact records are temporarily unavailable: subject/relation/"
                "object token semantics are not yet defined. Use word or idea "
                "instead. No record was written.");
        }
        /* Identity: a canonical UUIDv4 string, or omitted. Never an integer.
         *
         * This is the boundary where the old behaviour was worst: `id` went
         * through arg_int, so 1031 was an id, "1031" was the id 1031, and
         * anything else became 0 - the nil id, which then looked like a
         * deliberate choice. Every one of those is now a refusal that happens
         * BEFORE any mutation, so a rejected call leaves nothing behind.
         *
         * Omitting id asks the fabric to mint one, which is why an agent never
         * has to generate a v4 itself. */
        if (a && json_object_object_get_ex(a, "id", &jt) &&
            json_object_get_type(jt) != json_type_null) {
            if (json_object_get_type(jt) != json_type_string) {
                return err_obj(
                    "id must be a canonical UUIDv4 string "
                    "(xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx), lowercase; "
                    "integers and labels are not ids. Omit it to have one "
                    "minted. No record was written.");
            }
            if (qrmem_uuid_parse(json_object_get_string(jt), &rid, err,
                                 sizeof err) != 0)
                return err_obj("%s No record was written.", err);
        } else if (qrmem_uuid_mint(&rid, err, sizeof err) != 0) {
            return err_obj("%s No record was written.", err);
        }
        qrmem_rec_init(&r, type_from_name(want_type), rid);

        /* THE TIMESTAMP IS RESERVED FIRST, before any caller field is added.
         *
         * The previous version appended it LAST, after text, tokens, links,
         * status and the index key had all claimed their bytes. Checking the
         * text budget up front did not fix that: the check only covers text
         * alone, so a record like text=210 plus a 20-byte index key passed the
         * advertised 224 limit and every field fit (214 + 24 = 238 of 240), and
         * was then refused with "no room for the publication timestamp".
         *
         * That is the same bug as the one this slice set out to remove, just
         * moved: a caller told "224 is yours" is refused by the reservation
         * mechanism itself, with a message about the store's internals rather
         * than about the caller's own payload.
         *
         * Reserving first makes the arithmetic honest. The 12 bytes are spent
         * before anything else can compete for them, so caller TLVs are bounded
         * by what genuinely remains (QRMEM_CELL_CALLER_BYTES), any overflow is
         * reported against the CALLER's fields, and a published record can never
         * have lost its timestamp to a neighbour that wanted the space. */
        if (qrmem_rec_stamp_written(&r, realtime_ns()) != 0)
            return err_obj("a cell cannot hold its own publication timestamp; "
                           "the cell body is too small. No record was written.");

        /* The text budget is checked first so the most common oversize gets a
         * specific message. It is a check on TEXT, not on the whole record: a
         * record carrying tokens, links, a status or an index key has
         * correspondingly less text room, and those overflows are reported by
         * the codec below against the caller's own budget.
         *
         * Deliberately not opportunistic, per operator decision: a deterministic
         * capacity an agent can reason about beats a larger but conditional one.
         */
        {
            const char *text = arg_str(a, "text", NULL);
            if (text && strlen(text) > QRMEM_CELL_CALLER_BYTES)
                return err_obj(
                    "text payload is %zu bytes; a cell holds %u for the caller "
                    "once the always-present publication timestamp is reserved. "
                    "No record was written.",
                    strlen(text), (unsigned)QRMEM_CELL_CALLER_BYTES);
        }
        {
            const char *text = arg_str(a, "text", NULL);
            if (text && qrmem_rec_add_text(&r, text, strlen(text)) != 0)
                return err_obj(
                    "the fields of this record do not fit: %u bytes are left "
                    "for the caller after the publication timestamp is "
                    "reserved, and text, tokens, links, status and the index "
                    "key each claim their own header. Shorten the payload or "
                    "record fewer links. No record was written.",
                    (unsigned)QRMEM_CELL_CALLER_BYTES);
        }
        if (a && json_object_object_get_ex(a, "tokens", &jt) &&
            json_object_get_type(jt) == json_type_array) {
            uint32_t toks[64];
            size_t n = json_object_array_length(jt), k = 0;
            if (n > 64)
                return err_obj("%zu tokens does not fit a cell (max 64)", n);
            for (size_t i = 0; i < n; i++)
                toks[k++] = (uint32_t)json_object_get_int64(
                    json_object_array_get_idx(jt, i));
            if (k && qrmem_rec_add_u32_array(&r, QRMEM_TLV_TOKENS, toks, k) != 0)
                return err_obj(
                    "the fields of this record do not fit: %u bytes are left "
                    "for the caller after the publication timestamp is "
                    "reserved. No record was written.",
                    (unsigned)QRMEM_CELL_CALLER_BYTES);
        }
        arg_int(a, "subject", 0, &subject);
        arg_int(a, "relation", 0, &relation);
        arg_int(a, "object", 0, &object);
        arg_int(a, "source", 0, &source);
        if (subject)
            qrmem_rec_add_u32(&r, QRMEM_TLV_SUBJECT, (uint32_t)subject);
        if (relation)
            qrmem_rec_add_u32(&r, QRMEM_TLV_RELATION, (uint32_t)relation);
        if (object)
            qrmem_rec_add_u32(&r, QRMEM_TLV_OBJECT, (uint32_t)object);
        if (source)
            qrmem_rec_add_u32(&r, QRMEM_TLV_SOURCE, (uint32_t)source);
        /* Status is OPTIONAL, and written only when supplied.
         *
         * It used to be appended unconditionally, which spent five bytes of
         * every cell's body on a field most records do not use - and the
         * consequence was invisible until the publication timestamp arrived and
         * asked for twelve more: the stated caller limit and the encoder
         * disagreed by exactly those five bytes, and a payload the surface said
         * fitted was refused by the codec.
         *
         * A field a caller did not supply is not stored. Presence now means
         * what it says, the same rule the index key follows, and the caller's
         * budget is the one number the header derives. */
        {
            const char *want_status = arg_str(a, "status", NULL);
            if (want_status && want_status[0])
                qrmem_rec_add_u8(&r, QRMEM_TLV_STATUS,
                                 status_from_name(want_status));
        }
        /* Links are UUIDv4 references for the same reason ids are: a link is a
         * pointer at another record, so it needs that record's identity. A link
         * that was a number would be a number relative to no stated convention
         * - exactly the ambiguity the id change removes. Parsed before any
         * mutation, and a cell full of links is refused rather than truncated. */
        if (a && json_object_object_get_ex(a, "links", &jt) &&
            json_object_get_type(jt) == json_type_array) {
            size_t n = json_object_array_length(jt);
            if (n > QRMEM_CELL_LINKS)
                return err_obj("%zu links does not fit a cell (max %u); no "
                               "record was written",
                               n, (unsigned)QRMEM_CELL_LINKS);
            for (size_t i = 0; i < n; i++) {
                struct json_object *lv = json_object_array_get_idx(jt, i);
                qrmem_uuid_t lid;
                if (!lv || json_object_get_type(lv) != json_type_string)
                    return err_obj("link %zu must be a canonical UUIDv4 string, "
                                   "lowercase; no record was written",
                                   i);
                if (qrmem_uuid_parse(json_object_get_string(lv), &lid, err,
                                     sizeof err) != 0)
                    return err_obj("link %zu: %s No record was written.", i,
                                   err);
                if (qrmem_rec_link(&r, lid) != 0)
                    return err_obj("a cell holds at most %u links",
                                   (unsigned)QRMEM_CELL_LINKS);
            }
        }
        /* The lookup key goes INTO THE RECORD, before publication, so it is
         * durable with the cell rather than living only in the index table.
         *
         * The index table is derived state: it lives in the aperture, which a
         * reboot empties. A key stored only there was lost on restart, and the
         * record came back readable by coordinate but invisible to qrmem_index -
         * a silent loss of its discovery handle, which is the worst way for a
         * lookup capability to go missing. Persisting the key with the record and
         * rebuilding the table from it on restore keeps one source of truth.
         *
         * Validated before the write so a key that could never have been indexed
         * does not get stored as though it were. */
        if (idx && idx[0]) {
            size_t ilen = strlen(idx);
            if (ilen == 0u || ilen > 256u)
                return err_obj("index key length %zu is out of range (1..256); "
                               "no record was written",
                               ilen);
            if (qrmem_rec_get_text_tag(&r, QRMEM_TLV_INDEX_KEY, &dummy_key,
                                       &dummy_len) == 0)
                return err_obj(
                    "this record already carries an index key; one key per "
                    "record, matching the one-key-per-write rule. No record was "
                    "written.");
            if (qrmem_rec_add_text_tag(&r, QRMEM_TLV_INDEX_KEY, idx, ilen) != 0)
                return err_obj(
                    "the fields of this record do not fit: %u bytes are left "
                    "for the caller after the publication timestamp is "
                    "reserved, and this index key needs %zu. Shorten the text "
                    "or the key. No record was written.",
                    (unsigned)QRMEM_CELL_CALLER_BYTES, ilen);
        }
        /* The stamp was added FIRST, above, before any caller field - so its 12
         * bytes cannot be taken by a neighbour that wanted the space. Set by
         * the write path with no caller override: a caller cannot backdate a
         * record or forge its freshness, because "how old is this" is exactly
         * the kind of field a dishonest caller would want to control. */
        c->ap.self_agent = c->agent;
        if (qrmem_tile_write(&c->ap, (uint32_t)screen, (uint32_t)block, (uint32_t)slot,
                             ctx_id(c), &r, err, sizeof err) != 0)
            return err_obj("%s", err);
        if (idx && idx[0] &&
            qrmem_index_put(&c->ap, (uint32_t)screen, ctx_id(c), idx,
                            (uint32_t)block, (uint32_t)slot, err, sizeof err) != 0) {
            /* The record IS published. Reporting a bare failure here would tell
             * the caller nothing happened, which is worse than saying what
             * actually occurred: the write landed and only the lookup key did
             * not. */
            char msg[700];
            char id_txt[QRMEM_UUID_TEXT_LEN + 1];
            qrmem_uuid_text(&rid, id_txt, sizeof id_txt);
            snprintf(msg, sizeof msg,
                     "record %s was written to (block %ld, slot %ld) but "
                     "could not be indexed under \"%s\": %s",
                     id_txt, block, slot, idx, err);
            return err_obj("%s", msg);
        }
        res = json_object_new_object();
        json_object_object_add(res, "screen", json_object_new_int(screen));
        {
            char pl[QRMEM_PROJECT_MAX + 1];
            screen_project(c, screen, pl, sizeof pl);
            screen_ref_json(res, c, screen, pl);
        }
        json_object_object_add(res, "block", json_object_new_int(block));
        json_object_object_add(res, "slot", json_object_new_int(slot));
        {
            char id_txt[QRMEM_UUID_TEXT_LEN + 1];
            qrmem_uuid_text(&rid, id_txt, sizeof id_txt);
            json_object_object_add(res, "id",
                                   json_object_new_string(id_txt));
        }
        json_object_object_add(
            res, "generation",
            json_object_new_int64((int64_t)qrmem_generation(
                &c->ap, (uint32_t)screen)));
        return res;
    }

    if (!strcmp(tool, "qrmem_read") || !strcmp(tool, "qrmem_commit_payload")) {
        qrmem_rec_t r;
        if (!coords_ok(c, a, &screen, &block, &slot, err, sizeof err))
            return err_obj("%s", err);
        if (qrmem_tile_read(&c->ap, (uint32_t)screen, (uint32_t)block,
                            (uint32_t)slot, &r, err, sizeof err) != 0)
            return err_obj("%s", err);
        if (!strcmp(tool, "qrmem_read")) {
            /* Qualified too. A read is the most likely thing to be quoted back
             * into shared knowledge - "the record at screen N says..." - so it
             * is exactly the response that must not hand out a bare number. */
            struct json_object *ro =
                rec_render(&r, block, slot,
                           qrmem_generation(&c->ap, (uint32_t)screen));
            if (ro) {
                char rpl[QRMEM_PROJECT_MAX + 1];
                screen_project(c, (uint32_t)screen, rpl, sizeof rpl);
                screen_ref_json(ro, c, (uint32_t)screen, rpl);
            }
            return ro;
        }
        {
            /* Prepare, never write. The agent decides whether this becomes
             * durable and hands the payload to the ordinary memory tools. */
            const char *ename = arg_str(a, "entity_name", "");
            const char *project = arg_str(a, "project", "");
            const char *txt = NULL;
            size_t tlen = 0;
            uint32_t subject = 0, relation = 0, object = 0, source = 0;
            uint8_t sv = 0;
            char obs[1024];
            struct json_object *oarr;
            if (!ename[0])
                return err_obj(
                    "entity_name is required: the fabric does not choose what "
                    "a fact is called");
            if (r.type == QRMEM_CT_TOMB)
                return err_obj(
                    "cell (%ld,%ld) is superseded; promote its successor "
                    "instead",
                    x, y);
            {
                char rid_txt[QRMEM_UUID_TEXT_LEN + 1];
                qrmem_uuid_text(&r.id, rid_txt, sizeof rid_txt);
                snprintf(obs, sizeof obs,
                         "tile %ld,%ld record %s type %s screen %ld", x, y,
                         rid_txt, type_name(r.type), screen);
            }
            res = json_object_new_object();
            json_object_object_add(res, "entity_name",
                                   json_object_new_string(ename));
            if (project[0])
                json_object_object_add(res, "project",
                                       json_object_new_string(project));
            oarr = json_object_new_array();
            json_object_array_add(oarr, json_object_new_string(obs));
            if (qrmem_rec_get_text(&r, &txt, &tlen) == 0) {
                char line[1200];
                snprintf(line, sizeof line, "tile text: %.*s", (int)tlen, txt);
                json_object_array_add(oarr, json_object_new_string(line));
            }
            qrmem_rec_get_u32(&r, QRMEM_TLV_SUBJECT, &subject);
            qrmem_rec_get_u32(&r, QRMEM_TLV_RELATION, &relation);
            qrmem_rec_get_u32(&r, QRMEM_TLV_OBJECT, &object);
            qrmem_rec_get_u32(&r, QRMEM_TLV_SOURCE, &source);
            qrmem_rec_get_u8(&r, QRMEM_TLV_STATUS, &sv);
            if (subject || relation || object) {
                char line[256];
                snprintf(line, sizeof line,
                         "subject=%u relation=%u object=%u status=%s",
                         subject, relation, object, status_name(sv));
                json_object_array_add(oarr, json_object_new_string(line));
            }
            if (source) {
                char line[128];
                snprintf(line, sizeof line, "source=%u", source);
                json_object_array_add(oarr, json_object_new_string(line));
            }
            if (r.n_links) {
                struct json_object *la = json_object_new_array();
                for (uint16_t i = 0; i < r.n_links; i++) {
                    char lt[QRMEM_UUID_TEXT_LEN + 1];
                    qrmem_uuid_text(&r.links[i], lt, sizeof lt);
                    json_object_array_add(la, json_object_new_string(lt));
                }
                json_object_object_add(res, "links", la);
            }
            json_object_object_add(res, "observations", oarr);
            json_object_object_add(res, "write_performed",
                                   json_object_new_boolean(0));
            json_object_object_add(
                res, "next_step",
                json_object_new_string(
                    "Nothing was written. To make this durable, call "
                    "create_entities with entity_name and observations, then "
                    "add_observations if you want the body, then record the "
                    "task or note."));
            return res;
        }
    }

    if (!strcmp(tool, "qrmem_decode_region")) {
        struct json_object *arr;
        int truncated;
        arg_int(a, "screen", -1, &screen);
        arg_int(a, "block", 0, &block);
        arg_int(a, "slot", 0, &slot);
        arg_int(a, "width", 16, &w);
        arg_int(a, "height", 16, &h);
        if (screen < 0 || (uint32_t)screen >= QRMEM_SCREENS)
            return err_obj("screen %ld does not exist (0..%u)", screen,
                           QRMEM_SCREENS - 1u);
        if (block < 0 || (uint32_t)block >= QRMEM_BLOCKS_PER_SCREEN ||
            slot < 0 || (uint32_t)slot >= QRMEM_SLOTS_PER_BLOCK)
            return err_obj(
                "record (block %ld, slot %ld) is outside a screen: %u blocks of "
                "%u slots",
                block, slot, QRMEM_BLOCKS_PER_SCREEN, QRMEM_SLOTS_PER_BLOCK);
        if (w <= 0 || h <= 0 || (uint32_t)w > QRMEM_RECORDS_PER_SCREEN ||
            (uint32_t)h > QRMEM_RECORDS_PER_SCREEN)
            return err_obj(
                "window %ldx%ld records does not fit a screen of %u records", w,
                h, QRMEM_RECORDS_PER_SCREEN);
        /* An inspection verb must not be able to detonate in the caller's
         * context. A full 128x128 window is 16384 cells, and returning every
         * published record is a payload no agent can afford - the first report
         * of this arrived as an agent asking for exactly that window.
         *
         * The cap is EXPLICIT rather than silent: the response says how many
         * records it returned, how many the window holds, that it was cut off,
         * and how to get the rest. A truncated answer that does not admit it is
         * worse than a refusal. */
        /* The window counts RECORDS from (block, slot) onwards, in record order,
         * and wraps from the end of one block into the next.
         *
         * It used to divide the PLANE x coordinate by the slots-per-block to
         * invent a block and a slot, which quietly re-read the same records
         * several times: a window reported one record four times at four
         * different "y" values. Plane coordinates say where a block is DRAWN;
         * they are not an address for the record store, and treating them as one
         * is the exact confusion this geometry exists to prevent. */
        {
            uint32_t start = (uint32_t)block * QRMEM_SLOTS_PER_BLOCK +
                            (uint32_t)slot;
            uint32_t total = (uint32_t)w * (uint32_t)h;
            uint32_t window_records =
                start + total > QRMEM_RECORDS_PER_SCREEN
                    ? QRMEM_RECORDS_PER_SCREEN - start
                    : total;
            arr = json_object_new_array();
            truncated = 0;
            for (uint32_t i = 0; i < window_records; i++) {
                qrmem_rec_t r;
                char e[256] = "";
                uint32_t idx = start + i;
                uint32_t rb = idx / QRMEM_SLOTS_PER_BLOCK;
                uint32_t rs = idx % QRMEM_SLOTS_PER_BLOCK;
                if (qrmem_cell_read(&c->ap, (uint32_t)screen, rb, rs, &r, e,
                                    sizeof e) != 0)
                    continue;
                if (json_object_array_length(arr) >= QRMEM_DECODE_MAX) {
                    truncated = 1;
                    break;
                }
                json_object_array_add(
                    arr, rec_render(&r, (long)rb, (long)rs,
                                    qrmem_generation(&c->ap,
                                                     (uint32_t)screen)));
            }
        }
        res = json_object_new_object();
        json_object_object_add(res, "screen", json_object_new_int(screen));
        {
            char pl[QRMEM_PROJECT_MAX + 1];
            screen_project(c, screen, pl, sizeof pl);
            screen_ref_json(res, c, screen, pl);
        }
        json_object_object_add(res, "records", arr);
        json_object_object_add(res, "returned",
                               json_object_new_int64(
                                   (int64_t)json_object_array_length(arr)));
        /* Named for what it counts. "window_cells" was a lie about a window
         * measured in records, and the geometry changed underneath it. */
        json_object_object_add(res, "window_records",
                               json_object_new_int64(w * h));
        json_object_object_add(res, "truncated",
                               json_object_new_boolean(truncated));
        if (truncated)
            json_object_object_add(
                res, "next_hint",
                json_object_new_string(
                    "cut off at the per-call record cap; decode the remainder "
                    "with a smaller window, or walk the screen in strips"));
        json_object_object_add(
            res, "generation",
            json_object_new_int64((int64_t)qrmem_generation(
                &c->ap, (uint32_t)screen)));
        return res;
    }

    if (!strcmp(tool, "qrmem_view_tile")) {
        char *buf;
        size_t need = 0, n = 0;
        arg_int(a, "screen", -1, &screen);
        arg_int(a, "x", 0, &x);
        arg_int(a, "y", 0, &y);
        arg_int(a, "width", 64, &w);
        arg_int(a, "height", 32, &h);
        if (screen < 0 || (uint32_t)screen >= QRMEM_SCREENS)
            return err_obj("screen %ld does not exist (0..%u)", screen,
                           QRMEM_SCREENS - 1u);
        if (w <= 0 || h <= 0 || (uint32_t)w > QRMEM_PLANE_DIM ||
            (uint32_t)h > QRMEM_PLANE_DIM)
            return err_obj("window %ldx%ld does not fit a %ux%u plane", w, h,
                           QRMEM_PLANE_DIM, QRMEM_PLANE_DIM);
        if ((uint32_t)w * (uint32_t)h > 4096u)
            return err_obj(
                "a %ldx%ld render is %ld cells of text; ask for a smaller "
                "window (4096 cells maximum)",
                w, h, w * h);
        need = (size_t)h * ((size_t)w + 1u) + 1u;
        buf = malloc(need);
        if (!buf)
            return err_obj("cannot allocate %zu bytes for the render", need);
        if (qrmem_plane_render(&c->ap, (uint32_t)screen, (uint32_t)x, (uint32_t)y,
                              (uint32_t)w, (uint32_t)h, buf, need, &n, err,
                              sizeof err) != 0) {
            free(buf);
            return err_obj("%s", err);
        }
        res = json_object_new_object();
        json_object_object_add(res, "screen", json_object_new_int(screen));
        {
            char pl[QRMEM_PROJECT_MAX + 1];
            screen_project(c, screen, pl, sizeof pl);
            screen_ref_json(res, c, screen, pl);
        }
        json_object_object_add(res, "width", json_object_new_int(w));
        json_object_object_add(res, "height", json_object_new_int(h));
        /* The legend describes MODULES, not record types. It used to claim
         * "# word" and "* idea" for a surface that carries one bit per module
         * and has no notion of a type, so a reader was told a meaning these
         * characters do not have. */
        json_object_object_add(
            res, "legend",
            json_object_new_string(". white QR-plane pixel  # black QR-plane pixel"));
        json_object_object_add(
            res, "unit",
            json_object_new_string(
                "red QR display pixel; it is not a record coordinate or QR data module"));
        json_object_object_add(res, "render", json_object_new_string(buf));
        free(buf);
        return res;
    }

    if (!strcmp(tool, "qrmem_link")) {
        qrmem_uuid_t target;
        char tgt_txt[QRMEM_UUID_TEXT_LEN + 1];
        if (!coords_ok(c, a, &screen, &block, &slot, err, sizeof err))
            return err_obj("%s", err);
        /* A link target is required, not defaulted. Defaulting to 0 used to mean
         * "link to nothing" was expressible and the cell silently gained a link
         * to the nil id. */
        if (qrmem_uuid_parse(arg_str(a, "target_id", NULL), &target, err,
                             sizeof err) != 0)
            return err_obj("target_id: %s No link was made.", err);
        c->ap.self_agent = c->agent;
        if (qrmem_tile_link(&c->ap, (uint32_t)screen, (uint32_t)block,
                            (uint32_t)slot, ctx_id(c), target, err,
                            sizeof err) != 0)
            return err_obj("%s", err);
        res = json_object_new_object();
        qrmem_uuid_text(&target, tgt_txt, sizeof tgt_txt);
        json_object_object_add(res, "linked_to",
                               json_object_new_string(tgt_txt));
        json_object_object_add(
            res, "generation",
            json_object_new_int64((int64_t)qrmem_generation(&c->ap,
                                                            (uint32_t)screen)));
        return res;
    }

    if (!strcmp(tool, "qrmem_copy") || !strcmp(tool, "qrmem_move")) {
        long fs = 0, fx = 0, fy = 0, ts = 0, tx = 0, ty = 0;
        arg_int(a, "from_screen", -1, &fs);
        arg_int(a, "from_block", -1, &fx);
        arg_int(a, "from_slot", -1, &fy);
        arg_int(a, "to_screen", -1, &ts);
        arg_int(a, "to_block", -1, &tx);
        arg_int(a, "to_slot", -1, &ty);
        if (fs < 0 || (uint32_t)fs >= QRMEM_SCREENS || ts < 0 ||
            (uint32_t)ts >= QRMEM_SCREENS)
            return err_obj("screens must be 0..%u", QRMEM_SCREENS - 1u);
        if (fx < 0 || (uint32_t)fx >= QRMEM_BLOCKS_PER_SCREEN ||
            (uint32_t)tx >= QRMEM_BLOCKS_PER_SCREEN || fy < 0 ||
            (uint32_t)fy >= QRMEM_SLOTS_PER_BLOCK ||
            (uint32_t)ty >= QRMEM_SLOTS_PER_BLOCK)
            return err_obj("blocks must be 0..%u and slots 0..%u",
                           QRMEM_BLOCKS_PER_SCREEN - 1u,
                           QRMEM_SLOTS_PER_BLOCK - 1u);
        c->ap.self_agent = c->agent;
        if (!strcmp(tool, "qrmem_copy")) {
            if (qrmem_tile_copy(&c->ap, (uint32_t)fs, (uint32_t)fx, (uint32_t)fy,
                                (uint32_t)ts, (uint32_t)tx, (uint32_t)ty,
                                ctx_id(c), err, sizeof err) != 0)
                return err_obj("%s", err);
        } else {
            if (qrmem_tile_move(&c->ap, (uint32_t)fs, (uint32_t)fx, (uint32_t)fy,
                                (uint32_t)ts, (uint32_t)tx, (uint32_t)ty,
                                ctx_id(c), err, sizeof err) != 0)
                return err_obj("%s", err);
        }
        res = json_object_new_object();
        json_object_object_add(res, "from_screen", json_object_new_int(fs));
        json_object_object_add(res, "to_screen", json_object_new_int(ts));
        json_object_object_add(res, "to_block", json_object_new_int(tx));
        json_object_object_add(res, "to_slot", json_object_new_int(ty));
        json_object_object_add(res, "ok", json_object_new_boolean(1));
        /* Copy and move differ in identity, so the reply says which happened
         * and what the record is now called. An agent that assumed a copy keeps
         * the id would go on to link the original, which would now be two live
         * records sharing one reference. */
        if (!strcmp(tool, "qrmem_copy")) {
            qrmem_rec_t cr;
            char cerr[256] = "";
            json_object_object_add(res, "identity", json_object_new_string(
                "minted: this is a new record, linked to the record it was "
                "copied from"));
            if (qrmem_cell_read(&c->ap, (uint32_t)ts, (uint32_t)tx, (uint32_t)ty,
                                &cr, cerr, sizeof cerr) == 0) {
                char it[QRMEM_UUID_TEXT_LEN + 1];
                qrmem_uuid_text(&cr.id, it, sizeof it);
                json_object_object_add(res, "id", json_object_new_string(it));
                if (cr.n_links) {
                    struct json_object *la = json_object_new_array();
                    for (uint16_t i = 0; i < cr.n_links; i++) {
                        char lt[QRMEM_UUID_TEXT_LEN + 1];
                        qrmem_uuid_text(&cr.links[i], lt, sizeof lt);
                        json_object_array_add(la, json_object_new_string(lt));
                    }
                    json_object_object_add(res, "links", la);
                }
            }
        } else {
            json_object_object_add(res, "identity", json_object_new_string(
                "preserved: the same record now lives at the new address"));
            {
                qrmem_rec_t mr;
                char merr[256] = "";
                if (qrmem_cell_read(&c->ap, (uint32_t)ts, (uint32_t)tx,
                                    (uint32_t)ty, &mr, merr, sizeof merr) == 0) {
                    char it[QRMEM_UUID_TEXT_LEN + 1];
                    qrmem_uuid_text(&mr.id, it, sizeof it);
                    json_object_object_add(res, "id",
                                           json_object_new_string(it));
                }
            }
        }
        return res;
    }

    if (!strcmp(tool, "qrmem_supersede")) {
        qrmem_uuid_t succ;
        struct json_object *jt = NULL;
        memset(&succ, 0, sizeof succ);
        if (!coords_ok(c, a, &screen, &block, &slot, err, sizeof err))
            return err_obj("%s", err);
        /* Omitted means "record no successor", which is the nil UUID - and the
         * nil UUID is not a valid v4, so it can never collide with a real
         * record's id. A supplied successor must be canonical, and must not be
         * this record's own id: a record cannot succeed itself. */
        if (a && json_object_object_get_ex(a, "successor_id", &jt) &&
            json_object_get_type(jt) != json_type_null) {
            if (json_object_get_type(jt) != json_type_string)
                return err_obj("successor_id must be a canonical UUIDv4 string, "
                               "lowercase, or omitted. Nothing was "
                               "superseded.");
            if (qrmem_uuid_parse(json_object_get_string(jt), &succ, err,
                                 sizeof err) != 0)
                return err_obj("successor_id: %s Nothing was superseded.", err);
        }
        c->ap.self_agent = c->agent;
        if (qrmem_tile_supersede(&c->ap, (uint32_t)screen, (uint32_t)block,
                                 (uint32_t)slot, ctx_id(c), succ, err,
                                 sizeof err) != 0)
            return err_obj("%s", err);
        res = json_object_new_object();
        json_object_object_add(res, "superseded", json_object_new_boolean(1));
        if (!qrmem_uuid_is_nil(&succ)) {
            char stxt[QRMEM_UUID_TEXT_LEN + 1];
            qrmem_uuid_text(&succ, stxt, sizeof stxt);
            json_object_object_add(res, "successor_id",
                                   json_object_new_string(stxt));
        }
        return res;
    }

    if (!strcmp(tool, "qrmem_index")) {
        const char *key = arg_str(a, "key", "");
        long limit = 16;
        uint32_t ix[QRMEM_INDEX_ENTRIES], iy[QRMEM_INDEX_ENTRIES];
        size_t n = 0, i;
        struct json_object *arr;
        arg_int(a, "screen", -1, &screen);
        arg_int(a, "limit", 16, &limit);
        if (screen < 0 || (uint32_t)screen >= QRMEM_SCREENS)
            return err_obj("screen %ld does not exist (0..%u)", screen,
                           QRMEM_SCREENS - 1u);
        if (!key[0])
            return err_obj("a lookup key is required");
        if (limit <= 0 || (uint32_t)limit > 64)
            return err_obj("limit %ld is out of range (1..64)", limit);
        if (qrmem_index_lookup(&c->ap, (uint32_t)screen, key,
                               (uint32_t)limit, ix, iy, &n, err,
                               sizeof err) != 0)
            return err_obj("%s", err);
        arr = json_object_new_array();
        for (i = 0; i < n; i++) {
            qrmem_rec_t r;
            char e[256] = "";
            if (qrmem_cell_read(&c->ap, (uint32_t)screen, ix[i], iy[i], &r, e,
                                sizeof e) != 0)
                continue;
            json_object_array_add(
                arr, rec_render(&r, ix[i], iy[i],
                                qrmem_generation(&c->ap, (uint32_t)screen)));
        }
        res = json_object_new_object();
        json_object_object_add(res, "screen", json_object_new_int(screen));
        {
            char pl[QRMEM_PROJECT_MAX + 1];
            screen_project(c, screen, pl, sizeof pl);
            screen_ref_json(res, c, screen, pl);
        }
        json_object_object_add(res, "key", json_object_new_string(key));
        json_object_object_add(res, "cells", arr);
        json_object_object_add(res, "matched",
                               json_object_new_int64((int64_t)n));
        json_object_object_add(
            res, "note",
            json_object_new_string(
                "Indexed lookup only. An unindexed cell is invisible here by "
                "design; use qrmem_decode_region to inspect an area directly."));
        return res;
    }

    {
        char msg[256];
        snprintf(msg, sizeof msg, "Unknown tool: '%s'", tool ? tool : "");
        return err_obj("%s", msg);
    }
}

/* ------------------------------------------------------------------ envelopes */

static void emit(struct json_object *env) {
    const char *text = json_object_to_json_string_ext(env, JSON_C_TO_STRING_PLAIN);
    printf("%s\n", text ? text : "{}");
    fflush(stdout);
    json_object_put(env);
}

/* The request id is BORROWED from the request object, and the request is
 * released before its envelope is serialised. Handing that borrowed pointer to
 * the envelope leaves a dangling child: the first version of this file did
 * exactly that and crashed inside the serialiser on every single response,
 * including ping. json-c 0.19's json_object_object_add does not take its own
 * reference, so json_object_get() would fix the crash while leaking one
 * reference per request. Copying the value is the only form that is both
 * crash-free and leak-free.
 *
 * JSON-RPC ids are an integer, a string, or absent; anything else is
 * normalised to null rather than echoed as a type the client did not send. */
static struct json_object *id_copy(struct json_object *id) {
    if (!id)
        return json_object_new_null();
    switch (json_object_get_type(id)) {
    case json_type_int:
        return json_object_new_int64(json_object_get_int64(id));
    case json_type_string:
        return json_object_new_string(json_object_get_string(id));
    default:
        return json_object_new_null();
    }
}

static struct json_object *result_envelope(struct json_object *id,
                                           struct json_object *result) {
    struct json_object *env = json_object_new_object();
    json_object_object_add(env, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(env, "id", id_copy(id));
    json_object_object_add(env, "result",
                           result ? result : json_object_new_null());
    return env;
}

static struct json_object *error_envelope(struct json_object *id, long code,
                                          const char *msg) {
    struct json_object *env = json_object_new_object();
    struct json_object *err = json_object_new_object();
    json_object_object_add(env, "jsonrpc", json_object_new_string("2.0"));
    json_object_object_add(env, "id", id_copy(id));
    json_object_object_add(err, "code", json_object_new_int((int)code));
    json_object_object_add(err, "message",
                           json_object_new_string(msg ? msg : ""));
    json_object_object_add(env, "error", err);
    return env;
}

/* Wrap a payload in the shape MCP clients expect: text content for a model to
 * read, plus structuredContent for a program. */
static struct json_object *wrap(struct json_object *payload) {
    const char *text =
        json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN);
    struct json_object *res = json_object_new_object();
    struct json_object *content = json_object_new_array();
    struct json_object *part = json_object_new_object();
    struct json_object *meta = json_object_new_object();
    struct json_object *fm = json_object_new_object();
    struct json_object *sc = json_object_new_object();
    json_object_object_add(part, "type", json_object_new_string("text"));
    json_object_object_add(part, "text", json_object_new_string(text ? text : ""));
    json_object_array_add(content, part);
    json_object_object_add(fm, "wrap_result", json_object_new_boolean(1));
    json_object_object_add(meta, "fastmcp", fm);
    json_object_object_add(res, "_meta", meta);
    json_object_object_add(res, "content", content);
    json_object_object_add(sc, "result", json_object_new_string(text ? text : ""));
    json_object_object_add(res, "structuredContent", sc);
    json_object_object_add(res, "isError", json_object_new_boolean(0));
    return res;
}

static struct json_object *dispatch(qrmem_ctx_t *c, struct json_object *req) {
    struct json_object *jmethod = NULL, *jid = NULL, *jparams = NULL;
    const char *method = "";
    /* Liveness on EVERY request, not on writes. An agent can be perfectly
     * alive and simply not have written for minutes; heartbeating only on
     * mutation would have the sweep reclaiming it mid-thought. */
    qrmem_agent_touch(&c->ap, c->agent);
    json_object_object_get_ex(req, "method", &jmethod);
    json_object_object_get_ex(req, "id", &jid);
    json_object_object_get_ex(req, "params", &jparams);
    if (jmethod && json_object_get_type(jmethod) == json_type_string)
        method = json_object_get_string(jmethod);
    if (!jid)
        return NULL; /* notification: silence */
    if (!strcmp(method, "initialize")) {
        struct json_object *res = json_object_new_object();
        struct json_object *caps = json_object_new_object();
        struct json_object *tools = json_object_new_object();
        struct json_object *si = json_object_new_object();
        json_object_object_add(res, "protocolVersion",
                               json_object_new_string(
                                   QRMEM_MCP_PROTOCOL_VERSION));
        json_object_object_add(tools, "listChanged",
                               json_object_new_boolean(0));
        json_object_object_add(caps, "tools", tools);
        json_object_object_add(caps, "experimental",
                               json_object_new_object());
        json_object_object_add(res, "capabilities", caps);
        json_object_object_add(si, "name",
                               json_object_new_string(QRMEM_SERVER_NAME));
        json_object_object_add(si, "version",
                               json_object_new_string(SAPHIRA_VERSION));
        json_object_object_add(res, "serverInfo", si);
        char inst[2048];
        instructions_text(inst, sizeof inst);
        json_object_object_add(res, "instructions",
                               json_object_new_string(inst));
        return result_envelope(jid, res);
    }
    if (!strcmp(method, "tools/list")) {
        struct json_object *res = json_object_new_object();
        json_object_object_add(res, "tools", tools_list());
        return result_envelope(jid, res);
    }
    if (!strcmp(method, "tools/call")) {
        struct json_object *jname = NULL, *jargs = NULL;
        const char *name = "";
        if (jparams) {
            json_object_object_get_ex(jparams, "name", &jname);
            json_object_object_get_ex(jparams, "arguments", &jargs);
        }
        if (jname && json_object_get_type(jname) == json_type_string)
            name = json_object_get_string(jname);
        if (!name[0])
            return error_envelope(jid, -32602,
                                  "Invalid params: missing tool name");
        if (jargs && json_object_get_type(jargs) != json_type_object &&
            json_object_get_type(jargs) != json_type_null)
            return error_envelope(jid, -32602,
                                  "Invalid request parameters");
        {
            struct json_object *payload =
                call_tool(c, name, jargs ? jargs : NULL);
            struct json_object *wrapped = wrap(payload);
            json_object_put(payload);
            return result_envelope(jid, wrapped);
        }
    }
    if (!strcmp(method, "ping"))
        return result_envelope(jid, json_object_new_object());
    return error_envelope(jid, -32601, "Method not found");
}

/* ------------------------------------------------------------------ serve mode */

/* The control socket.
 *
 * Length-prefixed JSON over AF_UNIX, one request per connection, request and
 * reply on the same socket. Deliberately small: the socket exists so a process
 * that is NOT in this uid can still be refused politely and so an operator can
 * poke the fabric. It is not the data path, and it is not where a hot-path
 * reader goes.
 *
 * A connection is served on its own thread so a reader cannot starve the daemon,
 * but the fabric itself is what enforces correctness: the one-writer rule lives
 * in the aperture, not in this loop. */
#define QRMEM_MAX_CONNS 16

static int serve_listen(const char *path, char *err, size_t errlen) {
    int fd;
    struct sockaddr_un sa;
    if (strlen(path) >= sizeof sa.sun_path) {
        set_err(err, errlen, "socket path is too long (max %zu bytes)",
                sizeof sa.sun_path - 1u);
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        set_err(err, errlen, "socket: %s", strerror(errno));
        return -1;
    }
    unlink(path);
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    /* Bounded explicitly: the length was checked above, but the compiler
     * cannot see through that and -Werror=format-truncation is not something
     * to appease with a pragma. */
    snprintf(sa.sun_path, sizeof sa.sun_path, "%.*s",
             (int)sizeof sa.sun_path - 1, path);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        set_err(err, errlen, "bind %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    /* 0600: the socket grants access to one uid. Tile ownership inside the
     * fabric is enforced by agent id, so the mode here is a coarse outer gate,
     * not the rule itself. */
    if (chmod(path, 0600) != 0) {
        set_err(err, errlen, "chmod %s: %s", path, strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }
    if (listen(fd, 8) != 0) {
        set_err(err, errlen, "listen %s: %s", path, strerror(errno));
        close(fd);
        unlink(path);
        return -1;
    }
    return fd;
}

static int read_frame(int fd, char *buf, size_t cap) {
    /* 4-byte big-endian length, then the body. The length arrives before the
     * body exists, which is why it is checked against a ceiling here rather
     * than trusted: a corrupt length must never become an allocation. */
    unsigned char lb[4];
    size_t got = 0, want;
    while (got < 4) {
        ssize_t n = read(fd, lb + got, 4 - got);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    want = ((size_t)lb[0] << 24) | ((size_t)lb[1] << 16) | ((size_t)lb[2] << 8) |
           (size_t)lb[3];
    if (want == 0 || want + 1u > cap)
        return -1;
    got = 0;
    while (got < want) {
        ssize_t n = read(fd, buf + got, want - got);
        if (n <= 0)
            return -1;
        got += (size_t)n;
    }
    buf[want] = '\0';
    return (int)want;
}

static int write_frame(int fd, const char *body, size_t len) {
    unsigned char lb[4];
    size_t off = 0;
    lb[0] = (unsigned char)((len >> 24) & 0xFFu);
    lb[1] = (unsigned char)((len >> 16) & 0xFFu);
    lb[2] = (unsigned char)((len >> 8) & 0xFFu);
    lb[3] = (unsigned char)(len & 0xFFu);
    if (write(fd, lb, 4) != 4)
        return -1;
    while (off < len) {
        ssize_t n = write(fd, body + off, len - off);
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

/* One connection, on its own thread. The context is shared read-mostly; the
 * fabric serialises writers, and the socket only decides who gets to ask. */
typedef struct {
    qrmem_ctx_t *ctx;
    int fd;
    uint32_t leased_slot; /* 0 until this connection says hello */
} qrmem_conn_t;

static void *serve_conn(void *arg) {
    qrmem_conn_t *cc = (qrmem_conn_t *)arg;
    qrmem_ctx_t *c = cc->ctx;
    int fd = cc->fd;
    char *buf = malloc(1024u * 1024u);
    char *out = malloc(1024u * 1024u);
    if (!buf || !out) {
        free(buf);
        free(out);
        close(fd);
        return NULL;
    }
    for (;;) {
        int n = read_frame(fd, buf, 1024u * 1024u);
        struct json_object *req, *payload;
        const char *text;
        if (n < 0)
            break;
        req = json_tokener_parse(buf);
        if (!req) {
            const char *m = "{\"error\":\"parse error\"}";
            write_frame(fd, m, strlen(m));
            continue;
        }
        /* Two kinds of frame share this socket.
         *
         * op=hello is the LEASE. It is not a tool call and it does not go
         * through call_tool: it names an identity, takes a lease, and then the
         * connection simply stays open. Holding that connection is the whole
         * liveness contract, so the daemon must never write to it unsolicited -
         * an unprompted write to a client that never reads would eventually
         * block on a full buffer and wedge the connection thread.
         *
         * tool= is the operator poking path, unchanged. */
        {
            struct json_object *jop = json_object_object_get(req, "op");
            if (jop && json_object_get_type(jop) == json_type_string &&
                !strcmp(json_object_get_string(jop), "hello")) {
                struct json_object *who =
                    json_object_object_get(req, "agent");
                struct json_object *rep = json_object_new_object();
                if (!who || json_object_get_type(who) != json_type_string) {
                    json_object_object_add(rep, "ok",
                                           json_object_new_boolean(0));
                    json_object_object_add(rep, "error",
                                           json_object_new_string("hello "
                                                                 "requires an "
                                                                 "agent name"));
                } else {
                    const char *name = json_object_get_string(who);
                    uint32_t slot = 0, gen = 0;
                    char herr[256] = "";
                    if (qrmem_agent_claim(&c->ap, name, &slot, &gen, herr,
                                          sizeof herr) != 0) {
                        json_object_object_add(rep, "ok",
                                               json_object_new_boolean(0));
                        json_object_object_add(rep, "error",
                                               json_object_new_string(herr));
                    } else {
                        qrmem_agent_lease(&c->ap, slot);
                        cc->leased_slot = slot;
                        json_object_object_add(rep, "ok",
                                               json_object_new_boolean(1));
                        json_object_object_add(rep, "agent",
                                               json_object_new_string(name));
                        json_object_object_add(
                            rep, "slot",
                            json_object_new_int64((int64_t)slot));
                        /* The generation is part of the lease: a slot
                         * number alone is never authority, so the
                         * client must learn which allocation it holds. */
                        json_object_object_add(
                            rep, "agent_gen",
                            json_object_new_int64((int64_t)gen));
                        /* Third element of the fence: without it a client
                         * that survives a daemon restart cannot tell that
                         * the authority it leased from is gone. */
                        json_object_object_add(
                            rep, "authority_gen",
                            json_object_new_int64((int64_t)atomic_load_explicit(
                                (&c->ap.hdr->authority_gen),
                                memory_order_acquire)));
                        /* WHICH FABRIC. The socket and the aperture are two
                         * independent arguments, so a client can name a socket
                         * from one daemon and an aperture from another and
                         * otherwise appear to work: it would hold a lease in the
                         * first fabric while reading and writing the second, and
                         * every write would be refused as "not yours" against a
                         * screen it appears to own. Saying which fabric this is
                         * lets the client refuse the mismatch outright instead. */
                        json_object_object_add(
                            rep, "aperture",
                            json_object_new_string(c->aperture));
                        json_object_object_add(
                            rep, "abi_major",
                            json_object_new_int64(
                                (int64_t)QRMEM_ABI_MAJOR));
                        json_object_object_add(
                            rep, "planes",
                            json_object_new_int64(
                                (int64_t)qrmem_agent_lease_held(&c->ap, slot)));
                    }
                }
                text = json_object_to_json_string_ext(rep,
                                                      JSON_C_TO_STRING_PLAIN);
                if (text)
                    write_frame(fd, text, strlen(text));
                json_object_put(rep);
                json_object_put(req);
                continue;
            }
            payload = json_object_object_get(req, "tool") ? call_tool(
                                  c, json_object_get_string(
                                         json_object_object_get(req, "tool")),
                                  json_object_object_get(req, "arguments"))
                                                      : err_obj(
                                                            "expected {\"op\":"
                                                            "\"hello\",...} or "
                                                            "{\"tool\":\"...\""
                                                            ",\"arguments\":{"
                                                            "...}}");
        }
        text = json_object_to_json_string_ext(payload, JSON_C_TO_STRING_PLAIN);
        if (text)
            write_frame(fd, text, strlen(text));
        json_object_put(payload);
        json_object_put(req);
    }
    /* The connection ended, for any reason including a crash the peer never
     * got to report. The kernel has already closed its descriptor, so this is
     * the OS telling us the process is gone - not a timeout guessing at it. The
     * last lease to go takes the agent and every screen it held with it. */
    if (cc->leased_slot)
        qrmem_agent_unlease(&c->ap, cc->leased_slot);
    close(fd);
    free(buf);
    free(out);
    free(cc);
    return NULL;
}

static int run_serve(qrmem_ctx_t *c, const char *sockpath, int recreate) {
    char err[512] = "";
    int lfd;
    qrmem_ap_path_of(c->aperture, c->aperture_path, sizeof c->aperture_path);
    fprintf(stderr, "%s: fabric %s, socket %s\n", QRMEM_SERVER_NAME,
            c->aperture_path, sockpath);
    if (recreate)
        qrmem_aperture_unlink(c->aperture);
    /* Before anything else: if the restore point cannot be written, say so now
     * rather than discovering it after the next reboot. */
    if (c->snapshot[0])
        ensure_snapshot_dir(c->snapshot);
    /* CREATE the fabric if there is none; ATTACH to it if there is.
     *
     * This branch is the other half of not unlinking on exit. While the daemon
     * deleted its own segment on a clean stop, every start was necessarily a
     * first start, so create-only was sufficient - and a second daemon could
     * only ever fail. Now the segment deliberately outlives the process, so the
     * ordinary restart path is: the segment is already there, the new daemon
     * attaches to the SAME fabric, and the fabric keeps its identity.
     *
     * If neither create nor attach succeeds, the fabric is genuinely unusable
     * and the error is reported rather than papered over by starting empty: an
     * empty fabric that looks healthy is worse than a refusal. */
    if (qrmem_aperture_create(&c->ap, c->aperture, err, sizeof err) != 0) {
        char aerr[512] = "";
        if (qrmem_aperture_attach(&c->ap, c->aperture, aerr,
                                  sizeof aerr) == 0) {
            fprintf(stderr,
                    "%s: fabric %s already existed; attaching to it and "
                    "keeping its identity\n",
                    QRMEM_SERVER_NAME, c->aperture_path);
        } else {
            fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, err);
            fprintf(stderr, "%s: and it could not be attached to either: %s\n",
                    QRMEM_SERVER_NAME, aerr);
            return QRMEM_EXIT_CONFIG;
        }
    }
    /* The authority states its own hostname, once per bind.
     *
     * This is the source every lease granted in this incarnation will report,
     * and it is written here - by the daemon, from the kernel - rather than
     * accepted from any client. A caller-supplied host would be attribution by
     * the attributed: the --host flag and the hello greeting both stay purely
     * descriptive and never reach this field. A rename is picked up on the next
     * bind, which is exactly right for data that describes rather than
     * identifies. */
    {
        char hn[QRMEM_AUTHORITY_HOST_MAX];
        if (gethostname(hn, sizeof hn) == 0) {
            hn[sizeof hn - 1u] = '\0';
            snprintf(c->ap.hdr->authority_host,
                     sizeof c->ap.hdr->authority_host, "%s", hn);
        }
    }
    /* A restart is a new epoch, so anything in flight from a previous
     * incarnation is provably stale rather than mysteriously wrong.
     *
     * Epoch and authority move on a restart. Fabric identity does NOT: it is
     * read from the fabric and never rewritten here, which is what makes a
     * qualified address stable across the restart that invalidates every lease. */
    qrmem_aperture_bump_epoch(&c->ap);
    /* Restore AFTER the new authority has been minted, never before.
     *
     * The order is the whole contract. The fabric now has a fresh
     * authority_gen, zero leases and zero owners; restoring page content on top
     * of that adds records and labels and nothing else. Restoring first and
     * bumping after would work too only by accident of ordering, and would leave
     * a window in which the segment holds a previous incarnation's owners. */
    if (c->snapshot[0]) {
        char serr[512] = "";
        int got = qrmem_snapshot_load(&c->ap, c->snapshot, serr, sizeof serr);
        if (got < 0) {
            /* Not fatal and not silent. The fabric is usable and empty; the
             * operator is told their restore point is bad, because silently
             * starting empty is how a real page goes missing twice. */
            fprintf(stderr, "%s: RESTORE POINT UNUSABLE: %s\n",
                    QRMEM_SERVER_NAME, serr);
            fprintf(stderr,
                    "%s: starting with an empty fabric. The restore point has "
                    "been left in place; move it aside to start clean, or fix "
                    "it and restart.\n",
                    QRMEM_SERVER_NAME);
        } else if (got > 0) {
            fprintf(stderr,
                    "%s: restored page contents from %s; authority is new, no "
                    "screen has an owner, every page needs re-joining\n",
                    QRMEM_SERVER_NAME, c->snapshot);
            /* The restore reports what it rebuilt, including any index entries it
             * could not rebuild. A shortfall is printed rather than swallowed: a
             * record whose lookup key no longer resolves is exactly the silent
             * loss of a discovery handle this path exists to prevent. */
            if (serr[0])
                fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, serr);
        } else {
            fprintf(stderr, "%s: no restore point at %s; starting empty\n",
                    QRMEM_SERVER_NAME, c->snapshot);
        }
    }
    lfd = serve_listen(sockpath, err, sizeof err);
    if (lfd < 0) {
        fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, err);
        qrmem_aperture_unlink(c->aperture);
        qrmem_aperture_detach(&c->ap);
        return QRMEM_EXIT_CONFIG;
    }
    fprintf(stderr,
            "%s: epoch %llu, %u screens, each a %ux%u module code plane in "
            "%u blocks of %ux%u holding %u records, listening\n",
            QRMEM_SERVER_NAME, (unsigned long long)qrmem_epoch(&c->ap),
            QRMEM_SCREENS, QRMEM_PLANE_DIM, QRMEM_PLANE_DIM,
            QRMEM_BLOCKS_PER_SCREEN, QRMEM_BLOCK_DIM, QRMEM_BLOCK_DIM,
            QRMEM_RECORDS_PER_SCREEN);
    while (!saphira_should_stop()) {
        int cfd = accept(lfd, NULL, NULL);
        qrmem_conn_t *cc;
        pthread_t th;
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        cc = malloc(sizeof *cc);
        if (!cc) {
            close(cfd);
            continue;
        }
        cc->ctx = c;
        cc->fd = cfd;
        cc->leased_slot = 0;
        if (pthread_create(&th, NULL, serve_conn, cc) != 0) {
            close(cfd);
            free(cc);
            continue;
        }
        pthread_detach(th);
    }
    /* Save the durable shadow while the aperture still exists. This runs on a
     * clean exit; a SIGKILL or power loss is exactly why the file is written
     * with fsync and renamed atomically, so the previous complete save survives
     * even when this one never happens. */
    if (c->snapshot[0]) {
        char werr[512] = "";
        if (qrmem_snapshot_save(&c->ap, c->snapshot, werr, sizeof werr) != 0)
            fprintf(stderr, "%s: could not save page contents to %s: %s\n",
                    QRMEM_SERVER_NAME, c->snapshot, werr);
        else if (werr[0])
            fprintf(stderr, "%s: saved %s to %s\n", QRMEM_SERVER_NAME, werr,
                    c->snapshot);
    }
    close(lfd);
    unlink(sockpath);
    /* The aperture is DELIBERATELY NOT unlinked on a clean exit.
     *
     * It used to be, and that quietly made every daemon restart a brand-new
     * namespace. Content and project labels came back from the snapshot, so the
     * damage was invisible: the fabric looked continuous while its identity was
     * not. That is precisely the illusion this fabric must not have, because a
     * qualified address (fabric_id, screen) is a claim that two references name
     * the same place - and with a fresh id on every restart, every address ever
     * written stopped being true the moment a daemon cycled.
     *
     * So the segment outlives the process that created it, and the next start
     * ATTACHES to it: same fabric, same identity, new authority generation.
     * Ownership and leases are still re-minted on every bind, so nothing
     * survives that ought not to; only the namespace and its identity do.
     *
     * A genuinely NEW fabric is still one deliberate operator action: --recreate
     * unlinks, mints a new id, and restores content from the snapshot into it. */
    qrmem_aperture_detach(&c->ap);
    return QRMEM_EXIT_OK;
}

static int run_stdio(qrmem_ctx_t *c, const char *agent,
                     const char *stable_id, const char *sockpath) {
    char err[512] = "";
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    if (qrmem_aperture_attach(&c->ap, c->aperture, err, sizeof err) != 0) {
        fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, err);
        fprintf(stderr,
                "%s: start the fabric first: %s --serve --agent <id>\n",
                QRMEM_SERVER_NAME, QRMEM_SERVER_NAME);
        return QRMEM_EXIT_CONFIG;
    }
    snprintf(c->agent_label, sizeof c->agent_label, "%s", agent);
    mint_identity(c->agent_name, sizeof c->agent_name, agent, stable_id);
    snprintf(g_client_identity, sizeof g_client_identity, "%s",
             c->agent_name);
    /* The slot comes from the fabric's agent registry, matched on the exact
     * name. It is deliberately NOT derived from a hash of the name: two
     * identities that collided would become one, and the second would then pass
     * the idempotent "this screen is already mine" claim check and write the
     * first agent's tile. That bug shipped in the first version of this file and
     * was caught only by asking two agents to claim the same screen.
     *
     * It registers c->agent_name, the MINTED identity, not the label. An
     * intermediate version of this fix registered the label while displaying the
     * minted identity, so every session still collapsed onto one slot and the
     * one-writer rule stayed void - and the status output looked correct, which
     * is the worst way for it to fail. The smoke test that starts two sessions
     * and compares slots is what caught it. */
    /* Take the lease BEFORE claiming a slot. The daemon names us on the socket
     * and hands back the slot, so identity comes from the authority rather than
     * being asserted by the client and trusted. */
    {
        uint32_t leased = 0, leased_gen = 0, leased_auth = 0;
        pthread_t watcher;
        char said_aperture[512] = "";
        int lfd = lease_connect(sockpath, &leased, &leased_gen, &leased_auth,
                                said_aperture, sizeof said_aperture, err,
                                sizeof err);
        if (lfd < 0) {
            fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, err);
            fprintf(stderr,
                    "%s: the fabric lease is what makes a tile yours. Start the "
                    "daemon with --serve, or pass --socket.\n",
                    QRMEM_SERVER_NAME);
            qrmem_aperture_detach(&c->ap);
            return QRMEM_EXIT_CONFIG;
        }
        /* REFUSE A FABRIC MISMATCH. Holding a lease from one fabric while
         * reading and writing another is not a degraded mode, it is a lie: the
         * writes are all refused, and the agent's own status shows screens it
         * believes are its own. Better to fail at startup with both names in
         * the message. */
        if (said_aperture[0] && strcmp(said_aperture, c->aperture) != 0) {
            fprintf(stderr,
                    "%s: the daemon at %s is serving fabric %s, but --aperture "
                    "opened %s. Those are different fabrics; a lease from one "
                    "grants nothing in the other. Fix one of the two arguments.\n",
                    QRMEM_SERVER_NAME, sockpath, said_aperture, c->aperture);
            qrmem_aperture_detach(&c->ap);
            return QRMEM_EXIT_CONFIG;
        }
        c->agent = leased;
        c->agent_gen = leased_gen;
        c->authority_gen = leased_auth;
        c->ap.self_agent = leased;
        g_lease_fd = lfd;
        if (pthread_create(&watcher, NULL, lease_watch,
                           (void *)(intptr_t)lfd) == 0)
            pthread_detach(watcher);
        fprintf(stderr, "%s: lease held as %s (slot %u)\n", QRMEM_SERVER_NAME,
                c->agent_name, leased);
    }
    while (!saphira_should_stop() && !g_lease_lost &&
           (n = getline(&line, &cap, stdin)) >= 0) {
        struct json_object *req, *resp;
        if ((size_t)n > 8u * 1024u * 1024u) {
            int ch;
            emit(error_envelope(NULL, -32700, "Parse error: message too large"));
            if (line[n - 1] != '\n')
                while ((ch = getchar()) != '\n' && ch != EOF) {
                }
            continue;
        }
        req = json_tokener_parse(line);
        if (!req) {
            emit(error_envelope(NULL, -32700, "Parse error"));
            continue;
        }
        resp = dispatch(c, req);
        json_object_put(req);
        if (resp)
            emit(resp);
    }
    free(line);
    if (g_lease_lost)
        fprintf(stderr,
                "%s: the fabric lease ended, so this session no longer owns "
                "anything it was given. Stopping rather than reading a fabric "
                "nobody else can reach.\n",
                QRMEM_SERVER_NAME);
    /* Closing the lease descriptor is the release. The daemon sees end-of-file
     * and drops the slot and its screens; we do not have to, and must not, drop
     * them ourselves, or the two sides could disagree about who owns a tile. */
    if (g_lease_fd >= 0)
        close(g_lease_fd);
    qrmem_aperture_detach(&c->ap);
    return g_lease_lost ? QRMEM_EXIT_CONFIG : QRMEM_EXIT_OK;
}

static void usage(void) {
    fprintf(stderr,
            "%s %s - tile fabric and MCP window\n"
            "\n"
            "usage:\n"
            "  %s --serve [--socket PATH] [--aperture PATH] [--recreate]\n"
            "                [--snapshot PATH] [--no-snapshot]\n"
            "  %s --stdio  [--agent LABEL] [--agent-id ID] [--aperture PATH]\n"
            "               [--socket PATH] [--snapshot PATH] [--no-snapshot]\n"
            "  %s --doctor\n"
            "  %s --inspect-screen N   report one screen's metadata, changing "
            "nothing\n"
            "  %s --export-tile S:B:L --output FILE.pbm [--aperture PATH]\n"
            "                        export one red QR tile as a lossless PBM image\n"
            "  %s --repair-project N --project LABEL [--recovery-log PATH] "
            "[--dry-run]\n"
            "                        OPERATOR ONLY: correct a page's project "
            "label. Metadata\n"
            "                        only; never touches a record. Requires "
            "the screen unowned,\n"
            "                        and logs every repair. Not an MCP "
            "tool.\n"
            "  %s --version\n"
            "\n"
            "The fabric is a shared-memory aperture of %u screens. One agent\n"
            "owns each screen and is its only writer; every agent may read\n"
            "every screen live. The default aperture is\n"
            "/dev/shm/%s-<uid> and the default control socket is\n"
            "$XDG_RUNTIME_DIR/%s.sock.\n"
            "\n"
            "This surface is the control plane. It holds no database and writes\n"
            "no SQL: promoting a tile record to durable memory is an explicit\n"
            "agent decision made with the ordinary memory tools.\n"
            "\n"
            "--agent is a LABEL. Each process mints a unique identity from it\n"
            "(label#suffix) so that two sessions sharing a label cannot share\n"
            "write authority over one tile. Pass --agent-id only when a STABLE\n"
            "identity across restarts is actually wanted, such as a supervised\n"
            "daemon.\n"
            "\n"
            "RECORD IDS ARE UUIDs, not integers or labels. Omit the id argument\n"
            "and the fabric mints one. --socket and --aperture must name the\n"
            "SAME fabric: a lease from one daemon grants nothing in another\n"
            "segment, and the client refuses that combination at startup rather\n"
            "than appearing to work.\n"
            "\n"
            "The aperture lives in /dev/shm and is wiped on reboot, so the daemon\n"
            "keeps a durable restore point. Content and project labels come back;\n"
            "authority does not - a fresh authority generation is minted, leases\n"
            "are zeroed and no screen owner is restored, so a dead writer can\n"
            "never come back. Restart your session after a daemon restart.\n",
            QRMEM_SERVER_NAME, SAPHIRA_VERSION, QRMEM_SERVER_NAME,
            QRMEM_SERVER_NAME, QRMEM_SERVER_NAME, QRMEM_SERVER_NAME,
            QRMEM_SERVER_NAME, QRMEM_SERVER_NAME, QRMEM_SERVER_NAME,
            QRMEM_SCREENS, QRMEM_DEFAULT_NAME, QRMEM_DEFAULT_NAME);
}

static const char *flag_val(int argc, char **argv, int *i) {
    const char *a = argv[*i];
    const char *eq = strchr(a, '=');
    if (eq)
        return eq + 1;
    if (*i + 1 < argc)
        return argv[++(*i)];
    return NULL;
}

int main(int argc, char **argv) {
    qrmem_ctx_t c;
    char sockpath[512] = "";
    const char *agent = "opencode";
    const char *stable_id = NULL;
    int mode = 0, recreate = 0;
    long inspect_screen = -1, repair_screen = -1;
    long export_screen = -1, export_block = -1, export_slot = -1;
    char export_path[1024] = "";
    int dry_run = 0;
    char repair_project[QRMEM_PROJECT_MAX + 1] = "";
    char recovery_log_path[1024] = "";
    memset(&c, 0, sizeof c);
    host_default(c.agent_host, sizeof c.agent_host);
    install_signals();
    default_aperture_path(c.aperture, sizeof c.aperture);
    default_snapshot_path(c.aperture, c.snapshot, sizeof c.snapshot);
    qrmem_ap_path_of(c.aperture, c.aperture_path, sizeof c.aperture_path);
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *v;
        if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
            usage();
            return QRMEM_EXIT_OK;
        }
        if (!strcmp(a, "--version") || !strcmp(a, "-V")) {
            printf("%s %s (Saphira Memory tile fabric)\n", QRMEM_SERVER_NAME,
                   SAPHIRA_VERSION);
            return QRMEM_EXIT_OK;
        }
        if (!strcmp(a, "--serve")) {
            mode = 1;
            continue;
        }
        if (!strcmp(a, "--stdio")) {
            mode = 2;
            continue;
        }
        if (!strcmp(a, "--doctor")) {
            mode = 3;
            continue;
        }
        /* Operator recovery. Read-only inspection, or a metadata-only repair.
         * Deliberately CLI-only and not an MCP tool: see qrmem_recover.c. */
        if (!strncmp(a, "--inspect-screen", 16)) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            inspect_screen = strtol(v, NULL, 10);
            mode = 4;
            continue;
        }
        if (!strncmp(a, "--repair-project", 16)) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            repair_screen = strtol(v, NULL, 10);
            mode = 5;
            continue;
        }
        if (!strncmp(a, "--export-tile", 13)) {
            char extra[2];
            v = flag_val(argc, argv, &i);
            if (!v || sscanf(v, "%ld:%ld:%ld%1s", &export_screen, &export_block,
                             &export_slot, extra) != 3)
                return QRMEM_EXIT_USAGE;
            mode = 6;
            continue;
        }
        if (!strncmp(a, "--output", 8)) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            snprintf(export_path, sizeof export_path, "%s", v);
            continue;
        }
        if (!strncmp(a, "--project", 9)) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            snprintf(repair_project, sizeof repair_project, "%s", v);
            continue;
        }
        if (!strcmp(a, "--dry-run")) {
            dry_run = 1;
            continue;
        }
        if (!strncmp(a, "--recovery-log", 14)) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            snprintf(recovery_log_path, sizeof recovery_log_path, "%s", v);
            continue;
        }
        if (!strcmp(a, "--recreate")) {
            recreate = 1;
            continue;
        }
        if (!strncmp(a, "--socket", 8)) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            snprintf(sockpath, sizeof sockpath, "%s", v);
            continue;
        }
        if (!strncmp(a, "--aperture", 10)) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            if (qrmem_ap_name_of(v, c.aperture, sizeof c.aperture) != 0) {
                fprintf(stderr,
                        "%s: --aperture must be a shared-memory name or a "
                        "/dev/shm path, one leading slash and no others\n",
                        QRMEM_SERVER_NAME);
                return QRMEM_EXIT_USAGE;
            }
            qrmem_ap_path_of(c.aperture, c.aperture_path,
                             sizeof c.aperture_path);
            /* The restore point is derived from the aperture, so a custom
             * aperture gets its own restore point rather than quietly sharing
             * the default one. */
            default_snapshot_path(c.aperture, c.snapshot, sizeof c.snapshot);
            continue;
        }
        if (!strcmp(a, "--host")) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            snprintf(c.agent_host, sizeof c.agent_host, "%s", v);
            continue;
        }
        if (!strncmp(a, "--snapshot", 10)) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            snprintf(c.snapshot, sizeof c.snapshot, "%s", v);
            continue;
        }
        if (!strcmp(a, "--no-snapshot")) {
            c.snapshot[0] = '\0';
            continue;
        }
        if (!strncmp(a, "--agent-id", 10)) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            stable_id = v;
            continue;
        }
        if (!strncmp(a, "--agent", 7)) {
            v = flag_val(argc, argv, &i);
            if (!v)
                return QRMEM_EXIT_USAGE;
            agent = v;
            continue;
        }
        fprintf(stderr, "%s: unknown argument '%s'\n", QRMEM_SERVER_NAME, a);
        usage();
        return QRMEM_EXIT_USAGE;
    }
    if (!sockpath[0] && default_socket_path(sockpath, sizeof sockpath) != 0) {
        fprintf(stderr,
                "%s: no writable runtime directory for the control socket "
                "(tried $XDG_RUNTIME_DIR, /run/user/%u, and a private /tmp "
                "directory); pass --socket PATH\n",
                QRMEM_SERVER_NAME, (unsigned)getuid());
        return QRMEM_EXIT_CONFIG;
    }
    if (mode == 1)
        return run_serve(&c, sockpath, recreate);
    if (mode == 2)
        return run_stdio(&c, agent, stable_id, sockpath);
    if (mode == 3) {
        char err[512] = "";
        int rc = qrmem_aperture_attach(&c.ap, c.aperture, err, sizeof err);
        if (rc == 0) {
            qrmem_uuid_t fid;
            char idtxt[QRMEM_UUID_TEXT_LEN + 1];
            if (qrmem_fabric_id(&c.ap, &fid) == 0 &&
                qrmem_uuid_text(&fid, idtxt, sizeof idtxt) == 0)
                printf("fabric:   %s\n", idtxt);
        }
        {
            char rd[512] = "";
            runtime_dir(rd, sizeof rd);
            printf("aperture: %s\n", c.aperture_path);
            printf("socket:   %s\n", sockpath);
            printf("runtime:  %s%s\n", rd,
                   getenv("XDG_RUNTIME_DIR") && rd[0] &&
                           !strcmp(rd, getenv("XDG_RUNTIME_DIR"))
                       ? " (from XDG_RUNTIME_DIR)"
                       : " (fallback)");
        }
        if (rc != 0) {
            printf("status:   unreachable (%s)\n", err);
            return QRMEM_EXIT_CONFIG;
        }
        printf("status:   live\n");
        printf("epoch:    %llu\n", (unsigned long long)qrmem_epoch(&c.ap));
        printf("era:      %u\n", qrmem_era(&c.ap));
        for (uint32_t s = 0; s < QRMEM_SCREENS; s++) {
            uint32_t owner = qrmem_screen_owner(&c.ap, s);
            printf("screen %u: owner %s generation %llu writes %llu index "
                   "%u/%u\n",
                   s, owner ? "yes" : "no",
                   (unsigned long long)qrmem_generation(&c.ap, s),
                   (unsigned long long)qrmem_write_count(&c.ap, s),
                   qrmem_index_used(&c.ap, s), QRMEM_INDEX_ENTRIES);
        }
        qrmem_aperture_detach(&c.ap);
        return QRMEM_EXIT_OK;
    }
    if (mode == 6) {
        char err[512] = "";
        if (!export_path[0] || export_screen < 0 || export_block < 0 || export_slot < 0 ||
            (uint32_t)export_screen >= QRMEM_SCREENS ||
            (uint32_t)export_block >= QRMEM_BLOCKS_PER_SCREEN ||
            (uint32_t)export_slot >= QRMEM_SLOTS_PER_BLOCK) {
            fprintf(stderr, "%s: --export-tile needs S:B:L within the fabric and --output FILE.pbm\n", QRMEM_SERVER_NAME);
            return QRMEM_EXIT_USAGE;
        }
        if (qrmem_aperture_attach(&c.ap, c.aperture, err, sizeof err) != 0) {
            fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, err);
            return QRMEM_EXIT_CONFIG;
        }
        if (qrmem_plane_export_tile_pbm(&c.ap, (uint32_t)export_screen,
                                        (uint32_t)export_block, (uint32_t)export_slot,
                                        export_path, err, sizeof err) != 0) {
            fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, err);
            qrmem_aperture_detach(&c.ap);
            return QRMEM_EXIT_CONFIG;
        }
        qrmem_aperture_detach(&c.ap);
        printf("exported red QR tile screen=%ld block=%ld slot=%ld to %s\n",
               export_screen, export_block, export_slot, export_path);
        return QRMEM_EXIT_OK;
    }
    if (mode == 4 || mode == 5) {
        char err[512] = "";
        long target = (mode == 4) ? inspect_screen : repair_screen;
        char project[QRMEM_PROJECT_MAX + 1];
        uint64_t writes = 0, gen = 0, idx = 0;
        uint32_t owner = 0;
        if (qrmem_aperture_attach(&c.ap, c.aperture, err, sizeof err) != 0) {
            fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, err);
            return QRMEM_EXIT_CONFIG;
        }
        if (qrmem_recover_inspect(&c.ap, (uint32_t)(target < 0 ? 0 : target),
                                 project, sizeof project, &writes, &owner,
                                 &gen, &idx, err, sizeof err) != 0) {
            fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, err);
            qrmem_aperture_detach(&c.ap);
            return QRMEM_EXIT_USAGE;
        }
        printf("index_used:  %llu\n", (unsigned long long)idx);
        /* The audit destination is resolved BEFORE anything is printed, so the
         * report is a faithful preview of the real run rather than a first draft
         * with the destination still to be decided. */
        qrmem_uuid_t fidbuf;
        char fidtxt[QRMEM_UUID_TEXT_LEN + 1];
        fidtxt[0] = '\0';
        if (qrmem_fabric_id(&c.ap, &fidbuf) == 0)
            (void)qrmem_uuid_text(&fidbuf, fidtxt, sizeof fidtxt);
        if (!recovery_log_path[0] && c.snapshot[0]) {
            /* The audit lives beside the restore point, so an operator who
             * repairs metadata and then looks at the restore point finds both.
             *
             * Bounded explicitly. The snapshot path can already be near the
             * buffer limit, so an unbounded "%s.recovery" could truncate SILENTLY
             * and send the audit to a different filename than the one intended -
             * which for an audit file is worse than not writing it, because the
             * repair then looks unlogged when it was logged somewhere nobody
             * will look. Caught by the surface-truth gate, which is what it is
             * for. */
            snprintf(recovery_log_path, sizeof recovery_log_path,
                     "%.1000s.recovery", c.snapshot);
        }
        /* The fabric identity, so an operator reading this output can tell WHICH
         * fabric they are looking at. Two machines can carry an identical
         * aperture name and different fabrics, and this output is frequently
         * the first thing pasted into a shared channel. */
        {
            qrmem_uuid_t fid;
            char idtxt[QRMEM_UUID_TEXT_LEN + 1];
            if (qrmem_fabric_id(&c.ap, &fid) == 0 &&
                qrmem_uuid_text(&fid, idtxt, sizeof idtxt) == 0)
                printf("fabric:      %s\n", idtxt);
            printf("host:        %s\n", c.agent_host);
        }
        printf("screen:      %ld\n", target);
        printf("address:     fabric=%s screen=%ld\n",
               (qrmem_fabric_id(&c.ap, &fidbuf) == 0)
                   ? fidtxt : "(none)", target);
        printf("current:     %s\n", project[0] ? project : "(none)");
        printf("proposed:    %s\n", repair_project);
        printf("writes:      %llu\n", (unsigned long long)writes);
        printf("generation:  %llu\n", (unsigned long long)gen);
        printf("owner:       %s\n", owner ? "yes" : "no");
        printf("audit log:   %s\n", recovery_log_path);
        if (mode == 4) {
            qrmem_aperture_detach(&c.ap);
            return QRMEM_EXIT_OK;
        }
        if (!recovery_log_path[0]) {
            fprintf(stderr,
                    "%s: refusing an unlogged repair. Pass --recovery-log "
                    "PATH; a silent metadata edit on a shared surface cannot be "
                    "reconstructed afterwards.\n",
                    QRMEM_SERVER_NAME);
            qrmem_aperture_detach(&c.ap);
            return QRMEM_EXIT_USAGE;
        }
        if (qrmem_recover_project(&c.ap, (uint32_t)(target < 0 ? 0 : target),
                                  repair_project, recovery_log_path, dry_run,
                                  err, sizeof err) != 0) {
            fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, err);
            qrmem_aperture_detach(&c.ap);
            return QRMEM_EXIT_USAGE;
        }
        if (dry_run)
            printf("dry run:     NO CHANGES WRITTEN\n");
        else
            printf("repaired:    project is now \"%s\"\n", repair_project);
        if (err[0])
            fprintf(stderr, "%s: %s\n", QRMEM_SERVER_NAME, err);
        qrmem_aperture_detach(&c.ap);
        return QRMEM_EXIT_OK;
    }
    usage();
    return QRMEM_EXIT_USAGE;
}
