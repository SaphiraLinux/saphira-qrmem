/* Saphira Memory - operator recovery for fabric metadata.
 *
 * THE ONLY WRITE PATH THAT TOUCHES DURABLE METADATA DIRECTLY.
 *
 * A page's project label is immutable once it has published records. That rule
 * is deliberately one-directional and it is enforced against AGENTS: an agent
 * that mislabels a page cannot then correct it, because a label other agents may
 * have already found is not the writer's private scratch. That is the right
 * default and it stays the right default.
 *
 * But "the right default" and "the only possible thing" are different claims,
 * and holding both was a mistake. An OPERATOR repairing metadata damaged by a
 * fabric bug is a different act from an agent tidying its own page: one is
 * recovery of state that should never have been wrong, the other is an agent
 * rewriting history that other agents may have cited.
 *
 * This is the first. It exists because a real defect allowed exactly that
 * damage: a restored page carrying 11 records under `saphira-expanderllm` was
 * relabelled to `relabel-probe` by its first post-restore claim, because the
 * immutability guard lived only in the already-owned branch and a restored page
 * is deliberately unowned. The guard is fixed, but the label that was already
 * damaged still needs correcting, and there was no way to do it that did not
 * involve deleting records.
 *
 * WHAT IT WILL NOT DO:
 *
 *   - It never touches a record. Not the content, not the identity, not the
 *     links, not the index keys. Repair is metadata-only by construction: the
 *     functions below take a screen and a string, and there is no code path here
 *     that can address a cell at all.
 *   - It is not reachable from the MCP surface. There is no tool that calls it,
 *     and adding one is a decision for a later slice, not something to slip in
 *     here. Today it is a CLI verb on the daemon binary, which means running it
 *     requires the same access as starting the fabric.
 *   - It does not bypass the one-way rule for an agent. An agent still cannot
 *     relabel a populated page; the CLI is not a shortcut around the fence.
 *
 * It DOES record what it did. Every repair appends a line to a recovery log
 * naming the screen, the old label, the new label and the wall-clock time,
 * because a silent metadata edit on a shared surface is exactly the class of
 * change nobody can reconstruct afterwards.
 */
#include "qrmem.h"

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
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

/* Append one line to the recovery log, creating it if needed.
 *
 * Best effort by design: failing to write the audit must NOT fail the repair,
 * because refusing to correct metadata over a logging problem leaves the fabric
 * in the broken state, which is worse. It is reported instead, so the operator
 * knows the audit gap rather than discovering it later. */
static void recovery_log(const char *log_path, uint32_t screen,
                         const char *old_project, const char *new_project,
                         uint64_t writes, char *err, size_t errlen) {
    FILE *f;
    time_t now = time(NULL);
    struct tm tmv;
    char when[64] = "unknown";
    if (!log_path || !log_path[0])
        return;
    if (gmtime_r(&now, &tmv))
        strftime(when, sizeof when, "%Y-%m-%dT%H:%M:%SZ", &tmv);
    f = fopen(log_path, "a");
    if (!f) {
        if (err && errlen)
            snprintf(err, errlen,
                     "repaired, but could not append to the recovery log %s",
                     log_path);
        return;
    }
    fprintf(f,
            "%s screen=%u writes=%llu old_project=\"%s\" new_project=\"%s\" "
            "actor=operator reason=metadata-repair\n",
            when, screen, (unsigned long long)writes,
            old_project ? old_project : "", new_project ? new_project : "");
    /* Flush through to the file, so an audit line is not sitting in a buffer
     * when the operator needs it. Not fsync: this is an append-only note, and
     * blocking on a device flush for a log line is the wrong trade. */
    fflush(f);
    fclose(f);
}

/* Read a screen's current project label. Returns the length, or 0 for no label.
 * Never fails: an unreadable label is treated as absent because the repair's
 * whole job is to overwrite it anyway. */
static size_t read_project(const qrmem_ap_t *ap, uint32_t screen, char *out,
                           size_t outlen) {
    uint32_t plen;
    size_t n;
    if (outlen == 0u)
        return 0;
    out[0] = '\0';
    plen = atomic_load_explicit(&ap->screens[screen].project_len,
                                memory_order_acquire);
    if (plen == 0u || plen > QRMEM_PROJECT_MAX)
        return 0;
    n = (plen < outlen - 1u) ? (size_t)plen : outlen - 1u;
    memcpy(out, ap->screens[screen].project, n);
    out[n] = '\0';
    return n;
}

/* Operator repair: set a screen's project label, with a refusal when the
 * request is a no-op or when the label cannot be represented.
 *
 * Deliberately does NOT check whether the page has published records. That check
 * is the AGENT rule, enforced in qrmem_screen_claim; this function is the
 * operator path, and re-imposing it here would make the repair impossible for
 * the case it exists to fix. The requirement that the page is UNOWNED is
 * different and IS enforced: repairing a label out from under a live writer
 * would change what a screen means to a process that is actively using it. */
int qrmem_recover_project(qrmem_ap_t *ap, uint32_t screen, const char *project,
                          const char *log_path, int dry_run, char *err,
                          size_t errlen) {
    char old[QRMEM_PROJECT_MAX + 1];
    size_t oldlen;
    size_t plen;
    uint32_t owner;
    uint64_t writes;
    if (!ap || !ap->hdr) {
        set_err(err, errlen, "recovery needs an attached fabric");
        return -1;
    }
    if (!qrmem_screen_valid(screen)) {
        set_err(err, errlen, "screen %u does not exist (0..%u)", screen,
                QRMEM_SCREENS - 1u);
        return -1;
    }
    if (!project) {
        set_err(err, errlen, "recovery needs a project label to set");
        return -1;
    }
    plen = strlen(project);
    if (plen == 0u) {
        set_err(err, errlen,
                "refusing to clear a project label: an unlabelled page cannot "
                "be found by project, which is an orphan. Pass the label it "
                "should have.");
        return -1;
    }
    if (plen > QRMEM_PROJECT_MAX) {
        set_err(err, errlen,
                "project label is %zu bytes, limit is %u; refused, never "
                "truncated",
                plen, QRMEM_PROJECT_MAX);
        return -1;
    }
    owner = qrmem_screen_owner(ap, screen);
    if (owner != 0u) {
        set_err(err, errlen,
                "screen %u is owned by agent slot %u. Release it first with "
                "qrmem_leave from that agent: repairing a label out from under "
                "a live writer would change what the screen means to a process "
                "that is using it right now.",
                screen, owner);
        return -1;
    }
    oldlen = read_project(ap, screen, old, sizeof old);
    /* The dry run reports and stops. Every validation above has already run, so
     * what it prints is exactly what a real repair would do - which is the point:
     * the operator reads back the label they are about to commit before
     * committing it.
     *
     * This exists because the hazard was demonstrated rather than imagined: a
     * repair was run against a live screen with a deliberately wrong label,
     * intending to confirm the guard would refuse, and it did not refuse because
     * the operator path has no immutability guard by design. Nothing was lost -
     * no record was touched - but a label was overwritten, and only the audit log
     * recorded it. A path that can overwrite metadata with no confirmation and no
     * preview is one nobody should have to be careful around. */
    /* The no-op check comes BEFORE the dry-run exit, not after it. A preview has
     * to be a faithful preview: if this refused, the preview must refuse too,
     * otherwise "dry run" quietly means "report success for anything that
     * parses" - which is the least useful preview there is. The gate caught the
     * ordering by asserting that a dry run refuses exactly what a real run does. */
    if (oldlen == plen && memcmp(old, project, plen) == 0) {
        set_err(err, errlen,
                "screen %u already has project \"%s\"; nothing to repair",
                screen, project);
        return -1;
    }
    if (dry_run)
        return 0;
    writes = qrmem_write_count(ap, screen);
    memcpy(ap->screens[screen].project, project, plen);
    atomic_store_explicit(&ap->screens[screen].project_len, (uint32_t)plen,
                          memory_order_release);
    /* The plane is redrawn for a screen whose metadata changed, because the
     * block structure it encodes includes the page's label region. Stale pixels
     * here would be a small lie about which page this is. */
    for (uint32_t b = 0; b < QRMEM_BLOCKS_PER_SCREEN; b++)
        qrmem_plane_store_block(ap, screen, b);
    recovery_log(log_path, screen, old, project, writes, err, errlen);
    return 0;
}

/* Report a screen's metadata for triage, without changing anything. The read
 * half of repair, so an operator can see what is there before deciding. */
int qrmem_recover_inspect(const qrmem_ap_t *ap, uint32_t screen,
                          char *project_out, size_t project_outlen,
                          uint64_t *writes_out, uint32_t *owner_out,
                          uint64_t *generation_out, uint64_t *index_used_out,
                          char *err, size_t errlen) {
    if (!ap || !ap->hdr) {
        set_err(err, errlen, "inspection needs an attached fabric");
        return -1;
    }
    if (!qrmem_screen_valid(screen)) {
        set_err(err, errlen, "screen %u does not exist (0..%u)", screen,
                QRMEM_SCREENS - 1u);
        return -1;
    }
    (void)read_project(ap, screen, project_out, project_outlen);
    if (writes_out)
        *writes_out = qrmem_write_count(ap, screen);
    if (owner_out)
        *owner_out = qrmem_screen_owner(ap, screen);
    if (generation_out)
        *generation_out = qrmem_generation(ap, screen);
    if (index_used_out)
        *index_used_out = qrmem_index_used(ap, screen);
    return 0;
}