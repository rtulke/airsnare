/*
 * util.c - General utility functions
 *
 * Provides helper functions for privilege management and other
 * system-level operations.
 */

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "handler.h"
#include "terminal.h"

/*
 * Parse a strictly-numeric, non-zero id from an environment string.
 * atoi() cannot distinguish "0" from garbage, which would silently turn the
 * privilege drop below into a no-op (uid/gid 0 succeeds while running as root).
 * Rejects empty strings, trailing garbage, overflow, and a resulting 0.
 *
 * Returns: 1 and stores the value on success, 0 on any parse failure.
 */
static int parse_id(const char *s, unsigned long *out) {
    char *end;
    unsigned long value;

    errno = 0;
    value = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || value == 0) {
        return 0;
    }
    *out = value;
    return 1;
}

/*
 * Drop root privileges after completing operations that require them.
 *
 * This is a security measure to minimize the attack surface. After opening
 * the network interface (which requires root), we drop privileges to run
 * the main packet processing loop as a less-privileged user.
 *
 * Two strategies are used:
 *   1. If run with sudo, restore the original user's credentials
 *   2. Otherwise, become the 'nobody' user
 *
 * Parameters:
 *   zz - Handler for error reporting
 *
 * Returns:
 *   1 on success, 0 on failure
 */
int zz_drop_root(zz_handler *zz) {
    const char *sudo_user;
    uid_t uid;
    gid_t gid;

    /* If not running as root, no need to drop privileges */
    if (getuid() != 0) {
        zz_debug("User not root, nothing to do");
        return 1;
    }

    /* Check if running via sudo - if so, restore original user credentials */
    sudo_user = getenv("SUDO_USER");
    if (sudo_user) {
        const char *id;

        zz_debug("Running with sudo, becoming '%s'", sudo_user);

        /* Get the original user's UID from environment. Parse strictly: a
         * malformed value must abort the drop, never silently fall back to 0
         * (which would keep full root privileges while reporting success). */
        id = getenv("SUDO_UID");
        if (!id) {
            zz_error(zz, "SUDO_UID not defined");
            return 0;
        }
        {
            unsigned long value;
            if (!parse_id(id, &value)) {
                zz_error(zz, "Invalid SUDO_UID '%s'; refusing to drop privileges", id);
                return 0;
            }
            uid = (uid_t)value;
        }

        /* Get the original user's GID from environment */
        id = getenv("SUDO_GID");
        if (!id) {
            zz_error(zz, "SUDO_GID not defined");
            return 0;
        }
        {
            unsigned long value;
            if (!parse_id(id, &value)) {
                zz_error(zz, "Invalid SUDO_GID '%s'; refusing to drop privileges", id);
                return 0;
            }
            gid = (gid_t)value;
        }
    }
    /* Not running via sudo - become the 'nobody' user for minimal privileges */
    else {
        struct passwd *nobody;

        zz_debug("Becoming 'nobody'");
#ifdef __APPLE__
        /* On macOS the unprivileged system account is named '_nobody' */
        nobody = getpwnam("_nobody");
        if (!nobody) {
            nobody = getpwnam("nobody");
        }
#else
        nobody = getpwnam("nobody");
#endif
        if (!nobody) {
            zz_error(zz, "Cannot find unprivileged user to drop privileges");
            return 0;
        }
        uid = nobody->pw_uid;
        gid = nobody->pw_gid;
    }

    /* Actually drop privileges. Order matters: clear supplementary groups,
     * then set GID, then set UID. Setting UID last ensures we can't regain
     * privileges afterwards. */
    if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0) {
        zz_error(zz, "Cannot switch user %u:%u", uid, gid);
        return 0;
    }

    return 1;
}
