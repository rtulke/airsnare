/*
 * util.c - General utility functions
 *
 * Provides helper functions for privilege management and other
 * system-level operations.
 */

#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "handler.h"
#include "terminal.h"

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
        zz_log("User not root, nothing to do");
        return 1;
    }

    /* Check if running via sudo - if so, restore original user credentials */
    sudo_user = getenv("SUDO_USER");
    if (sudo_user) {
        const char *id;

        zz_log("Running with sudo, becoming '%s'", sudo_user);

        /* Get the original user's UID from environment */
        id = getenv("SUDO_UID");
        if (!id) {
            zz_error(zz, "SUDO_UID not defined");
            return 0;
        }
        uid = atoi(id);

        /* Get the original user's GID from environment */
        id = getenv("SUDO_GID");
        if (!id) {
            zz_error(zz, "SUDO_GID not defined");
        }
        gid = atoi(id);
    }
    /* Not running via sudo - become the 'nobody' user for minimal privileges */
    else {
        struct passwd *nobody;

        zz_log("Becoming 'nobody'");
        nobody = getpwnam("nobody");
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
