/*
 * iface.c - Network interface configuration
 *
 * Platform-specific code for setting the wireless channel on the capture
 * interface.
 *
 * On macOS the channel must be set BEFORE pcap_activate() enables RFMON,
 * because once the interface is in monitor mode the normal network stack no
 * longer controls it. zz_set_channel_pre_rfmon() tries networksetup(8) first
 * (Monterey and earlier) and falls back to airport(1) (Ventura+, where
 * networksetup dropped -setairportchannel). The post-RFMON path is a no-op.
 *
 * On Linux the sequence is reversed: ioctl(SIOCSIWFREQ) works while the
 * interface is in RFMON mode, so zz_set_channel_pre_rfmon() is a no-op and
 * zz_set_channel() performs the actual ioctl after pcap_activate().
 */

#ifdef __APPLE__

/* ------------------------------------------------------------------ macOS */

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "handler.h"
#include "terminal.h"

extern char **environ;

/*
 * Spawn a command and wait for it to finish.
 * Returns 1 if the process exits with code 0, 0 otherwise.
 */
static int try_command(const char *path, char *const argv[]) {
    posix_spawn_file_actions_t fa;
    pid_t pid;
    int status;
    int ok;

    /* Redirect stdout and stderr to /dev/null so that helper tools
     * (networksetup help dump, airport deprecation warning) do not
     * pollute the user's terminal. */
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    ok = posix_spawn(&pid, path, &fa, NULL, argv, environ) == 0
         && waitpid(pid, &status, 0) != -1
         && WIFEXITED(status) && WEXITSTATUS(status) == 0;

    posix_spawn_file_actions_destroy(&fa);
    return ok;
}

/*
 * Set wireless channel before RFMON activation (macOS).
 *
 * Tries two methods in order:
 *   1. networksetup -setairportchannel  (macOS Monterey and earlier)
 *   2. airport --channel=N              (fallback; Ventura+ removed the
 *                                        networksetup subcommand)
 *
 * Must run while the interface is still in managed mode (before pcap_activate).
 * Requires root.
 *
 * Returns: 1 on success, 0 on failure (error set in zz->error_buffer)
 */
int zz_set_channel_pre_rfmon(zz_handler *zz) {
    char channel_str[16];
    char channel_flag[32];

    snprintf(channel_str, sizeof(channel_str), "%d", zz->setup.channel);
    snprintf(channel_flag, sizeof(channel_flag), "--channel=%d", zz->setup.channel);

    zz_debug("Setting '%s' to channel %d", zz->setup.input, zz->setup.channel);

    /* Method 1: networksetup (macOS Monterey and earlier) */
    {
        char *const argv[] = {
            "/usr/sbin/networksetup", "-setairportchannel",
            zz->setup.input, channel_str, NULL
        };
        if (try_command("/usr/sbin/networksetup", argv)) {
            return 1;
        }
    }

    /* Method 2: airport utility (Ventura+ removed -setairportchannel) */
    {
        static const char airport[] =
            "/System/Library/PrivateFrameworks/"
            "Apple80211.framework/Versions/Current/Resources/airport";
        char *const argv[] = { (char *)airport, channel_flag, NULL };
        if (try_command(airport, argv)) {
            return 1;
        }
    }

    zz_error(zz, "Cannot set channel %d on '%s' — "
                 "networksetup and airport both failed; "
                 "set the channel manually before starting AirSnare: "
                 "sudo airport --channel=%d",
             zz->setup.channel, zz->setup.input, zz->setup.channel);
    return 0;
}

/*
 * Set wireless channel after RFMON activation (macOS).
 * Channel was already configured by zz_set_channel_pre_rfmon(); no-op here.
 *
 * Returns: always 1
 */
int zz_set_channel(zz_handler *zz) {
    (void)zz;
    return 1;
}

#else

/* ------------------------------------------------------------------ Linux */

#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if.h>
#include <linux/wireless.h>

#include "handler.h"
#include "terminal.h"

/*
 * Set wireless channel before RFMON activation (Linux).
 * On Linux the ioctl works after activation; nothing to do here.
 *
 * Returns: always 1
 */
int zz_set_channel_pre_rfmon(zz_handler *zz) {
    (void)zz;
    return 1;
}

/*
 * Set wireless channel using ioctl() and wireless extensions (Linux).
 * Helper that performs the actual SIOCSIWFREQ ioctl.
 */
static int iwreq_freq(int fd, const char *iface, int channel) {
    struct iwreq iwreq;

    memset(&iwreq, 0, sizeof(struct iwreq));
    strncpy(iwreq.ifr_name, iface, IFNAMSIZ);
    iwreq.u.freq.m = channel;
    iwreq.u.freq.e = 0;

    return (ioctl(fd, SIOCSIWFREQ, &iwreq) == 0);
}

/*
 * Set wireless channel after RFMON activation (Linux).
 * Opens a socket and uses ioctl() with SIOCSIWFREQ. Requires the interface
 * to already be in monitor mode.
 *
 * Returns: 1 on success, 0 on failure
 */
int zz_set_channel(zz_handler *zz) {
    int fd;

    if (!zz->setup.is_live || zz->setup.channel <= 0) {
        errno = EINVAL;
        return 0;
    }

    zz_debug("Setting '%s' to channel %d", zz->setup.input, zz->setup.channel);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return 0;
    }

    {
        int result = iwreq_freq(fd, zz->setup.input, zz->setup.channel);
        close(fd);
        return result;
    }
}

#endif
