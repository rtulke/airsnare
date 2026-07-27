/*
 * iface.c - Network interface configuration
 *
 * Platform-specific code for setting the wireless channel on the capture
 * interface.
 *
 * On macOS the channel must be set BEFORE pcap_activate() enables RFMON,
 * because once the interface is in monitor mode the normal network stack no
 * longer controls it. That path uses CoreWLAN and therefore lives in
 * iface_macos.m (Objective-C); this file only provides the Linux
 * implementation.
 *
 * On Linux the sequence is reversed: ioctl(SIOCSIWFREQ) works while the
 * interface is in RFMON mode, so zz_set_channel_pre_rfmon() is a no-op and
 * zz_set_channel() performs the actual ioctl after pcap_activate().
 */

#ifndef __APPLE__

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
    /* Copy at most IFNAMSIZ-1 bytes and force NUL termination: strncpy leaves
     * ifr_name unterminated when the interface name is exactly IFNAMSIZ long. */
    strncpy(iwreq.ifr_name, iface, IFNAMSIZ - 1);
    iwreq.ifr_name[IFNAMSIZ - 1] = '\0';
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

#else

/* On macOS the channel handling lives in iface_macos.m; this keeps the
 * translation unit non-empty so -pedantic does not reject it. */
typedef int zz_iface_translation_unit_not_empty;

#endif
