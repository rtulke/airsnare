/*
 * iface.h - Network interface configuration
 *
 * Channel setting is split into two phases to accommodate platform differences:
 *
 *   zz_set_channel_pre_rfmon()  — called BEFORE pcap_activate()
 *       macOS: sets channel via CoreWLAN while still in managed mode
 *              (implemented in iface_macos.m)
 *       Linux: no-op (ioctl works post-RFMON)
 *
 *   zz_set_channel()            — called AFTER pcap_activate()
 *       macOS: no-op (already done)
 *       Linux: sets channel via ioctl(SIOCSIWFREQ)
 */

#ifndef ZZ_IFACE_H
#define ZZ_IFACE_H

#include "handler.h"

/*
 * Set the wireless channel before RFMON activation.
 * On macOS this is the only effective call; on Linux it is a no-op.
 *
 * Returns: 1 on success, 0 on failure (error in zz->error_buffer)
 */
int zz_set_channel_pre_rfmon(zz_handler *zz);

/*
 * Set the wireless channel after RFMON activation.
 * On Linux this performs the ioctl; on macOS it is a no-op.
 *
 * Returns: 1 on success, 0 on failure (error in zz->error_buffer)
 */
int zz_set_channel(zz_handler *zz);

#endif
