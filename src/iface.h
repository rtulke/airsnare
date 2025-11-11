/*
 * iface.h - Network interface configuration
 *
 * Handles network interface operations including setting the wireless
 * channel and enabling monitor (RFMON) mode. Platform-specific
 * implementations handle differences between Linux and macOS.
 */

#ifndef ZZ_IFACE_H
#define ZZ_IFACE_H

#include "handler.h"

/*
 * Set the wireless channel for the capture interface.
 * This function is platform-specific:
 *   - On Linux: Uses iwconfig or similar tools
 *   - On macOS: May require manual channel setting via airport utility
 *
 * Parameters:
 *   zz - Handler containing interface name and target channel
 *
 * Returns:
 *   1 on success, 0 on failure (with error message set in zz->error_buffer)
 */
int zz_set_channel(zz_handler *zz);

#endif
