/*
 * iface_macos.m - Wireless channel configuration on macOS (CoreWLAN)
 *
 * The channel must be set BEFORE pcap_activate() enables RFMON, because once
 * the interface is in monitor mode the normal network stack no longer controls
 * it. This is done through CoreWLAN's -setWLANChannel:error:, which is the
 * supported API on modern macOS.
 *
 * Earlier releases shelled out to networksetup(8) and, as a fallback, the
 * airport(1) utility. networksetup dropped -setairportchannel in Ventura and
 * airport was removed entirely in macOS 15 (Sequoia), so both external tools
 * are unavailable on current systems. CoreWLAN replaces them and needs no
 * helper binaries. Requires root.
 *
 * This file is compiled as Objective-C and linked against the CoreWLAN and
 * Foundation frameworks (see config.Makefile). The matching Linux code lives
 * in iface.c.
 */

#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>

#include "iface.h"
#include "terminal.h"

/*
 * Set wireless channel before RFMON activation (macOS, CoreWLAN).
 *
 * Looks up the target channel in the interface's supported channel set and
 * applies it via -setWLANChannel:error:. Must run while the interface is still
 * in managed mode (before pcap_activate). Requires root.
 *
 * Returns: 1 on success, 0 on failure (error set in zz->error_buffer)
 */
int zz_set_channel_pre_rfmon(zz_handler *zz) {
    @autoreleasepool {
        NSString *name = [NSString stringWithUTF8String:zz->setup.input];

        zz_debug("Setting '%s' to channel %d via CoreWLAN",
                 zz->setup.input, zz->setup.channel);

        CWInterface *iface =
            [[CWWiFiClient sharedWiFiClient] interfaceWithName:name];
        if (!iface) {
            return zz_error(zz, "CoreWLAN: no Wi-Fi interface named '%s'",
                            zz->setup.input);
        }

        /* Find the CWChannel object matching the requested channel number. */
        CWChannel *target = nil;
        for (CWChannel *ch in [iface supportedWLANChannels]) {
            if ((int)[ch channelNumber] == zz->setup.channel) {
                target = ch;
                break;
            }
        }
        if (!target) {
            return zz_error(zz, "Channel %d is not supported by '%s'",
                            zz->setup.channel, zz->setup.input);
        }

        NSError *err = nil;
        if (![iface setWLANChannel:target error:&err]) {
            return zz_error(zz, "Cannot set channel %d on '%s': %s — "
                                "run as root and make sure the interface is "
                                "not associated to a network",
                            zz->setup.channel, zz->setup.input,
                            err ? [[err localizedDescription] UTF8String]
                                : "unknown CoreWLAN error");
        }

        return 1;
    }
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
