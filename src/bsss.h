/*
 * bsss.h - Access point (BSS) tracking
 *
 * Maintains a hash table of discovered access points (Basic Service Sets).
 * Each BSS entry tracks the SSID, allowed/filtered status, associated
 * stations with handshakes, and traffic statistics.
 */

#ifndef ZZ_BSSS_H
#define ZZ_BSSS_H

#include <uthash.h>

#include "members.h"

#include "ieee802.h"

/*
 * Basic Service Set (access point) structure
 * Tracks information about a single wireless network/AP.
 */
typedef struct {
    zz_mac_addr bssid;          /* AP's MAC address (BSSID) - hash table key */
    unsigned is_allowed:1;      /* AP passed include/exclude filters */
    unsigned has_beacon:1;      /* We've seen a beacon frame (have SSID) */
    char ssid[ZZ_BEACON_MAX_SSID_ESCAPED_LENGTH + 1];  /* Network name (escaped for display) */
    zz_members stations;        /* Set of stations with at least one handshake message */
    long n_handshakes;          /* Count of completed handshakes for this AP */
    long n_data_packets;        /* Count of data packets seen for this AP */
    UT_hash_handle hh;          /* uthash handle for hash table management */
} zz_bss;

/* BSSs collection is a pointer to hash table head */
typedef zz_bss *zz_bsss;

/*
 * Initialize a new empty BSSs hash table.
 *
 * Parameters:
 *   bsss - Pointer to BSSs collection (will be set to NULL)
 */
void zz_bsss_new(zz_bsss *bsss);

/*
 * Look up or create a BSS entry in the hash table.
 * If the BSS doesn't exist, a new entry is created and initialized.
 *
 * Parameters:
 *   bsss - BSSs hash table
 *   bssid - Access point BSSID to look up
 *   bss - Output pointer to the found/created BSS structure
 *
 * Returns:
 *   1 if BSS was newly created, 0 if it already existed
 */
int zz_bsss_lookup(zz_bsss *bsss, zz_mac_addr bssid, zz_bss **bss);

/*
 * Free all BSSs and the hash table.
 *
 * Parameters:
 *   bsss - BSSs hash table to free
 */
void zz_bsss_free(zz_bsss *bsss);

#endif
