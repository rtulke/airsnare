/*
 * bsss.c - Access point (BSS) tracking
 *
 * Implements a hash table of Basic Service Sets (access points) indexed by BSSID.
 * Each BSS entry tracks the SSID, filter status, associated stations with
 * handshakes, and traffic statistics.
 */

#include <assert.h>
#include <stdlib.h>

#include "bsss.h"

/*
 * Initialize a new empty BSSs hash table.
 * Sets the pointer to NULL (uthash convention for empty table).
 *
 * Parameters:
 *   bsss - Pointer to BSSs collection (will be set to NULL)
 */
void zz_bsss_new(zz_bsss *bsss) {
    *bsss = NULL;
}

/*
 * Look up or create a BSS entry in the hash table.
 * If the BSS doesn't exist, it's created with zero-initialized state
 * and an empty stations set.
 *
 * This is a "get or create" pattern that simplifies BSS management.
 *
 * Parameters:
 *   bsss - BSSs hash table
 *   bssid - Access point BSSID to look up
 *   bss - Output pointer to the found/created BSS structure
 *
 * Returns:
 *   1 if BSS was newly created, 0 if it already existed
 */
int zz_bsss_lookup(zz_bsss *bsss, zz_mac_addr bssid, zz_bss **bss) {
    /* Try to find existing BSS by BSSID */
    HASH_FIND(hh, *bsss, &bssid, sizeof(zz_mac_addr), *bss);
    if (*bss) {
        return 0;  /* BSS already exists */
    }

    /* BSS not found - create and initialize a new one */
    *bss = calloc(1, sizeof(zz_bss));  /* calloc zeros all fields */
    assert(*bss != NULL);
    (*bss)->bssid = bssid;
    zz_members_new(&(*bss)->stations);  /* Initialize empty stations set */

    /* Add to hash table, keyed by bssid field */
    HASH_ADD(hh, *bsss, bssid, sizeof(zz_mac_addr), *bss);
    return 1;  /* New BSS created */
}

/*
 * Free all BSSs and the hash table.
 * Iterates through the table, frees each BSS's stations set,
 * and then frees the BSS itself.
 *
 * Parameters:
 *   bsss - BSSs hash table to free
 */
void zz_bsss_free(zz_bsss *bsss) {
    zz_bss *tmp, *bss;

    HASH_ITER(hh, *bsss, bss, tmp) {
        HASH_DEL(*bsss, bss);
        zz_members_free(&bss->stations);  /* Free the stations set first */
        free(bss);
    }
}
