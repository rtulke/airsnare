/*
 * clients.c - Client station tracking
 *
 * Implements a hash table of client stations indexed by (station, bssid) tuple.
 * Each client entry tracks handshake state, replay counters, and EAPOL headers
 * needed for WPA/WPA2 handshake capture.
 */

#include <assert.h>
#include <stdlib.h>

#include "clients.h"

/*
 * Initialize a new empty clients hash table.
 * Sets the pointer to NULL (uthash convention for empty table).
 *
 * Parameters:
 *   clients - Pointer to clients collection (will be set to NULL)
 */
void zz_clients_new(zz_clients *clients) {
    *clients = NULL;
}

/*
 * Look up or create a client entry in the hash table.
 * The key is the combination of (station MAC, BSSID), allowing a station
 * to be tracked separately for each AP it connects to.
 *
 * If the client doesn't exist, it's created with zero-initialized state.
 * This is a "get or create" pattern that simplifies client management.
 *
 * Parameters:
 *   clients - Clients hash table
 *   station - Client station MAC address
 *   bssid - Access point BSSID
 *   client - Output pointer to the found/created client structure
 *
 * Returns:
 *   1 if client was newly created, 0 if it already existed
 */
int zz_clients_lookup(zz_clients *clients,
                      zz_mac_addr station, zz_mac_addr bssid,
                      zz_client **client) {
    /* Create composite key from station and BSSID.
     * The two MAC addresses are stored adjacently in memory, forming
     * a 16-byte key (2 * sizeof(zz_mac_addr)) */
    const zz_mac_addr key[] = {station, bssid};

    /* Try to find existing client using the composite key */
    HASH_FIND(hh, *clients, key, sizeof(key), *client);
    if (*client) {
        return 0;  /* Client already exists */
    }

    /* Client not found - create and initialize a new one */
    *client = calloc(1, sizeof(zz_client));  /* calloc zeros all fields */
    assert(*client != NULL);
    (*client)->station = station;
    (*client)->bssid = bssid;

    /* Add to hash table. Hash key starts at 'station' field and spans both
     * station and bssid (which are adjacent in memory) */
    HASH_ADD(hh, *clients, station, sizeof(key), *client);
    return 1;  /* New client created */
}

/*
 * Free all clients and the hash table.
 * Iterates through the table, removes each entry, and frees its memory.
 *
 * Parameters:
 *   clients - Clients hash table to free
 */
void zz_clients_free(zz_clients *clients) {
    zz_client *tmp, *client;

    HASH_ITER(hh, *clients, client, tmp) {
        HASH_DEL(*clients, client);
        free(client);
    }
}
