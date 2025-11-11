/*
 * clients.h - Client station tracking
 *
 * Maintains a hash table of client stations and their WPA handshake state.
 * Each client is identified by the combination of station MAC + BSSID.
 * Tracks handshake progress, replay counters, and EAPOL frame headers.
 */

#ifndef ZZ_CLIENTS_H
#define ZZ_CLIENTS_H

#include <time.h>

#include <uthash.h>

#include "ieee802.h"

/*
 * Client station structure - tracks one client's handshake state
 * Key is (station, bssid) tuple since a station could theoretically
 * connect to multiple APs.
 */
typedef struct {
    zz_mac_addr station;        /* Client station MAC address (part of key) */
    zz_mac_addr bssid;          /* Access point BSSID (part of key) */
    time_t last_data_ts;        /* Timestamp of last data frame (for timeout tracking) */
    uint64_t last_handshake_ts; /* Timestamp of first handshake message (reference point) */
    uint64_t replay_counter;    /* Last seen replay counter (for detecting retransmissions) */
    unsigned handshake;         /* Handshake progress bitmask: bit 0-3 for messages 1-4 */
    struct ieee8021x_authentication_header headers[4];  /* Saved EAPOL headers for all 4 messages */
    UT_hash_handle hh;          /* uthash handle for hash table management */
} zz_client;

/* Clients collection is a pointer to hash table head */
typedef zz_client *zz_clients;

/*
 * Initialize a new empty clients hash table.
 *
 * Parameters:
 *   clients - Pointer to clients collection (will be set to NULL)
 */
void zz_clients_new(zz_clients *clients);

/*
 * Look up or create a client entry in the hash table.
 * If the client doesn't exist, a new entry is created and initialized.
 *
 * Parameters:
 *   clients - Clients hash table
 *   station - Client MAC address
 *   bssid - Access point BSSID
 *   client - Output pointer to the found/created client structure
 *
 * Returns:
 *   1 if client was newly created, 0 if it already existed
 */
int zz_clients_lookup(zz_clients *clients,
                      zz_mac_addr station, zz_mac_addr bssid,
                      zz_client **client);

/*
 * Free all clients and the hash table.
 *
 * Parameters:
 *   clients - Clients hash table to free
 */
void zz_clients_free(zz_clients *clients);

#endif
