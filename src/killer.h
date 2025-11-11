/*
 * killer.h - Deauthentication attack subsystem
 *
 * Manages the injection of IEEE 802.11 deauthentication frames to force
 * clients to reassociate, thereby triggering WPA handshakes. Maintains
 * a queue of targets, handles retry logic, and communicates with the
 * packet dissector via a pipe.
 */

#ifndef ZZ_KILLER_H
#define ZZ_KILLER_H

#include "ieee802.h"

/* Forward declaration - full definition in killer.c */
struct zz_target;

/*
 * Killer subsystem state
 * Manages deauthentication attack targets and inter-thread communication.
 */
typedef struct {
    struct zz_target *targets;  /* Hash table of clients targeted for deauth */
    int pipe[2];                /* Pipe for communication from dissector to killer */
} zz_killer;

/*
 * Initialize a new killer subsystem.
 * Sets up the pipe and initializes the target hash table.
 *
 * Parameters:
 *   killer - Killer structure to initialize
 */
void zz_killer_new(zz_killer *killer);

/*
 * Clean up and free killer resources.
 * Closes pipe, frees all targets from the hash table.
 *
 * Parameters:
 *   killer - Killer structure to free
 */
void zz_killer_free(zz_killer *killer);

#endif
