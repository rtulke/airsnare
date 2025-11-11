/*
 * handshake.c - WPA/WPA2 handshake state machine
 *
 * Implements the core logic for tracking WPA 4-way handshake progress.
 * Maintains per-client state (which messages received, replay counters,
 * timestamps) and determines when a complete handshake has been captured.
 * Also handles timeouts, retransmissions, and invalidation scenarios.
 */

#include "clients.h"
#include "handshake.h"
#include "ieee802.h"
#include "params.h"
#include "terminal.h"

/* Compute absolute difference between two values */
#define abs(x, y) ((x) > (y) ? (x) - (y) : (y) - (x))

/* Check if first 'max' bits of handshake bitmask are all set.
 * For example, if max=4, checks if bits 0-3 are all 1 (full 4-way handshake).
 * If max=2, checks if bits 0-1 are all 1 (partial 2-message handshake). */
#define is_done(handshake, max) \
    ((((handshake) & ((1 << (max)) - 1)) == ((1 << (max)) - 1)))

/*
 * Process a packet through the WPA handshake state machine.
 * This is the heart of zizzania's handshake tracking logic. It maintains
 * per-client state and determines what actions should be taken based on
 * the packet type and current handshake progress.
 *
 * State machine logic:
 *   1. For new clients: initialize tracking state
 *   2. For EAPOL frames:
 *      - Identify which handshake message (1-4) based on flags
 *      - Validate replay counter sequence
 *      - Detect retransmissions (exact duplicate)
 *      - Handle timeouts (reinitialize if too much time passed)
 *      - Handle invalidation (received unexpected message, restart)
 *      - Check for handshake completion (all required messages received)
 *   3. For data frames:
 *      - Update last activity timestamp
 *      - Trigger retracking if client became active again after long idle
 *
 * The function returns an outcome structure that tells the dissector:
 *   - Whether to ignore this packet
 *   - Whether to dump this packet to output
 *   - Whether to (re)start tracking/deauthentication
 *   - Whether a complete handshake was captured
 *
 * Parameters:
 *   zz - Handler with configuration
 *   station - Client MAC address
 *   bssid - Access point BSSID
 *   packet_header - Packet metadata (timestamp, etc.)
 *   auth - EAPOL authentication header (NULL for data frames)
 *
 * Returns:
 *   Outcome structure indicating what actions to take
 */
zz_packet_outcome zz_process_packet(zz_handler *zz,
    zz_mac_addr station, zz_mac_addr bssid,
    const struct pcap_pkthdr *packet_header,
    const struct ieee8021x_authentication_header *auth) {
    zz_client *client;
    time_t last_data_ts;
    zz_packet_outcome outcome = {0};

    /* Lookup or create client descriptor.
     * The lookup function returns 1 if this is a newly created client. */
    if (zz_clients_lookup(&zz->clients, station, bssid, &client)) {
        /* New client discovered - initiate tracking */
        outcome.new_client = 1;
    }

    /* Update last activity timestamp.
     * Save old timestamp before updating (used later to detect "came back alive"). */
    last_data_ts = client->last_data_ts;
    client->last_data_ts = packet_header->ts.tv_sec;

    /* Branch 1: EAPOL authentication message (handshake frame) */
    if (auth) {
        unsigned handshake_id;
        uint64_t ts;
        uint64_t replay_counter_1; /* Expected replay counter for message #1 */
        int initialize = 0;

        /* Convert timestamp to microseconds for precise timeout calculations */
        ts = (packet_header->ts.tv_sec * 1000000 +
              packet_header->ts.tv_usec % 1000000);

        /* Identify which handshake message (1-4) based on EAPOL key information flags.
         * Each message has a unique combination of flags (see ieee802.h):
         *   Message #1: from AP, pairwise key, ACK flag set
         *   Message #2: from STA, pairwise key, MIC flag set
         *   Message #3: from AP, pairwise key, ACK+MIC+Install flags set
         *   Message #4: from STA, pairwise key, MIC flag set
         *
         * For messages #3 and #4, we compute replay_counter_1 by subtracting 1
         * because the AP increments the counter for messages #3/#4. */
        if ((be16toh(auth->flags) & ZZ_EAPOL_MASK_1) == ZZ_EAPOL_FLAGS_1) {
            handshake_id = 0;  /* Message #1 */
            replay_counter_1 = be64toh(auth->replay_counter);
        } else if ((be16toh(auth->flags) & ZZ_EAPOL_MASK_2) == ZZ_EAPOL_FLAGS_2) {
            handshake_id = 1;  /* Message #2 */
            replay_counter_1 = be64toh(auth->replay_counter);
        } else if ((be16toh(auth->flags) & ZZ_EAPOL_MASK_3) == ZZ_EAPOL_FLAGS_3) {
            handshake_id = 2;  /* Message #3 */
            replay_counter_1 = be64toh(auth->replay_counter) - 1;
        } else if ((be16toh(auth->flags) & ZZ_EAPOL_MASK_4) == ZZ_EAPOL_FLAGS_4) {
            handshake_id = 3;  /* Message #4 */
            replay_counter_1 = be64toh(auth->replay_counter) - 1;
        } else {
            /* Unrecognized flag combination - invalid EAPOL frame */
            #ifdef DEBUG
            zz_log("Unrecognizable EAPOL flags 0x%04hx", be16toh(auth->flags));
            #endif
            outcome.ignore = 1;
            outcome.ignore_reason = ZZ_IGNORE_REASON_INVALID_EAPOL;
            return outcome;
        }

        /* Store message number for logging (1-based, not 0-based) */
        outcome.handshake_info = handshake_id + 1;

        /* Determine whether to initialize/reinitialize handshake tracking.
         * We reinitialize in three scenarios:
         *   1. First handshake message ever for this client
         *   2. Timeout: too much time passed since last message
         *   3. Invalidation: received conflicting message (not a retransmission) */

        /* Scenario 1: First handshake message ever for this client */
        if (!client->handshake) {
            initialize = 1;
            outcome.track_reason = ZZ_TRACK_REASON_FIRST_HANDSHAKE;
        }
        /* Scenario 2: Handshake timeout - too much time passed.
         * Even if this is a retransmission, we restart the tracking because
         * the previous attempt is considered stale. */
        else if (abs(client->last_handshake_ts, ts) > ZZ_MAX_HANDSHAKE_TIME) {
            initialize = 1;
            outcome.track_reason = ZZ_TRACK_REASON_EXPIRATION;
        }
        /* Already received this handshake message ID before */
        else if (client->handshake & (1 << handshake_id)) {
            /* Check if this is an exact duplicate (retransmission).
             * If the EAPOL header is identical to what we saved, it's a retransmission. */
            if (memcmp(&client->headers[handshake_id], auth,
                       sizeof(struct ieee8021x_authentication_header)) == 0) {
                outcome.ignore = 1;
                outcome.ignore_reason = ZZ_IGNORE_REASON_RETRANSMISSION;
                return outcome;
            }
            /* Scenario 3: Not a retransmission but we already have this message.
             * This indicates a conflicting handshake attempt. Reinitialize. */
            else {
                initialize = 1;
                outcome.track_reason = ZZ_TRACK_REASON_INVALIDATION;
            }
        }
        /* Normal case: First time receiving this message in current handshake */
        else {
            int ok;

            /* Validate replay counter sequence.
             * Messages #1 and #2 should have the same counter as message #1.
             * Messages #3 and #4 should have counter = (message #1 counter) + 1. */
            switch (handshake_id) {
            case 0: case 1:
                ok = (be64toh(auth->replay_counter) == client->replay_counter);
                break;
            case 2: case 3:
                ok = (be64toh(auth->replay_counter) == client->replay_counter + 1);
                break;
            }

            /* Reject if replay counter doesn't match expected sequence */
            if (!ok) {
                outcome.ignore = 1;
                outcome.ignore_reason = ZZ_IGNORE_REASON_INVALID_COUNTER;
                return outcome;
            }

            /* Valid new message - store it in the handshake bitmask and save header */
            client->handshake |= 1 << handshake_id;
            memcpy(&client->headers[handshake_id], auth,
                   sizeof(struct ieee8021x_authentication_header));

            /* Check if we've captured all required messages.
             * For full handshake: need messages #1, #2, #3, #4 (max=4)
             * For partial:        need messages #1, #2 only (max=2, -2 option) */
            if (handshake_id < zz->setup.max_handshake &&
                is_done(client->handshake, zz->setup.max_handshake)) {
                outcome.got_handshake = 1;
            }
        }

        /* Perform initialization if any of the scenarios triggered it */
        if (initialize) {
            /* Request grace time: delay first deauth attack to allow natural
             * handshake completion. This avoids disrupting an ongoing handshake. */
            outcome.grace_time = 1;

            /* Request tracking/deauthentication to start */
            outcome.track_client = 1;

            /* Reset client state to start fresh handshake tracking */
            client->last_handshake_ts = ts;
            client->replay_counter = replay_counter_1;
            client->handshake = 1 << handshake_id;  /* Set only this message bit */
            memcpy(&client->headers[handshake_id], auth,
                   sizeof(struct ieee8021x_authentication_header));
        }
    }
    /* Branch 2: Regular data packet (not EAPOL) */
    else {
        /* Check if client "came back alive" after a long idle period.
         * This is useful when the killer gave up on deauthenticating this client
         * (ran out of attempts), but the client is still active and hasn't
         * completed its handshake. We can restart the deauth process.
         *
         * The "long" time threshold is set to match the killer's give-up time:
         * (max_attempts - 1) * interval seconds. */
        if (last_data_ts &&
            !is_done(client->handshake, zz->setup.max_handshake) &&
            (packet_header->ts.tv_sec - last_data_ts >
             (zz->setup.killer_max_attempts - 1) * zz->setup.killer_interval)) {
            outcome.track_client = 1;
            outcome.track_reason = ZZ_TRACK_REASON_ALIVE;
        }
    }

    /* Decide whether to dump this packet to output file.
     * Dump if:
     *   - It's a valid EAPOL message (regardless of handshake state), OR
     *   - Client has completed the required handshake (dump its data traffic too) */
    if (auth || is_done(client->handshake, zz->setup.max_handshake)) {
        outcome.dump_packet = 1;
    }

    return outcome;
}
