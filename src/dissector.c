/*
 * dissector.c - Packet dissection and parsing
 *
 * Implements the main packet dissection callback that's invoked by pcap_loop
 * for every captured packet. Parses 802.11 frame headers, extracts addresses,
 * handles beacon frames, applies filters, and delegates to the handshake
 * state machine. This is the entry point for all packet processing.
 */

#include <strings.h>

#include "dissector.h"
#include "handshake.h"
#include "ieee802.h"
#include "terminal.h"

/* Convert struct timeval to floating-point seconds */
#define TV_TO_SEC(tv) ((tv).tv_sec + (tv).tv_usec / 1000000.)

/* Logging macro that includes relative timestamp (seconds since first packet) */
#define log_ts(format, ...) \
    zz_log("%.3f - " format, \
           TV_TO_SEC(packet_header->ts) - zz->epoch, ##__VA_ARGS__)

/*
 * Extract SSID from beacon frame tagged parameters.
 * Beacon frames contain a variable-length list of tagged parameters,
 * each with a type-length-value (TLV) structure. This function scans
 * the list looking for the SSID parameter (type 0).
 *
 * Parameters:
 *   params - Start of tagged parameters section
 *   length - Total length of parameters section
 *   ssid - Output pointer to SSID string (not null-terminated)
 *   ssid_length - Output SSID length in bytes
 */
static void get_ssid(const uint8_t *params, uint32_t length,
                     const char **ssid, int *ssid_length) {
    const uint8_t *ptr;

    /* Initialize outputs to empty (prevents valgrind warnings) */
    *ssid = NULL;
    *ssid_length = 0;

    /* Scan through tagged parameters (TLV format: type, length, value) */
    ptr = params;
    while (ptr < params + length) {
        uint8_t param_type;
        uint8_t param_length;

        /* Read type and length fields */
        param_type = *ptr++;
        param_length = *ptr++;

        /* Check if this is the SSID parameter (type 0) */
        if (param_type == ZZ_BEACON_SSID_PARAM_TYPE) {
            *ssid_length = param_length;
            *ssid = (const char *)ptr;
            return;
        }

        /* Skip to next parameter */
        ptr += param_length;
    }
}

/*
 * Check if a MAC address passes the include/exclude filters.
 * Implements configurable filter logic with optional order reversal.
 *
 * Filter logic:
 *   - If both include and exclude are present:
 *       - If exclude_first: allowed if (in include) OR (not in exclude)
 *       - Otherwise: allowed if (in include) AND (not in exclude)
 *   - If only include is present: allowed if in include (whitelist)
 *   - If only exclude is present: allowed if not in exclude (blacklist)
 *   - If neither is present: allowed (no filtering)
 *
 * The order can be controlled via -x option for fine-grained filtering.
 *
 * Parameters:
 *   mac_addr - MAC address to check
 *   exclude_first - Whether to apply exclude filter before include (0/1)
 *   include - Whitelist set (can be empty)
 *   exclude - Blacklist set (can be empty)
 *
 * Returns:
 *   1 if allowed, 0 if blocked
 */
static int is_mac_addr_allowed(zz_mac_addr mac_addr, int exclude_first,
                               const zz_members *include, const zz_members *exclude) {
    /* When both sets are present, apply according to configured order */
    if (!zz_members_is_empty(include) && !zz_members_is_empty(exclude)) {
        if (exclude_first) {
            /* Exclude-first mode: pass if explicitly included OR not excluded */
            return zz_members_match(include, mac_addr) || !zz_members_match(exclude, mac_addr);
        } else {
            /* Include-first mode (default): pass if included AND not excluded */
            return zz_members_match(include, mac_addr) && !zz_members_match(exclude, mac_addr);
        }
    }
    /* Whitelist mode: only allow addresses in include set */
    else if (!zz_members_is_empty(include) && zz_members_is_empty(exclude)) {
        return zz_members_match(include, mac_addr);
    }
    /* Blacklist mode: allow all except addresses in exclude set */
    else if (zz_members_is_empty(include) && !zz_members_is_empty(exclude)) {
        return !zz_members_match(exclude, mac_addr);
    }
    /* No filters configured: allow all addresses by default */
    else {
        return 1;
    }
}

/*
 * Main packet dissection callback.
 * This is the central function invoked by pcap_loop() for every captured packet.
 * It performs layer-by-layer parsing and delegates to the handshake state machine.
 *
 * Processing flow:
 *   1. Parse radiotap header (capture metadata)
 *   2. Parse 802.11 MAC header (frame type, addresses, flags)
 *   3. Determine frame direction and extract addresses:
 *      - Beacon: AP → broadcast
 *      - FromDS: AP → station (download)
 *      - ToDS: station → AP (upload)
 *   4. Apply BSSID filtering (whitelist/blacklist)
 *   5. Handle beacon frames (extract and save SSID)
 *   6. Apply station filtering
 *   7. Handle broadcast/multicast traffic
 *   8. Parse LLC+SNAP header (needed for EAPOL)
 *   9. Detect and parse EAPOL frames (WPA handshake messages)
 *  10. Call handshake state machine (zz_process_packet)
 *  11. Handle outcome: dump packets, track clients, update stats
 *
 * This function implements the BPF filter logic in user space, applying
 * additional filtering beyond what the kernel BPF does.
 *
 * Parameters:
 *   _zz - Opaque pointer to zz_handler (cast from u_char* for pcap callback)
 *   packet_header - Packet metadata (timestamp, capture length, wire length)
 *   packet - Raw packet data starting with radiotap header
 */
void zz_dissect_packet(u_char *_zz, const struct pcap_pkthdr *packet_header,
                       const uint8_t *packet) {
    zz_handler *zz = (zz_handler *)_zz;
    struct ieee80211_radiotap_header *radiotap_header;
    struct ieee80211_mac_header *mac_header;
    struct ieee8022_llc_snap_header *llc_snap_header;
    struct ieee8021x_authentication_header *authentication_header;
    char bssid_str[ZZ_MAC_ADDR_STRING_SIZE];
    char source_str[ZZ_MAC_ADDR_STRING_SIZE];
    char destination_str[ZZ_MAC_ADDR_STRING_SIZE];
    char station_str[ZZ_MAC_ADDR_STRING_SIZE];
    zz_mac_addr bssid, source, destination, station;
    const uint8_t *cursor;
    uint32_t safe_size;
    int is_beacon;
    int is_eapol;
    zz_bss *bss;
    zz_packet_outcome outcome;
    const char *extra_info;

    /* Save the timestamp of the first packet as epoch (reference point).
     * All subsequent timestamps will be relative to this for readability. */
    if (!zz->epoch) {
        zz->epoch = TV_TO_SEC(packet_header->ts);
    }

    /* Phase 1: Parse radiotap header (variable-length capture metadata) */

    /* Verify minimum packet size for radiotap header */
    safe_size = sizeof(struct ieee80211_radiotap_header);
    if (packet_header->caplen < safe_size) {
        log_ts("Skipping too short packet %u bytes", packet_header->caplen);
        return;
    }

    /* Start parsing from the beginning */
    cursor = packet;

    /* Extract radiotap header and skip past it (variable length) */
    radiotap_header = (struct ieee80211_radiotap_header *)cursor;
    cursor += le16toh(radiotap_header->length);

    /* Phase 2: Parse 802.11 MAC header */

    /* Verify packet has enough space for MAC header */
    safe_size = (cursor - packet) + sizeof(struct ieee80211_mac_header);
    if (packet_header->caplen < safe_size) {
        log_ts("Skipping too short packet %u bytes", packet_header->caplen);
        return;
    }

    /* Extract MAC header and advance cursor.
     * QoS data frames have an additional 2-byte QoS control field. */
    mac_header = (struct ieee80211_mac_header *)cursor;
    cursor += sizeof(struct ieee80211_mac_header) +
              (cursor[0] == ZZ_FCF_QOS_DATA ? 2 : 0);

    /* Phase 3: Determine frame direction and extract addresses.
     * The meaning of the three address fields depends on the ToDS/FromDS flags:
     *
     * ToDS FromDS   Addr1        Addr2      Addr3        Direction
     *  0     0      Destination  Source     BSSID        Mgmt/beacon
     *  0     1      Destination  BSSID      Source       AP → STA (download)
     *  1     0      BSSID        Source     Destination  STA → AP (upload)
     *  1     1      Receiver     Sender     Destination  WDS (not supported)
     */

    is_beacon = 0;

    /* Neither flag set: Management frame (could be beacon) */
    if (!mac_header->from_ds && !mac_header->to_ds) {
        /* Verify it's actually a beacon frame */
        if (((uint8_t *)mac_header)[0] != ZZ_FCF_BEACON) {
            return;  /* Not a beacon, ignore */
        }

        /* Beacon frame: AP → broadcast */
        is_beacon = 1;
        destination = zz_mac_addr_from_array(mac_header->address_1);  /* Broadcast */
        source = zz_mac_addr_from_array(mac_header->address_2);       /* AP */
        bssid = zz_mac_addr_from_array(mac_header->address_3);        /* BSSID */
        station = 0;  /* Not applicable for beacons */
    }
    /* FromDS set: Data frame from AP to station (download) */
    else if (mac_header->from_ds && !mac_header->to_ds) {
        destination = zz_mac_addr_from_array(mac_header->address_1);  /* Station */
        bssid = zz_mac_addr_from_array(mac_header->address_2);        /* AP */
        source = zz_mac_addr_from_array(mac_header->address_3);       /* Original source */
        station = destination;  /* Track the station receiving the data */
    }
    /* ToDS set: Data frame from station to AP (upload) */
    else if (mac_header->to_ds && !mac_header->from_ds) {
        bssid = zz_mac_addr_from_array(mac_header->address_1);        /* AP */
        source = zz_mac_addr_from_array(mac_header->address_2);       /* Station */
        destination = zz_mac_addr_from_array(mac_header->address_3);  /* Final destination */
        station = source;  /* Track the station sending the data */
    }
    /* Both flags set: WDS (wireless distribution system) - not supported */
    else {
        log_ts("Skipping packet due to frame direction");
        return;
    }

    /* Phase 4: Prepare string representations for logging */
    zz_mac_addr_sprint(bssid_str, bssid);
    zz_mac_addr_sprint(source_str, source);
    zz_mac_addr_sprint(destination_str, destination);
    zz_mac_addr_sprint(station_str, station);

    /* Phase 5: Lookup or create BSS descriptor and apply BSSID filtering */

    /* Get or create the BSS structure for this access point.
     * On first encounter (lookup returns 1), check if this BSS passes filters. */
    if (zz_bsss_lookup(&zz->bsss, bssid, &bss)) {
        /* Determine if we should operate on this BSS based on include/exclude lists */
        bss->is_allowed = is_mac_addr_allowed(bssid, zz->setup.bssids_exclude_first,
                                              &zz->setup.included_bssids, &zz->setup.excluded_bssids);
    }

    /* Skip all traffic from filtered-out access points */
    if (!bss->is_allowed) {
        #ifdef DEBUG
        if (!is_beacon) {
            log_ts("%s @ %s $'%s' - Skipping excluded BSS traffic", station_str, bssid_str, bss->ssid);
        }
        #endif
        return;
    }

    /* Phase 6: Handle beacon frames (extract SSID) */

    if (is_beacon) {
        /* Only process the first beacon from each BSS (to extract SSID) */
        if (!bss->has_beacon) {
            int ssid_length;
            const char *ssid;

            /* Write beacon to output file if capturing */
            if (zz->dumper) {
                pcap_dump((u_char *)zz->dumper, packet_header, packet);
            }

            /* Extract SSID from beacon tagged parameters.
             * Cursor points to the start of the beacon frame body. */
            get_ssid(cursor + ZZ_BEACON_SSID_PARAMS_OFFSET,
                     packet_header->caplen - (cursor - packet),
                     &ssid, &ssid_length);
            memcpy(bss->ssid, ssid, ssid_length);
            bss->has_beacon = 1;

            /* Notify user of newly discovered access point */
            zz_ssid_escape_sprint(bss->ssid, ssid, ssid_length);
            zz_out("BSS discovered %s $'%s'", bssid_str, bss->ssid);
        }

        /* Beacon processing complete - no further action needed */
        return;
    }

    /* Phase 7: Apply station filtering */

    /* Check if this station passes the include/exclude filters (-s/-S options) */
    if (!is_mac_addr_allowed(station, zz->setup.stations_exclude_first,
                             &zz->setup.included_stations, &zz->setup.excluded_stations)) {
        log_ts("%s @ %s $'%s' - Skipping excluded station", station_str, bssid_str, bss->ssid);
        return;
    }

    /* Phase 8: Handle broadcast/multicast traffic */

    /* Check if destination is broadcast (FF:FF:FF:FF:FF:FF) or multicast (bit 0 set) */
    if (destination == ZZ_MAC_ADDR_BCAST ||
        destination & ZZ_MAC_ADDR_MCAST_MASK) {

        /* Only dump group traffic if explicitly requested (-g option) and we
         * already have a handshake for this BSS (so we can decrypt it later).
         * This captures EAPOL group key messages and encrypted broadcast data. */
        if (zz->setup.dump_group_traffic && bss->n_handshakes > 0) {
            bss->n_data_packets++;

            if (zz->dumper) {
                pcap_dump((u_char *)zz->dumper, packet_header, packet);
            }
        }

        /* Group traffic doesn't contain handshake messages, so stop here */
        return;
    }

    /* Phase 9: Parse LLC+SNAP header and detect EAPOL frames */

    /* Extract LLC+SNAP header (IEEE 802.2 logical link control).
     * This encapsulates higher-layer protocols like EAPOL. */
    llc_snap_header = (struct ieee8022_llc_snap_header *)cursor;
    cursor += sizeof(struct ieee8022_llc_snap_header);

    /* Check if this is an EAPOL frame (WPA handshake message).
     * An EAPOL frame must have:
     *   1. Sufficient remaining packet length
     *   2. SNAP header with correct DSAP (0xAA), SSAP (0xAA), Control (0x03)
     *   3. EtherType set to EAPOL (0x888E) */
    safe_size = (cursor - packet) + sizeof(struct ieee8021x_authentication_header);
    is_eapol = (packet_header->caplen >= safe_size &&
                llc_snap_header->dsap == ZZ_DSAP_SNAP &&
                llc_snap_header->ssap == ZZ_SSAP_SNAP &&
                llc_snap_header->control == ZZ_CONTROL_SNAP &&
                llc_snap_header->type == htobe16(ZZ_EAPOL_ETHERTYPE));

    /* Extract EAPOL authentication header if present */
    if (is_eapol) {
        authentication_header = (struct ieee8021x_authentication_header *)cursor;
    } else {
        authentication_header = NULL;  /* Regular data frame (not EAPOL) */
    }

    /* Phase 10: Invoke handshake state machine */

    /* Process this packet through the state machine.
     * This tracks handshake progress, detects retransmissions, handles timeouts,
     * and determines what action to take. */
    outcome = zz_process_packet(zz, station, bssid, packet_header,
                                authentication_header);

    /* Phase 11: Handle outcome - process state machine results */

    /* Check if packet should be ignored (retransmission, invalid, etc.) */
    if (outcome.ignore) {
        switch (outcome.ignore_reason) {
        case ZZ_IGNORE_REASON_RETRANSMISSION:
            /* Duplicate handshake message - already seen this exact frame */
            log_ts("%s @ %s $'%s' - Handshake message #%d (retransmission)",
                   station_str, bssid_str, bss->ssid, outcome.handshake_info);
            break;
        case ZZ_IGNORE_REASON_INVALID_EAPOL:
            /* EAPOL frame with incorrect key information flags */
            log_ts("%s @ %s $'%s' - Ignoring invalid key flags",
                   station_str, bssid_str, bss->ssid);
            break;
        case ZZ_IGNORE_REASON_INVALID_COUNTER:
            /* EAPOL frame with out-of-order replay counter */
            log_ts("%s @ %s $'%s' - Ignoring invalid replay counter",
                   station_str, bssid_str, bss->ssid);
            break;
        }

        return;  /* Don't process ignored packets further */
    }

    /* Dump this packet to output file if requested by state machine.
     * This includes handshake messages and relevant data frames. */
    if (outcome.dump_packet) {
        /* Count non-EAPOL data packets for statistics */
        if (!authentication_header) {
            bss->n_data_packets++;
        }

        /* Write packet to pcap file */
        if (zz->dumper) {
            pcap_dump((u_char *)zz->dumper, packet_header, packet);
        }
    }

    /* In active mode, notify killer to start/continue deauthentication attacks.
     * This is triggered for new clients or when tracking should (re)start. */
    if (outcome.new_client || outcome.track_client) {
        if (zz->setup.is_live) {
            /* Post message to killer via pipe (non-blocking) */
            zz_killer_post_message(&zz->killer, station, bssid, outcome);
        }
    }

    /* Prepare additional logging information based on tracking reason */
    extra_info = "";
    if (outcome.track_client) {
        switch (outcome.track_reason) {
        case ZZ_TRACK_REASON_ALIVE:
            /* Client showed activity after being idle - log separately */
            log_ts("%s @ %s $'%s' - Activity detected again",
                   station_str, bssid_str, bss->ssid);
            break;
        case ZZ_TRACK_REASON_FIRST_HANDSHAKE:
            /* First time we see this client attempt a handshake */
            extra_info = " (first attempt detected)";
            break;
        case ZZ_TRACK_REASON_EXPIRATION:
            /* Previous handshake attempt expired, starting over */
            extra_info = " (causes restart due to expiration)";
            break;
        case ZZ_TRACK_REASON_INVALIDATION:
            /* Handshake invalidated (e.g., out-of-order message), restarting */
            extra_info = " (caused restart due to invalidation)";
            break;
        }
    }

    /* Log handshake message detection (verbose mode) */
    if (outcome.handshake_info) {
        log_ts("%s @ %s $'%s' - Handshake message #%d%s",
               station_str, bssid_str, bss->ssid, outcome.handshake_info, extra_info);
    }

    /* Notify user of newly discovered client */
    if (outcome.new_client) {
        zz_out("New client %s @ %s $'%s'", station_str, bssid_str, bss->ssid);
    }

    /* Handle successful handshake capture */
    if (outcome.got_handshake) {
        /* Notify user with happy emoji */
        zz_out("^_^ Full handshake for %s @ %s $'%s'", station_str, bssid_str, bss->ssid);

        /* In active mode, stop deauthenticating this client (we got what we need) */
        if (zz->setup.is_live) {
            zz_killer_post_message(&zz->killer, station, bssid, outcome);
        }

        /* Update statistics */
        bss->n_handshakes++;                    /* Increment handshake count for this BSS */
        zz_members_put(&bss->stations, station); /* Add station to BSS's station set */

        /* If early quit mode enabled (-q), exit immediately after first handshake */
        if (zz->setup.is_live && zz->setup.early_quit) {
            pcap_breakloop(zz->pcap);
        }
    }
}
