/*
 * dissector.h - Packet dissection and parsing
 *
 * Provides the main packet processing callback used by libpcap.
 * Dissects captured packets by parsing protocol headers (radiotap,
 * IEEE 802.11 MAC, LLC/SNAP, EAPOL) and dispatches to appropriate
 * handlers based on frame type.
 */

#ifndef ZZ_DISSECT_H
#define ZZ_DISSECT_H

#include <pcap/pcap.h>

#include "handler.h"

/*
 * Dissect and process a captured packet.
 * This is the callback function registered with pcap_loop(). It:
 *   - Parses radiotap and 802.11 headers
 *   - Identifies frame type (beacon, data, EAPOL)
 *   - Extracts MAC addresses (source, destination, BSSID)
 *   - Applies include/exclude filters
 *   - Dispatches to handshake processor for EAPOL frames
 *   - Writes relevant frames to output pcap
 *
 * Parameters:
 *   _zz - Opaque pointer to zz_handler (cast from u_char* for pcap compatibility)
 *   packet_header - libpcap packet metadata (timestamp, capture/wire length)
 *   packet - Raw packet data including radiotap and all headers
 */
void zz_dissect_packet(u_char *_zz, const struct pcap_pkthdr *packet_header,
                       const uint8_t *packet);

#endif
