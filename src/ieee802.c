/*
 * ieee802.c - IEEE 802.11 protocol utilities
 *
 * Implements utility functions for working with MAC addresses and SSIDs,
 * including conversion between different representations and safe string
 * formatting for display.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ieee802.h"

/*
 * Lookup table for fast byte-to-hex string conversion.
 * Each entry is a 2-character hex representation of a byte value (0x00-0xFF).
 * This avoids repeated sprintf() calls for better performance.
 */
static const char *hex_table[] = {
    "00", "01", "02", "03", "04", "05", "06", "07",
    "08", "09", "0A", "0B", "0C", "0D", "0E", "0F",
    "10", "11", "12", "13", "14", "15", "16", "17",
    "18", "19", "1A", "1B", "1C", "1D", "1E", "1F",
    "20", "21", "22", "23", "24", "25", "26", "27",
    "28", "29", "2A", "2B", "2C", "2D", "2E", "2F",
    "30", "31", "32", "33", "34", "35", "36", "37",
    "38", "39", "3A", "3B", "3C", "3D", "3E", "3F",
    "40", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "4A", "4B", "4C", "4D", "4E", "4F",
    "50", "51", "52", "53", "54", "55", "56", "57",
    "58", "59", "5A", "5B", "5C", "5D", "5E", "5F",
    "60", "61", "62", "63", "64", "65", "66", "67",
    "68", "69", "6A", "6B", "6C", "6D", "6E", "6F",
    "70", "71", "72", "73", "74", "75", "76", "77",
    "78", "79", "7A", "7B", "7C", "7D", "7E", "7F",
    "80", "81", "82", "83", "84", "85", "86", "87",
    "88", "89", "8A", "8B", "8C", "8D", "8E", "8F",
    "90", "91", "92", "93", "94", "95", "96", "97",
    "98", "99", "9A", "9B", "9C", "9D", "9E", "9F",
    "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7",
    "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF",
    "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7",
    "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF",
    "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7",
    "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF",
    "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7",
    "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF",
    "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7",
    "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF",
    "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7",
    "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"
};

/*
 * Convert a 6-byte MAC address array to zz_mac_addr (64-bit integer).
 * The MAC address is stored in network byte order (big-endian).
 *
 * Parameters:
 *   octets - 6-byte array containing the MAC address
 *
 * Returns:
 *   MAC address as 64-bit integer (upper 16 bits are zero)
 */
zz_mac_addr zz_mac_addr_from_array(const uint8_t *octets) {
    return ((zz_mac_addr)octets[0] << 40) |
           ((zz_mac_addr)octets[1] << 32) |
           ((zz_mac_addr)octets[2] << 24) |
           ((zz_mac_addr)octets[3] << 16) |
           ((zz_mac_addr)octets[4] <<  8) |
           ((zz_mac_addr)octets[5] <<  0);
}

/*
 * Convert a zz_mac_addr (64-bit integer) to a 6-byte array.
 * Extracts each byte from the 48-bit MAC address.
 *
 * Parameters:
 *   octets - Output buffer (must be at least 6 bytes)
 *   addr - MAC address as 64-bit integer
 */
void zz_mac_addr_to_array(uint8_t *octets, zz_mac_addr addr) {
    octets[0] = (addr >> 40) & 0xff;
    octets[1] = (addr >> 32) & 0xff;
    octets[2] = (addr >> 24) & 0xff;
    octets[3] = (addr >> 16) & 0xff;
    octets[4] = (addr >>  8) & 0xff;
    octets[5] = (addr >>  0) & 0xff;
}

/*
 * Format a MAC address as a string "XX:XX:XX:XX:XX:XX".
 * Uses the hex_table for fast conversion without sprintf overhead.
 *
 * Parameters:
 *   buffer - Output buffer (must be at least ZZ_MAC_ADDR_STRING_SIZE bytes)
 *   addr - MAC address to format
 */
void zz_mac_addr_sprint(char *buffer, zz_mac_addr addr) {
    /* Extract each byte and format with colons as separators */
    buffer[ 0] = hex_table[(addr >> 40) & 0xff][0];
    buffer[ 1] = hex_table[(addr >> 40) & 0xff][1];
    buffer[ 2] = ':';
    buffer[ 3] = hex_table[(addr >> 32) & 0xff][0];
    buffer[ 4] = hex_table[(addr >> 32) & 0xff][1];
    buffer[ 5] = ':';
    buffer[ 6] = hex_table[(addr >> 24) & 0xff][0];
    buffer[ 7] = hex_table[(addr >> 24) & 0xff][1];
    buffer[ 8] = ':';
    buffer[ 9] = hex_table[(addr >> 16) & 0xff][0];
    buffer[10] = hex_table[(addr >> 16) & 0xff][1];
    buffer[11] = ':';
    buffer[12] = hex_table[(addr >>  8) & 0xff][0];
    buffer[13] = hex_table[(addr >>  8) & 0xff][1];
    buffer[14] = ':';
    buffer[15] = hex_table[(addr >>  0) & 0xff][0];
    buffer[16] = hex_table[(addr >>  0) & 0xff][1];
    buffer[17] = '\0';
}

/*
 * Parse a MAC address from a string.
 * Accepts formats: "XX:XX:XX:XX:XX:XX" or "XX-XX-XX-XX-XX-XX"
 * Each XX must be a valid 2-digit hexadecimal number.
 *
 * Parameters:
 *   addr - Output MAC address
 *   buffer - Input string to parse
 *   terminators - String of characters that mark end of MAC address
 *
 * Returns:
 *   1 on successful parse, 0 on parse error
 */
int zz_mac_addr_sscan(zz_mac_addr *addr, const char *buffer, const char *terminators) {
    const char *ptr;
    int i;
    uint8_t octets[6] = {0};

    /* Parse 6 octets (bytes) separated by ':' or '-' */
    i = 0;
    ptr = buffer;
    while (i < 6) {
        char *chk;

        /* Process groups of 3 characters: "XX:" or "XX-" */
        switch ((ptr - buffer) % 3) {
        case 0:
        case 1:
            /* First two characters must be hex digits */
            if (!isxdigit(*ptr)) {
                return 0;
            }
            break;

        case 2:
            /* Third character is separator or terminator */
            octets[i++] = strtol(ptr - 2, &chk, 16);
            /* Validate: proper hex conversion, correct separator */
            if (chk != ptr ||
                (i < 6 && !strchr(":-", *ptr)) ||         /* Mid-address: need : or - */
                (i == 6 && !strchr(terminators, *ptr))) { /* End: need terminator */
                return 0;
            }
            break;
        }

        ptr++;
    }

    /* Convert parsed octets to internal format */
    *addr = zz_mac_addr_from_array(octets);
    return 1;
}

/*
 * Escape non-printable characters in SSID for safe display.
 * SSIDs can contain arbitrary binary data, so non-printable characters
 * are escaped as "\xHH" hexadecimal sequences. Backslashes and quotes
 * are also escaped to avoid confusion.
 *
 * Parameters:
 *   buffer - Output buffer (must be at least ZZ_BEACON_MAX_SSID_ESCAPED_LENGTH + 1)
 *   ssid - Input SSID string (may contain binary data)
 *   ssid_length - Length of SSID in bytes
 */
void zz_ssid_escape_sprint(char *buffer, const char *ssid, int ssid_length) {
    int i;
    char *ptr;

    ptr = buffer;
    for (i = 0; i < ssid_length; i++) {
        char c;

        c = ssid[i];
        /* Keep printable ASCII characters except backslash and single quote */
        if ((isgraph(c) || c == ' ') && c != '\\' && c != '\'') {
            *ptr++ = c;
        } else {
            /* Escape non-printable as \xHH */
            sprintf(ptr, "\\x%02x", (unsigned char)c);
            ptr += 4;
        }
    }

    /* Null-terminate the output string */
    *ptr = '\0';
}
