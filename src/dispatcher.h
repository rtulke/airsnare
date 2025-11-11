/*
 * dispatcher.h - Main packet capture dispatch loop
 *
 * Manages the packet capture thread that runs the pcap_loop() and
 * periodically invokes the deauthentication killer subsystem.
 * Handles signal management for graceful shutdown and verbose toggle.
 */

#ifndef ZZ_DISPATCHER_H
#define ZZ_DISPATCHER_H

#include <pthread.h>

#include "handler.h"

/*
 * Start the packet dispatcher in a new thread.
 * The dispatcher thread:
 *   - Runs pcap_loop() to capture and process packets
 *   - Sets up signal handlers for SIGUSR1 (toggle verbose) and SIGALRM (periodic timer)
 *   - Periodically invokes the killer to send deauth frames
 *   - Runs until zz->is_done is set or pcap_breakloop() is called
 *
 * Parameters:
 *   zz - Main handler with pcap interface and configuration
 *   thread - Output parameter for the created thread handle
 *
 * Returns:
 *   1 on success, 0 on failure (error in zz->error_buffer)
 */
int zz_dispatcher_start(zz_handler *zz, pthread_t *thread);

#endif
