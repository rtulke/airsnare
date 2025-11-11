/*
 * dispatcher.c - Signal handling and periodic task dispatch
 *
 * Implements the dispatcher thread that runs alongside the main packet
 * capture loop. Handles signals (SIGUSR1 for verbose toggle, SIGALRM for
 * periodic timer) and invokes the killer subsystem at regular intervals
 * to send deauthentication frames.
 */

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>

#include "dispatcher.h"
#include "handler.h"
#include "killer.h"
#include "terminal.h"

/* Interval between periodic killer invocations (in seconds) */
#define DISPATCHER_TIMEOUT 1

/* Forward declaration to avoid circular dependency with killer.h */
int zz_killer_run(zz_handler *zz, zz_killer *killer);

/* Global pcap handle for signal handler (signal handlers can't take parameters) */
static pcap_t *pcap = NULL;

/*
 * Signal handler for graceful termination (SIGINT, SIGTERM).
 * Breaks the pcap loop, allowing the program to shut down cleanly.
 *
 * Parameters:
 *   signum - Signal number (not used)
 */
static void terminate_pcap_loop(int signum) {
    pcap_breakloop(pcap);
}

/*
 * Dispatcher thread main function.
 * Runs in a separate thread, waiting for signals and periodically
 * invoking the killer subsystem. Continues until zz->is_done is set.
 *
 * Handles two signals:
 *   SIGUSR1 - Toggle verbose logging on/off
 *   SIGALRM - Periodic timer (triggers killer execution)
 *
 * Parameters:
 *   _zz - Opaque pointer to zz_handler
 *
 * Returns:
 *   (void *)1 on success, (void *)0 on error
 */
static void *dispatcher(void *_zz) {
    zz_handler *zz = _zz;
    sigset_t set;
    struct itimerval timer;
    int error;

    /* Prepare signal mask - we'll wait for these signals */
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);  /* Verbose toggle signal */
    sigaddset(&set, SIGALRM);  /* Periodic timer signal */

    /* Set up periodic alarm that fires every DISPATCHER_TIMEOUT seconds.
     * This drives the periodic killer invocation. */
    memset(&timer, 0, sizeof(struct itimerval));
    timer.it_value.tv_sec = DISPATCHER_TIMEOUT;    /* Initial delay */
    timer.it_interval.tv_sec = DISPATCHER_TIMEOUT; /* Repeat interval */
    assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);

    /* Main dispatcher loop - wait for signals */
    error = 0;
    while (!zz->is_done) {
        int signal;

        /* Block until we receive one of the signals in our set */
        assert(sigwait(&set, &signal) == 0);

        switch (signal) {
        case SIGUSR1:
            /* Toggle verbose logging (useful for debugging live captures) */
            if (zz->setup.is_verbose) {
                zz_log("Verbose logging disabled");
                zz->setup.is_verbose = 0;
            } else {
                zz->setup.is_verbose = 1;
                zz_log("Verbose logging enabled");
            }
            break;

        case SIGALRM:
            /* Periodic timer expired.
             * In passive mode, this just helps check the is_done flag.
             * In active mode, invoke the killer to send deauth frames. */
            if (!zz->setup.is_passive) {
                /* Run the killer subsystem (sends deauth frames to targets) */
                if (!zz_killer_run(zz, &zz->killer)) {
                    error = zz->is_done = 1;
                }
            }
            break;
        }
    }

    /* Clean up: disable the periodic alarm */
    if (!zz->setup.is_passive) {
        memset(&timer, 0, sizeof(struct itimerval));
        assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
    }

    /* Return success/failure status to joining thread */
    return (error ? (void *)0 : (void *)1);
}

/*
 * Start the dispatcher thread.
 * Sets up signal handlers and creates the dispatcher thread that will
 * handle signals and periodic tasks.
 *
 * Signal handling strategy:
 *   - SIGINT/SIGTERM: Handled in main thread, breaks pcap loop
 *   - SIGUSR1/SIGALRM: Handled in dispatcher thread
 *   - All other signals: Masked in both threads
 *
 * Parameters:
 *   zz - Handler with configuration
 *   thread - Output parameter for created thread handle
 *
 * Returns:
 *   Always returns 1 (failures are asserted)
 */
int zz_dispatcher_start(zz_handler *zz, pthread_t *thread) {
    struct sigaction sa = {0};
    sigset_t set;

    /* Set up global pcap handle for signal handler */
    pcap = zz->pcap;

    /* Install signal handler for graceful termination */
    sa.sa_handler = terminate_pcap_loop;
    assert(sigaction(SIGINT, &sa, NULL) == 0);  /* Ctrl-C */
    assert(sigaction(SIGTERM, &sa, NULL) == 0); /* kill command */

    /* Mask all signals in the calling thread (main thread) except
     * termination signals, which must be able to break the pcap loop.
     * The dispatcher thread will inherit this mask and modify it. */
    sigfillset(&set);
    sigdelset(&set, SIGINT);   /* Allow SIGINT in main thread */
    sigdelset(&set, SIGTERM);  /* Allow SIGTERM in main thread */
    assert(pthread_sigmask(SIG_SETMASK, &set, NULL) == 0);

    /* Create the dispatcher thread */
    zz_log("Starting the dispatcher thread");
    assert(pthread_create(thread, NULL, dispatcher, zz) == 0);

    return 1;
}
