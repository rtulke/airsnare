/*
 * dispatcher.c - Signal handling and periodic task dispatch
 *
 * Implements the dispatcher thread that runs alongside the main packet
 * capture loop. Handles signals and invokes the killer subsystem at
 * regular intervals to send deauthentication frames.
 *
 * All signals are delivered to the dispatcher thread; the main thread
 * blocks them all via sigfillset so there is no need for a global pcap
 * handle or an async signal handler.
 *
 * Signal routing:
 *   SIGUSR1       - Cycle through log levels (all platforms)
 *   SIGINT/SIGTERM - Break the pcap loop for graceful shutdown (all platforms)
 *   SIGALRM       - Periodic timer on Linux (driven by setitimer)
 *   macOS timer   - kqueue EVFILT_TIMER (replaces deprecated setitimer)
 */

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#ifdef __APPLE__
#  include <sys/event.h>  /* kqueue, kevent, EVFILT_TIMER, EVFILT_SIGNAL */
#else
#  include <sys/time.h>   /* setitimer, struct itimerval */
#endif

#include "dispatcher.h"
#include "handler.h"
#include "killer.h"
#include "log.h"
#include "terminal.h"

/* Interval between periodic killer invocations (in seconds) */
#define DISPATCHER_TIMEOUT 1

#ifdef __APPLE__

/*
 * Dispatcher thread (macOS) — kqueue-based periodic timer + signals.
 * All signals are blocked in the main thread (sigfillset in zz_dispatcher_start),
 * so EVFILT_SIGNAL reliably intercepts them without racing the normal signal path.
 */
static void *dispatcher(void *_zz) {
    zz_handler *zz = _zz;
    struct kevent changes[4];
    struct kevent events[4];
    int kq;
    int error = 0;
    int nev;
    int i;

    kq = kqueue();
    if (kq == -1) {
        zz_error(zz, "Cannot create kqueue: %s", strerror(errno));
        return (void *)0;
    }

    /* Periodic 1-second timer (replaces SIGALRM / setitimer) */
    EV_SET(&changes[0], 1,       EVFILT_TIMER,  EV_ADD, NOTE_SECONDS, DISPATCHER_TIMEOUT, NULL);
    /* SIGUSR1 for log-level cycling */
    EV_SET(&changes[1], SIGUSR1, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
    /* SIGINT / SIGTERM for graceful shutdown */
    EV_SET(&changes[2], SIGINT,  EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
    EV_SET(&changes[3], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);

    if (kevent(kq, changes, 4, NULL, 0, NULL) == -1) {
        zz_error(zz, "Cannot register kqueue events: %s", strerror(errno));
        close(kq);
        return (void *)0;
    }

    while (!zz->is_done) {
        struct timespec timeout;
        timeout.tv_sec  = DISPATCHER_TIMEOUT;
        timeout.tv_nsec = 0;

        nev = kevent(kq, NULL, 0, events, 4, &timeout);
        if (nev == -1) {
            if (errno == EINTR) {
                continue;
            }
            zz_error(zz, "kevent failed: %s", strerror(errno));
            error = 1;
            break;
        }

        for (i = 0; i < nev; i++) {
            switch (events[i].filter) {
            case EVFILT_SIGNAL:
                switch ((int)events[i].ident) {
                case SIGUSR1:
                    /* Cycle through log levels: ERROR → INFO → WARN → DEBUG → TRACE → ERROR */
                    zz->setup.log_level =
                        (zz->setup.log_level + 1) % (ZZ_LOG_TRACE + 1);
                    zz_info("Log level changed to: %s",
                            ZZ_LOG_LEVEL_NAMES[zz->setup.log_level]);
                    break;
                case SIGINT:
                case SIGTERM:
                    /* Graceful shutdown: break the pcap loop */
                    pcap_breakloop(zz->pcap);
                    zz->is_done = 1;
                    break;
                }
                break;

            case EVFILT_TIMER:
                /* Periodic tick: invoke killer in active mode */
                if (!zz->setup.is_passive) {
                    if (!zz_killer_run(zz, &zz->killer)) {
                        error = zz->is_done = 1;
                    }
                }
                break;
            }
        }
    }

    close(kq);
    return error ? (void *)0 : (void *)1;
}

#else

/*
 * Dispatcher thread (Linux) — sigwait-based, driven by setitimer/SIGALRM.
 * Continues until zz->is_done is set.
 *
 * Handles four signals:
 *   SIGUSR1       - Cycle through log levels
 *   SIGALRM       - Periodic timer (triggers killer execution)
 *   SIGINT/SIGTERM - Graceful shutdown (breaks pcap loop)
 */
static void *dispatcher(void *_zz) {
    zz_handler *zz = _zz;
    sigset_t set;
    struct itimerval timer;
    int error;

    /* Wait for all signals we care about */
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);  /* Verbose toggle */
    sigaddset(&set, SIGALRM);  /* Periodic timer */
    sigaddset(&set, SIGINT);   /* Ctrl-C graceful shutdown */
    sigaddset(&set, SIGTERM);  /* kill graceful shutdown */

    /* Set up periodic alarm */
    memset(&timer, 0, sizeof(struct itimerval));
    timer.it_value.tv_sec = DISPATCHER_TIMEOUT;
    timer.it_interval.tv_sec = DISPATCHER_TIMEOUT;
    if (setitimer(ITIMER_REAL, &timer, NULL) != 0) {
        zz_error(zz, "Cannot configure dispatcher timer: %s", strerror(errno));
        return (void *)0;
    }

    error = 0;
    while (!zz->is_done) {
        int signal;

        {
            int sigwait_result = sigwait(&set, &signal);
            if (sigwait_result != 0) {
                zz_error(zz, "sigwait failed: %s", strerror(sigwait_result));
                zz->is_done = 1;
                error = 1;
                break;
            }
        }

        switch (signal) {
        case SIGUSR1:
            /* Cycle through log levels: ERROR → INFO → WARN → DEBUG → TRACE → ERROR */
            zz->setup.log_level = (zz->setup.log_level + 1) % (ZZ_LOG_TRACE + 1);
            zz_info("Log level changed to: %s", ZZ_LOG_LEVEL_NAMES[zz->setup.log_level]);
            break;

        case SIGALRM:
            /* Periodic timer expired — invoke killer if in active mode */
            if (!zz->setup.is_passive) {
                if (!zz_killer_run(zz, &zz->killer)) {
                    error = zz->is_done = 1;
                }
            }
            break;

        case SIGINT:
        case SIGTERM:
            /* Graceful shutdown: break the pcap loop */
            pcap_breakloop(zz->pcap);
            zz->is_done = 1;
            break;
        }
    }

    /* Clean up: disable the periodic alarm */
    if (!zz->setup.is_passive) {
        memset(&timer, 0, sizeof(struct itimerval));
        if (setitimer(ITIMER_REAL, &timer, NULL) != 0) {
            zz_error(zz, "Cannot disable dispatcher timer: %s", strerror(errno));
            error = 1;
        }
    }

    return (error ? (void *)0 : (void *)1);
}

#endif

/*
 * Start the dispatcher thread.
 * Blocks all signals in the calling (main) thread so that SIGINT, SIGTERM,
 * and SIGUSR1 are delivered to the dispatcher thread instead.  No async
 * signal handler or global pcap handle is required.
 *
 * Parameters:
 *   zz - Handler with configuration
 *   thread - Output parameter for created thread handle
 *
 * Returns:
 *   1 on success, 0 on failure
 */
int zz_dispatcher_start(zz_handler *zz, pthread_t *thread) {
    sigset_t set;
    sigset_t previous_mask;
    int pthread_error;

    /* Block all signals in the main thread so the dispatcher thread
     * receives them via kqueue EVFILT_SIGNAL (macOS) or sigwait (Linux). */
    sigfillset(&set);
    pthread_error = pthread_sigmask(SIG_SETMASK, &set, &previous_mask);
    if (pthread_error != 0) {
        zz_error(zz, "Cannot apply signal mask: %s", strerror(pthread_error));
        return 0;
    }

    zz_debug("Starting the dispatcher thread");
    pthread_error = pthread_create(thread, NULL, dispatcher, zz);
    if (pthread_error != 0) {
        pthread_sigmask(SIG_SETMASK, &previous_mask, NULL);
        zz_error(zz, "Cannot create dispatcher thread: %s", strerror(pthread_error));
        return 0;
    }

    return 1;
}
