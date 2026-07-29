/* kafka_proxy_connect.h
 *
 * HTTP CONNECT proxy support for librdkafka-based rsyslog plugins
 * (imkafka / omkafka), implemented via rd_kafka_conf_set_connect_cb().
 *
 * How it works:
 *   librdkafka creates the broker socket itself (non-blocking), then hands
 *   it to our connect callback instead of calling connect() directly.
 *   We temporarily switch the socket to blocking mode (with I/O timeouts),
 *   connect it to the HTTP proxy, perform the "CONNECT host:port" exchange,
 *   then restore non-blocking mode and return 0. librdkafka then proceeds
 *   with its normal state machine (TLS handshake, SASL, ApiVersion...) over
 *   the established tunnel, which is fully transparent.
 *
 * Requirements: librdkafka >= 0.9.5 (rd_kafka_conf_set_connect_cb).
 *
 * This header is self-contained and must be included from imkafka.c AFTER
 * the rsyslog headers (it uses LogError / DBGPRINTF / RS_RET_KAFKA_ERROR).
 *
 * Licensed under the Apache License, Version 2.0 (same as rsyslog).
 */
#ifndef KAFKA_PROXY_CONNECT_H_INCLUDED
#define KAFKA_PROXY_CONNECT_H_INCLUDED

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h> /* strncasecmp */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define KPX_IO_TIMEOUT_SEC 10 /* timeout for proxy connect + CONNECT exchange */
#define KPX_MAX_RESPONSE 4096 /* max size of proxy HTTP response headers      */

typedef struct kpx_cfg_s {
    char host[256]; /* proxy host */
    char port[16]; /* proxy port (string, for getaddrinfo) */
    char authhdr[512]; /* pre-built "Proxy-Authorization: Basic ...\r\n" or "" */
    int enabled;
} kpx_cfg_t;

/* ------------------------------------------------------------------------ */
/* minimal base64 (for Proxy-Authorization: Basic)                          */
/* ------------------------------------------------------------------------ */
static void kpx_b64_encode(const unsigned char *in, size_t len, char *out, size_t outsz) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, oi = 0;
    for (i = 0; i < len && oi + 5 <= outsz; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < len) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < len) v |= (unsigned)in[i + 2];
        out[oi++] = t[(v >> 18) & 0x3f];
        out[oi++] = t[(v >> 12) & 0x3f];
        out[oi++] = (i + 1 < len) ? t[(v >> 6) & 0x3f] : '=';
        out[oi++] = (i + 2 < len) ? t[v & 0x3f] : '=';
    }
    out[oi] = '\0';
}

/* ------------------------------------------------------------------------ */
/* Parse proxy URL "host:port" or "http://host:port[/]".                    */
/* credentials: optional "user:password" for Basic auth (may be NULL).      */
/* Returns 0 on success, -1 on parse error.                                 */
/* Note: IPv6 literal proxy addresses ("[::1]:3128") are not supported;     */
/* use a resolvable name instead.                                           */
/* ------------------------------------------------------------------------ */
static int kpx_cfg_init(kpx_cfg_t *p, const char *url, const char *credentials) {
    const char *s = url;
    const char *colon;
    size_t hlen, plen;

    memset(p, 0, sizeof(*p));
    if (url == NULL || *url == '\0') return -1;

    if (strncasecmp(s, "http://", 7) == 0) {
        s += 7;
    } else if (strncasecmp(s, "https://", 8) == 0) {
        /* TLS *to the proxy itself* is not implemented */
        return -1;
    }

    colon = strrchr(s, ':');
    if (colon == NULL || colon == s) return -1;

    hlen = (size_t)(colon - s);
    if (hlen >= sizeof(p->host)) return -1;
    memcpy(p->host, s, hlen);
    p->host[hlen] = '\0';

    plen = strcspn(colon + 1, "/");
    if (plen == 0 || plen >= sizeof(p->port)) return -1;
    memcpy(p->port, colon + 1, plen);
    p->port[plen] = '\0';

    if (credentials != NULL && *credentials != '\0') {
        char b64[384];
        kpx_b64_encode((const unsigned char *)credentials, strlen(credentials), b64, sizeof(b64));
        snprintf(p->authhdr, sizeof(p->authhdr), "Proxy-Authorization: Basic %s\r\n", b64);
    }
    p->enabled = 1;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* toggle O_NONBLOCK                                                        */
/* ------------------------------------------------------------------------ */
static int kpx_set_blocking(int fd, int blocking) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl == -1) return -1;
    fl = blocking ? (fl & ~O_NONBLOCK) : (fl | O_NONBLOCK);
    return fcntl(fd, F_SETFL, fl);
}

static void kpx_set_io_timeout(int fd, int seconds) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static int kpx_send_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* librdkafka connect callback.                                             */
/*                                                                          */
/* opaque MUST point to a kpx_cfg_t (set via rd_kafka_conf_set_opaque()).   */
/* `id` is the broker name as known by librdkafka, formatted                */
/* "host:port/<nodeid>" (e.g. "broker1.example.com:9092/1" or               */
/* ".../bootstrap"). We use it as the CONNECT target so that the *proxy*    */
/* performs the final DNS resolution of the broker.                         */
/*                                                                          */
/* Return value convention (librdkafka): 0 on success, errno on failure.    */
/* ------------------------------------------------------------------------ */
static int kpx_connect_cb(int sockfd,
                          const struct sockaddr *addr,
                          int addrlen,
                          const char *id,
                          void *opaque) {
    const kpx_cfg_t *p = (const kpx_cfg_t *)opaque;
    char target[300];
    char req[1024];
    char resp[KPX_MAX_RESPONSE];
    size_t n, resplen = 0;
    struct addrinfo hints, *res = NULL;
    int r, ret;

    (void)addrlen;

    if (p == NULL || !p->enabled) return EINVAL;

    /* target = broker name without the trailing "/<nodeid>" */
    n = strcspn(id, "/");
    if (n == 0 || n >= sizeof(target)) return EINVAL;
    memcpy(target, id, n);
    target[n] = '\0';
    if (strchr(target, ':') == NULL) return EINVAL;

    /* Resolve the proxy. The socket was created by librdkafka with the
     * address family of the *broker's* resolved address, so we must pick
     * a proxy address of the same family. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (addr != NULL) ? addr->sa_family : AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    r = getaddrinfo(p->host, p->port, &hints, &res);
    if (r != 0 || res == NULL) {
        LogError(0, RS_RET_KAFKA_ERROR, "imkafka: proxy: cannot resolve proxy %s:%s (family %d): %s", p->host,
                 p->port, (addr != NULL) ? addr->sa_family : -1, gai_strerror(r));
        return EHOSTUNREACH;
    }

    /* Blocking mode + I/O timeouts for the whole handshake. This only
     * blocks the librdkafka broker thread, which is acceptable and is
     * bounded by KPX_IO_TIMEOUT_SEC. */
    if (kpx_set_blocking(sockfd, 1) == -1) {
        ret = errno ? errno : EINVAL;
        goto out_free;
    }
    kpx_set_io_timeout(sockfd, KPX_IO_TIMEOUT_SEC);

    /* TCP connect to the proxy (first resolved address only: a socket
     * cannot portably be reused for connect() after a failure; librdkafka
     * will retry the whole broker connection anyway). */
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) != 0) {
        ret = errno ? errno : ECONNREFUSED;
        LogError(0, RS_RET_KAFKA_ERROR, "imkafka: proxy: connect to %s:%s failed: %s", p->host, p->port,
                 strerror(ret));
        goto out_restore;
    }

    /* HTTP CONNECT request */
    r = snprintf(req, sizeof(req),
                 "CONNECT %s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "%s"
                 "Proxy-Connection: keep-alive\r\n"
                 "\r\n",
                 target, target, p->authhdr);
    if (r < 0 || (size_t)r >= sizeof(req)) {
        ret = EINVAL;
        goto out_restore;
    }
    if (kpx_send_all(sockfd, req, (size_t)r) != 0) {
        ret = errno ? errno : EIO;
        LogError(0, RS_RET_KAFKA_ERROR, "imkafka: proxy: sending CONNECT for %s failed: %s", target, strerror(ret));
        goto out_restore;
    }

    /* Read response headers until CRLFCRLF. The proxy sends nothing after
     * its response until we speak, so we cannot swallow Kafka bytes here. */
    for (;;) {
        ssize_t rn;
        if (resplen >= sizeof(resp) - 1) {
            ret = EMSGSIZE;
            goto out_log;
        }
        rn = recv(sockfd, resp + resplen, sizeof(resp) - 1 - resplen, 0);
        if (rn == 0) {
            ret = ECONNRESET;
            goto out_log;
        }
        if (rn < 0) {
            if (errno == EINTR) continue;
            ret = errno;
            goto out_log;
        }
        resplen += (size_t)rn;
        resp[resplen] = '\0';
        if (strstr(resp, "\r\n\r\n") != NULL) break;
    }

    /* Expect "HTTP/1.x 200 ..." */
    {
        const char *sp = strchr(resp, ' ');
        int status = (sp != NULL) ? atoi(sp + 1) : 0;
        if (status != 200) {
            char firstline[128];
            size_t fl = strcspn(resp, "\r\n");
            if (fl >= sizeof(firstline)) fl = sizeof(firstline) - 1;
            memcpy(firstline, resp, fl);
            firstline[fl] = '\0';
            LogError(0, RS_RET_KAFKA_ERROR, "imkafka: proxy: CONNECT %s refused by %s:%s: '%s'", target, p->host,
                     p->port, firstline);
            ret = (status == 407) ? EACCES : ECONNREFUSED;
            goto out_restore;
        }
    }

    DBGPRINTF("imkafka: proxy: tunnel established to %s via %s:%s\n", target, p->host, p->port);
    ret = 0;
    goto out_restore;

out_log:
    LogError(0, RS_RET_KAFKA_ERROR, "imkafka: proxy: reading CONNECT response for %s failed: %s", target,
             strerror(ret));
out_restore:
    /* librdkafka expects a non-blocking socket back */
    kpx_set_io_timeout(sockfd, 0);
    if (kpx_set_blocking(sockfd, 0) == -1 && ret == 0) ret = errno ? errno : EINVAL;
out_free:
    if (res != NULL) freeaddrinfo(res);
    return ret;
}

#endif /* KAFKA_PROXY_CONNECT_H_INCLUDED */
