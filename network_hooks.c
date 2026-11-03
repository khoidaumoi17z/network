#include <dlfcn.h>
#include <netdb.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "fishhook.h"

#ifndef REAL_OPEN_DEFAULT
#define REAL_OPEN_DEFAULT 0
#endif

#if REAL_OPEN_DEFAULT != 0 && REAL_OPEN_DEFAULT != 1
#error REAL_OPEN_DEFAULT must be 0 or 1
#endif

typedef int (*getaddrinfo_fn)(const char *, const char *,
                              const struct addrinfo *, struct addrinfo **);
typedef ssize_t (*recvmsg_fn)(int, struct msghdr *, int);
typedef ssize_t (*send_fn)(int, const void *, size_t, int);
typedef ssize_t (*recv_fn)(int, void *, size_t, int);

static getaddrinfo_fn original_getaddrinfo;
static recvmsg_fn original_recvmsg;
static send_fn original_send;
static recv_fn original_recv;
static _Atomic int real_open = REAL_OPEN_DEFAULT;

__attribute__((visibility("default")))
void network_hooks_set_real_open(int enabled) {
    atomic_store_explicit(&real_open, enabled != 0, memory_order_release);
}

__attribute__((visibility("default")))
int network_hooks_get_real_open(void) {
    return atomic_load_explicit(&real_open, memory_order_acquire);
}

static int hooked_getaddrinfo(const char *node, const char *service,
                              const struct addrinfo *hints,
                              struct addrinfo **result) {
    if (original_getaddrinfo == NULL) {
        return EAI_SYSTEM;
    }

    char target[4096];
    int written = snprintf(target, sizeof(target), "%s:%s",
                           node != NULL ? node : "(null)",
                           service != NULL ? service : "(null)");
    if (written >= 0 && (size_t)written < sizeof(target) &&
        strstr(target, "sharkios") != NULL) {
        return original_getaddrinfo("168.198.161.199", "80", hints, result);
    }
    return original_getaddrinfo(node, service, hints, result);
}

static ssize_t hooked_recvmsg(int fd, struct msghdr *message, int flags) {
    if (network_hooks_get_real_open()) {
        return 1;
    }
    return original_recvmsg != NULL ? original_recvmsg(fd, message, flags) : -1;
}

static ssize_t hooked_send(int fd, const void *buffer, size_t length, int flags) {
    if (network_hooks_get_real_open()) {
        return 1;
    }
    return original_send != NULL ? original_send(fd, buffer, length, flags) : -1;
}

static ssize_t hooked_recv(int fd, void *buffer, size_t length, int flags) {
    if (network_hooks_get_real_open()) {
        return 1;
    }
    return original_recv != NULL ? original_recv(fd, buffer, length, flags) : -1;
}

__attribute__((constructor))
static void install_network_hooks(void) {
    original_getaddrinfo = (getaddrinfo_fn)dlsym(RTLD_NEXT, "getaddrinfo");
    original_recvmsg = (recvmsg_fn)dlsym(RTLD_NEXT, "recvmsg");
    original_send = (send_fn)dlsym(RTLD_NEXT, "send");
    original_recv = (recv_fn)dlsym(RTLD_NEXT, "recv");

    if (original_getaddrinfo == NULL || original_recvmsg == NULL ||
        original_send == NULL || original_recv == NULL) {
        return;
    }

    struct rebinding hooks[] = {
        {"getaddrinfo", (void *)hooked_getaddrinfo, NULL},
        {"recvmsg", (void *)hooked_recvmsg, NULL},
        {"send", (void *)hooked_send, NULL},
        {"recv", (void *)hooked_recv, NULL},
    };
    (void)rebind_symbols(hooks, sizeof(hooks) / sizeof(hooks[0]));
}
