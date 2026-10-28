#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "exec_kern.skel.h"

struct event {
    unsigned int pid;
    char comm[16];
    char filename[64];
    int blocked;
};

static volatile sig_atomic_t stop = 0;

static void sig_handler(int signo) {
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event *e = data;
    char status_str[32];
    
    if (e->blocked) {
        snprintf(status_str, sizeof(status_str), "\033[1;31mBLOCKED \033[0m");
    } else {
        snprintf(status_str, sizeof(status_str), "\033[1;32mALLOWED \033[0m");
    }

    printf("\033[1;37m│\033[0m FK-Guard \033[1;37m│\033[0m %s\033[1;37m│\033[0m %-8u \033[1;37m│\033[0m %-15.15s \033[1;37m│\033[0m %-47.47s \033[1;37m│\033[0m\n",
           status_str, e->pid, e->comm, e->filename);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    struct exec_kern *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = exec_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = exec_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    err = exec_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("\033[1;36m╔════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\033[0m\n");
    printf("\033[1;33m║  🛡️   FK-KERNEL GUARD — eBPF Real-Time Behavioral Threat & Process Monitor                         ║\033[0m\n");
    printf("\033[1;37m║  Developed by: Fahad Khuwaylid Almuzaini | Institution: Gulf Colleges                              ║\033[0m\n");
    printf("\033[1;36m╚════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\033[0m\n\n");
    printf("\033[1;37m┌──────────┬──────────┬──────────┬─────────────────┬─────────────────────────────────────────────────┐\033[0m\n");
    printf("\033[1;37m│ \033[1;33mSYSTEM   \033[1;37m│ \033[1;33mSTATUS   \033[1;37m│ \033[1;33mPID      \033[1;37m│ \033[1;33mPROCESS (COMM)  \033[1;37m│ \033[1;33mEXECUTABLE PATH                                 \033[1;37m│\033[0m\n");
    printf("\033[1;37m├──────────┼──────────┼──────────┼─────────────────┼─────────────────────────────────────────────────┤\033[0m\n");

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            break;
        }
    }

cleanup:
    printf("\033[1;37m└──────────┴──────────┴──────────┴─────────────────┴─────────────────────────────────────────────────┘\033[0m\n");
    printf("\n\033[1;33m[*] FK-Kernel Guard Monitoring Stopped. Rights Reserved to Fahad Khuwaylid Almuzaini.\033[0m\n");
    ring_buffer__free(rb);
    exec_kern__destroy(skel);
    return err < 0 ? -err : 0;
}
