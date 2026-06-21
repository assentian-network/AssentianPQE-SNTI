/*
 * QNT CPU Miner — Simple XMSS-based Proof-of-Useful-Work miner
 * Compile: gcc -O2 -o qnt_miner qnt_miner.c -lcrypto -lpthread
 * Usage: ./qnt_miner [threads] [difficulty]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <openssl/sha.h>

#include "xmss.h"
#include "params.h"
#include "xmss_core.h"

#define XMSS_OID 0x00000001
#define MAX_THREADS 16

static volatile int g_running = 1;
static uint64_t g_total_hashes = 0;
static uint64_t g_blocks_found = 0;
static time_t g_start_time = 0;

typedef struct {
    int thread_id;
    uint32_t difficulty;
    uint64_t hashes;
    int found;
    uint32_t winning_nonce;
} miner_thread_t;

void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

void print_stats(void) {
    time_t elapsed = time(NULL) - g_start_time;
    if (elapsed == 0) elapsed = 1;
    double hashrate = (double)g_total_hashes / elapsed;
    printf("\r[STATS] Hashes: %lu | Rate: %.2f H/s | Blocks: %lu | Time: %lds   ",
           (unsigned long)g_total_hashes, hashrate, (unsigned long)g_blocks_found, (long)elapsed);
    fflush(stdout);
}

/* Simple hash-based work simulation using XMSS key operations */
void *miner_worker(void *arg) {
    miner_thread_t *t = (miner_thread_t *)arg;
    xmss_params params;
    
    if (xmss_parse_oid(&params, XMSS_OID) != 0) {
        fprintf(stderr, "Thread %d: Failed to parse XMSS params\n", t->thread_id);
        return NULL;
    }

    /* Allocate XMSS key buffers */
    unsigned char pk[params.pk_bytes];
    unsigned char sk[params.sk_bytes];
    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));

    uint32_t nonce = t->thread_id;
    unsigned char header[80];
    unsigned char hash[32];
    
    /* Simulate block header */
    memset(header, 0, sizeof(header));
    header[0] = 0x01; /* version */
    
    t->hashes = 0;
    t->found = 0;

    while (g_running) {
        /* Update nonce in header */
        memcpy(header + 4, &nonce, sizeof(nonce));
        
        /* Hash the header (simulating work) */
        SHA256(header, sizeof(header), hash);
        
        /* Check if hash meets difficulty target */
        uint32_t hash_prefix = (hash[0] << 24) | (hash[1] << 16) | (hash[2] << 8) | hash[3];
        
        if (hash_prefix < t->difficulty) {
            t->found = 1;
            t->winning_nonce = nonce;
            g_blocks_found++;
            
            printf("\n[BLOCK FOUND] Thread %d | Nonce: %u | Hash: %02x%02x%02x%02x...\n",
                   t->thread_id, nonce, hash[0], hash[1], hash[2], hash[3]);
            
            /* In real implementation, submit block to network here */
        }
        
        t->hashes++;
        nonce += MAX_THREADS; /* Each thread searches different nonce space */
        
        /* Update global counter periodically */
        if (t->hashes % 10000 == 0) {
            __sync_fetch_and_add(&g_total_hashes, 10000);
        }
    }
    
    /* Add remaining hashes */
    __sync_fetch_and_add(&g_total_hashes, t->hashes % 10000);
    
    return NULL;
}

int main(int argc, char *argv[]) {
    int num_threads = 2;
    uint32_t difficulty = 0x00FFFFFF; /* Easy difficulty for testing */
    
    if (argc > 1) num_threads = atoi(argv[1]);
    if (argc > 2) difficulty = (uint32_t)strtoul(argv[2], NULL, 0);
    
    if (num_threads < 1) num_threads = 1;
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║           QNT CPU Miner v0.1                     ║\n");
    printf("║   Post-Quantum Proof-of-Useful-Work Mining       ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║ Threads:    %-4d                                 ║\n", num_threads);
    printf("║ Difficulty: 0x%08X                          ║\n", difficulty);
    printf("║ Algorithm:  XMSS-SHA2_10_256                     ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    g_start_time = time(NULL);
    
    pthread_t threads[MAX_THREADS];
    miner_thread_t thread_data[MAX_THREADS];
    
    /* Start miner threads */
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].difficulty = difficulty;
        thread_data[i].hashes = 0;
        thread_data[i].found = 0;
        thread_data[i].winning_nonce = 0;
        
        if (pthread_create(&threads[i], NULL, miner_worker, &thread_data[i]) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            num_threads = i;
            break;
        }
    }
    
    printf("[INFO] Mining started with %d threads. Press Ctrl+C to stop.\n\n", num_threads);
    
    /* Stats loop */
    while (g_running) {
        sleep(2);
        print_stats();
    }
    
    printf("\n\n[INFO] Shutting down...\n");
    
    /* Wait for threads */
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    /* Final stats */
    time_t elapsed = time(NULL) - g_start_time;
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║              MINING SUMMARY                      ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║ Total Hashes:  %-20lu                 ║\n", (unsigned long)g_total_hashes);
    printf("║ Blocks Found:  %-20lu                 ║\n", (unsigned long)g_blocks_found);
    printf("║ Runtime:       %-20ld seconds          ║\n", (long)elapsed);
    if (elapsed > 0) {
        printf("║ Avg Hashrate:  %-20.2f H/s            ║\n", (double)g_total_hashes / elapsed);
    }
    printf("╚══════════════════════════════════════════════════╝\n");
    
    return 0;
}
