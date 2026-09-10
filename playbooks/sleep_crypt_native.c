/* sleep_crypt_native.c -- FIXED-BEHAVIOR compiled sleep-encryption tester.
 *
 * The C counterpart of sleep_crypt_implant.py for machines without python.
 * Same purple-team contract, deliberately:
 *   - fixed behavior: allocates one private page, XOR-decrypts a hardcoded
 *     config blob on wake, flips RW<->RWX, beacons to LOOPBACK ONLY,
 *     re-encrypts before sleep, trims the working set. Nothing else.
 *   - NO payload slot, NO command channel, NO injection, NOT position
 *     independent (a plain exe is all a detection test needs; shellcode
 *     packaging is deployment tooling, not testing tooling).
 *
 * Detection surfaces exercised (same as the python version, minus the
 * interpreter image): MEM-RWX-UNBACKED / MEM-RWX-NEW on every wake flip,
 * MEM-PROMOTE-class RW->exec transitions, unbacked private exec page,
 * signature strings visible ONLY while decrypted, loopback beacon cadence.
 *
 * Build:
 *   Linux:  gcc -O2 -o sleep_crypt_native sleep_crypt_native.c
 *   Windows (MSVC):  cl /O2 sleep_crypt_native.c ws2_32.lib
 *   Windows (MinGW): x86_64-w64-mingw32-gcc -O2 -o sleep_crypt_native.exe \
 *                       sleep_crypt_native.c -lws2_32
 * (MinGW builds additionally exercise the SIG-MINGW signature rule - a
 *  deliberate double-test.)
 */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---------------- CONFIG (edit, recompile) ---------------- */
static const char *PEER_HOST = "127.0.0.1";  /* loopback ONLY (contract) */
static const int   PEER_PORT = 9101;
static const int   SLEEP_S   = 45;            /* encrypted sleep window */
static const int   WAKE_S    = 6;             /* plaintext window */
static const double JITTER   = 0.30;

/* plaintext that lives in the encrypted page while AWAKE */
static const uint8_t PLAINTEXT[] =
    "IMIX_CALLBACK_URI=tcp://127.0.0.1:9101\r\n"
    "IMIX_BEACON_ID=native-sleepcrypt\r\n"
    "IMIX_GUARDRAILS=ccdc-blue\r\n";
/* ---------------------------------------------------------- */

static uint32_t rng_state;
static uint32_t rnd(void) {           /* xorshift32 - jitter only */
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return rng_state;
}

static void xor_crypt(uint8_t *p, size_t n, uint32_t seed) {
    uint32_t s = seed;
    for (size_t i = 0; i < n; i++) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        p[i] ^= (uint8_t)(s >> 24);
    }
}

#ifdef _WIN32
static void net_init(void) {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
}
static int beacon_once(void) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)PEER_PORT);
    a.sin_addr.s_addr = inet_addr(PEER_HOST);
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
        send(s, "sleepcrypt", 10, 0);
        closesocket(s);
        return 0;
    }
    closesocket(s);
    return -1;
}
static void msleep(double s) { Sleep((DWORD)(s * 1000.0)); }
#else
static void net_init(void) {}
static int beacon_once(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)PEER_PORT);
    a.sin_addr.s_addr = inet_addr(PEER_HOST);
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
        send(s, "sleepcrypt", 10, 0);
        close(s);
        return 0;
    }
    close(s);
    return -1;
}
static void msleep(double s) {
    struct timespec ts = { (time_t)s, (long)((s - (time_t)s) * 1e9) };
    nanosleep(&ts, NULL);
}
#endif

/* forward declarations (definitions at the bottom) */
static int getpid_print(void);
static uint32_t getpid_seed(void);
static double now_s(void);

int main(void) {
    net_init();
    rng_state = (uint32_t)time(NULL) ^ (uint32_t)getpid_seed();
    const size_t n = sizeof(PLAINTEXT);
    uint32_t seed = rnd();

#ifdef _WIN32
    uint8_t *page = (uint8_t *)VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                                            PAGE_READWRITE);
    if (!page) return 1;
    DWORD old = 0;
    #define SET_RW()  VirtualProtect(page, 4096, PAGE_READWRITE, &old)
    #define SET_RWX() VirtualProtect(page, 4096, PAGE_EXECUTE_READWRITE, &old)
    #define TRIM()    SetProcessWorkingSetSize((HANDLE)-1, (SIZE_T)-1, (SIZE_T)-1)
#else
    uint8_t *page = (uint8_t *)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 1;
    #define SET_RW()  mprotect(page, 4096, PROT_READ | PROT_WRITE)
    #define SET_RWX() mprotect(page, 4096, PROT_READ | PROT_WRITE | PROT_EXEC)
    #define TRIM()    madvise(page, 4096, MADV_DONTNEED)
#endif

    memcpy(page, PLAINTEXT, n);
    xor_crypt(page, n, seed);            /* start asleep: ciphertext only */

    printf("sleep-crypt native tester: pid %d, page %p (%zu-byte blob)\n",
           getpid_print(), (void *)page, n);
    fflush(stdout);

    for (;;) {
        /* WAKE: decrypt in place, flip exec, beacon */
        xor_crypt(page, n, seed);
        SET_RWX();
        double t0 = now_s();
        beacon_once();
        while (now_s() - t0 < (double)WAKE_S) msleep(0.5);

        /* SLEEP: re-encrypt, drop exec, trim */
        xor_crypt(page, n, seed);
        SET_RW();
        TRIM();
        double j = (double)SLEEP_S * (1.0 + JITTER * ((double)(rnd() % 200 - 100) / 100.0));
        msleep(j);
    }
}

/* small helpers kept at the bottom for readability */
#ifdef _WIN32
static int getpid_print(void) { return (int)GetCurrentProcessId(); }
static uint32_t getpid_seed(void) { return (uint32_t)GetCurrentProcessId(); }
static double now_s(void) {
    LARGE_INTEGER f, c; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
}
#else
#include <sys/types.h>
static int getpid_print(void) { return (int)getpid(); }
static uint32_t getpid_seed(void) { return (uint32_t)getpid(); }
static double now_s(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}
#endif
