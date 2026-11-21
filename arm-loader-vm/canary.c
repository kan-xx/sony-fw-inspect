/* Minimal constructor canary writing one bounded 48-byte record when loaded
 * into an executable whose basename is `im.elf`.
 * Uses ARM Linux `O_NOFOLLOW` (0x8000) | `O_CLOEXEC` (0x80000).
 */
typedef unsigned int u32;
typedef int s32;
typedef char abi_u32_must_be_four[(sizeof(u32) == 4) ? 1 : -1];

#ifndef USE_RAW_SVC
extern long syscall(long number, ...);
#define DO_SYSCALL0(n) syscall((long)(n))
#define DO_SYSCALL1(n, a) syscall((long)(n), (long)(a))
#define DO_SYSCALL2(n, a, b) syscall((long)(n), (long)(a), (long)(b))
#define DO_SYSCALL3(n, a, b, c) syscall((long)(n), (long)(a), (long)(b), (long)(c))
#define CANARY_VERSION 1u
#else
static inline long raw_svc3(long nr, long a0, long a1, long a2) {
    register long r7 __asm__("r7") = nr;
    register long r0 __asm__("r0") = a0;
    register long r1 __asm__("r1") = a1;
    register long r2 __asm__("r2") = a2;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7), "r"(r1), "r"(r2) : "memory");
    return r0;
}
#define DO_SYSCALL0(n) raw_svc3((n), 0, 0, 0)
#define DO_SYSCALL1(n, a) raw_svc3((n), (long)(a), 0, 0)
#define DO_SYSCALL2(n, a, b) raw_svc3((n), (long)(a), (long)(b), 0)
#define DO_SYSCALL3(n, a, b, c) raw_svc3((n), (long)(a), (long)(b), (long)(c))
#define CANARY_VERSION 2u
#endif

#define CANARY_PATH "/setting/custom_sound_test/boot-canary"
#define OPEN_FLAGS (1L | 64L | 128L | 0x8000L | 0x80000L) /* O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC */

struct time32 {
    s32 sec;
    s32 usec;
};

struct record {
    u32 magic, version, bytes, pid, ppid;
    s32 time_rc, sec, usec;
    u32 build_tag, exe_length, reserved0, reserved1;
};
typedef char record_must_be_48[(sizeof(struct record) == 48) ? 1 : -1];

static void canary_body(void) {
    char exe[96];
    static const char leaf[] = "/im.elf";
    long n = DO_SYSCALL3(85L, "/proc/self/exe", exe, 96L); /* readlink */
    if (n < 7 || n >= 96) {
        return;
    }
    for (long i = 0; i < 7; i++) {
        if (exe[n - 7 + i] != leaf[i]) {
            return;
        }
    }
    long pid = DO_SYSCALL0(20L); /* getpid */
    if (pid <= 0) {
        return;
    }
    long ppid = DO_SYSCALL0(64L); /* getppid */
    struct time32 tv = {0, 0};
    long tr = DO_SYSCALL2(78L, &tv, 0L); /* gettimeofday */
    struct record r = {
        0x314e4342u,
        CANARY_VERSION,
        48u,
        (u32)pid,
        ppid > 0 ? (u32)ppid : 0u,
        (s32)tr,
        tv.sec,
        tv.usec,
        0x20261021u,
        (u32)n,
        0u,
        0u,
    };
    long fd = DO_SYSCALL3(5L, CANARY_PATH, OPEN_FLAGS, 0600L);
    if (fd < 0) {
        return;
    }
    (void)DO_SYSCALL3(4L, fd, &r, 48L);
    (void)DO_SYSCALL1(6L, fd);
}

#ifndef CX_HOST_TEST
__attribute__((constructor, visibility("hidden"))) static void canary_ctor(void) {
    canary_body();
}
#endif
