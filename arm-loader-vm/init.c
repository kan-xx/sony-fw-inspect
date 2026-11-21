#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

/* Isolated QEMU ARM guest PID 1.
 * No network, block disks, or USB devices are attached.
 * Executes self-authored inert `/probe/im.elf` under stock Sony `ld-2.11.2.so`
 * across three canary DSO variants to prove the `DT_RELCOUNT = 0` fix offline.
 */
static int run_trial(const char *name, const char *so, int expect_signal, int expect_version) {
    const char *record = "/setting/custom_sound_test/boot-canary";
    if (unlink(record) && errno != ENOENT) {
        return 1;
    }
    printf("CXVM_TRIAL_BEGIN %s\n", name);
    fflush(stdout);

    pid_t p = fork();
    if (p == 0) {
        char env[256];
        snprintf(env, sizeof(env), "LD_PRELOAD=%s", so);
        char *argv[] = {"/probe/im.elf", NULL};
        char *envp[] = {env, "LD_LIBRARY_PATH=/lib", NULL};
        execve(argv[0], argv, envp);
        _exit(127);
    }

    int status = 0;
    if (p < 0 || waitpid(p, &status, 0) != p) {
        return 1;
    }

    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    int f = open(record, O_RDONLY);
    int n = -1;
    if (f >= 0) {
        n = (int)read(f, buf, sizeof(buf));
        close(f);
    }

    int sig = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    unsigned version = n >= 8
        ? (unsigned)buf[4] | ((unsigned)buf[5] << 8) | ((unsigned)buf[6] << 16) | ((unsigned)buf[7] << 24)
        : 0;

    printf("CXVM_RESULT %s rc=%d signal=%d record_bytes=%d version=%u hex=", name, rc, sig, n, version);
    if (n > 0) {
        for (int i = 0; i < n; i++) {
            printf("%02x", buf[i]);
        }
    }
    puts("");
    fflush(stdout);

    if (expect_signal) {
        return (sig != expect_signal || n != -1);
    }
    return (rc != 0 || sig != 0 || n != 48 || version != (unsigned)expect_version);
}

int main(void) {
    int console = open("/dev/console", O_RDWR);
    if (console >= 0) {
        dup2(console, 0);
        dup2(console, 1);
        dup2(console, 2);
        if (console > 2) {
            close(console);
        }
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    struct rlimit r = {0, 0};
    setrlimit(RLIMIT_CORE, &r);

    if (mount("proc", "/proc", "proc", 0, NULL)) {
        perror("mount proc");
        return 101;
    }

    struct utsname u;
    uname(&u);
    printf("CXVM_BOOT kernel=%s machine=%s pid=%d\n", u.release, u.machine, (int)getpid());

    int failures = 0;
    failures += run_trial("original-V1", "/probe/original-v1.so", 11, 0);
    failures += run_trial("fixed-RELCOUNT0", "/probe/fixed-relcount0.so", 0, 1);
    failures += run_trial("raw-SVC", "/probe/raw-svc.so", 0, 2);

    printf("CXVM_COMPLETE failures=%d scope=original_ARM_loader_on_generic_guest_not_camera\n", failures);
    sync();
    reboot(RB_POWER_OFF);
    return failures ? 102 : 0;
}
