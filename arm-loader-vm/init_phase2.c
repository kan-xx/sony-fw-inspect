#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

/* Phase 2 isolated guest PID 1: verifies ARM O_NOFOLLOW (0x8000) symlink rejection
 * and pending-profile state isolation in guest RAM.
 */
static int run_child(const char *name, const char *exe, const char *so) {
    printf("CXVM_PHASE2_BEGIN %s\n", name);
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
        char env[256];
        snprintf(env, sizeof(env), "LD_PRELOAD=%s", so);
        char *argv[] = {(char *)exe, NULL};
        char *envp[] = {env, "LD_LIBRARY_PATH=/lib", NULL};
        execve(exe, argv, envp);
        _exit(127);
    }
    int status = 0;
    if (p < 0 || waitpid(p, &status, 0) != p) {
        return 1;
    }
    int sig = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("CXVM_PHASE2_RESULT %s rc=%d signal=%d\n", name, rc, sig);
    return sig != 0 || rc != 0;
}

int main(void) {
    int c = open("/dev/console", O_RDWR);
    if (c >= 0) {
        dup2(c, 0);
        dup2(c, 1);
        dup2(c, 2);
        if (c > 2) {
            close(c);
        }
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    struct rlimit lim = {0, 0};
    setrlimit(RLIMIT_CORE, &lim);
    if (mount("proc", "/proc", "proc", 0, NULL)) {
        return 101;
    }
    struct utsname u;
    uname(&u);
    printf("CXVM_PHASE2_BOOT kernel=%s machine=%s\n", u.release, u.machine);

    int failed = run_child("router-prepare-and-profile", "/probe/native-preflight.elf", "/probe/coherent-router.so");
    unsigned char b[17];
    int n = -1;
    int f = open("/setting/custom_sound_test/profile", O_RDONLY);
    if (f >= 0) {
        n = (int)read(f, b, sizeof(b));
        close(f);
    }
    printf("CXVM_PHASE2_PROFILE bytes=%d hex=", n);
    for (int i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    puts("");
    if (n != 16) {
        failed++;
    }

    failed += run_child(
        "new-process-read-only",
        "/probe/native-profile-read.elf",
        "/setting/custom_sound_test/native-menu/pending-profile.so"
    );

    const char *caution = "/lens/custom_sound_test/native-menu/CautionConfig.so";
    if (rename(caution, "/probe/Caution-moved.so") || symlink("/probe/Caution-moved.so", caution)) {
        failed++;
    } else {
        failed += run_child("ARM-NOFOLLOW-symlink-rejected", "/probe/native-expect-stock.elf", "/probe/coherent-router.so");
    }

    printf("CXVM_PHASE2_COMPLETE failures=%d Sony_config_ELFs_mapped=0\n", failed);
    sync();
    reboot(RB_POWER_OFF);
    return failed ? 102 : 0;
}
