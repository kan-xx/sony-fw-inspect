/* Self-authored idle executable named im.elf used solely inside the isolated
 * QEMU ARM guest harness to trigger LD_PRELOAD canary tests.
 * Contains zero Sony code or APIs.
 */
extern long syscall(long, ...);
__attribute__((noreturn)) void _start(void) {
    syscall(1L, 0L);
    __builtin_unreachable();
}
