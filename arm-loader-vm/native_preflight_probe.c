/* Freestanding ARM Linux guest probe exercising dlsym-resolved router callbacks.
 * Invokes zero Sony application APIs.
 */
typedef unsigned int u32;
extern void *dlsym(void *, const char *);
extern long syscall(long, ...);

static u32 result[20];

static void emit(void) {
    static const char hex[] = "0123456789abcdef";
    char line[256];
    unsigned p = 0;
    const char *s = "CXVM_NATIVE_WORDS ";
    while (*s) {
        line[p++] = *s++;
    }
    for (unsigned i = 0; i < 20; i++) {
        for (int b = 7; b >= 0; b--) {
            line[p++] = hex[(result[i] >> (4 * b)) & 15];
        }
        line[p++] = ' ';
    }
    line[p++] = '\n';
    syscall(4L, 1L, line, (long)p);
}

__attribute__((noreturn)) static void finish(int code) {
    emit();
    syscall(1L, (long)code);
    __builtin_unreachable();
}

__attribute__((noreturn)) void _start(void) {
    for (unsigned i = 0; i < 20; i++) {
        result[i] = 0xccccccccu;
    }
    result[0] = 0x32564d43u;

#ifndef READ_ONLY
    int (*prepare)(void) = dlsym((void *)0, "cx_menu_router_prepare");
    unsigned (*state)(void) = dlsym((void *)0, "cx_menu_router_state");
    unsigned (*error)(void) = dlsym((void *)0, "cx_menu_router_error");
    if (!prepare || !state || !error) {
        finish(61);
    }
    result[1] = (u32)prepare();
    result[2] = state();
    result[3] = error();
#ifdef EXPECT_STOCK
    if (result[1] != 1 || result[2] != 1 || result[3] != 3) {
        finish(70);
    }
    result[19] = 0;
    finish(0);
#endif
    if (result[1] != 0 || result[2] != 2 || result[3] != 0) {
        finish(62);
    }
#else
    result[1] = result[2] = result[3] = 0;
#endif

    int (*read_profile)(int *) = dlsym((void *)0, "cx_profile_read");
    int (*menu_set)(void *, int) = dlsym((void *)0, "cx_menu_set");
    int (*menu_get)(void *, int *, void *) = dlsym((void *)0, "cx_menu_get");
    if (!read_profile || !menu_set || !menu_get) {
        finish(63);
    }

    int value = 0x12345678;
    result[4] = (u32)read_profile(&value);
    result[5] = (u32)value;

#ifndef READ_ONLY
    if (result[4] != 1 || value != 0x12345678) {
        finish(64);
    }
    int values[3] = {0, 4, 5};
    for (unsigned i = 0; i < 3; i++) {
        result[6 + i * 3] = (u32)menu_set((void *)0, values[i]);
        value = -99;
        result[7 + i * 3] = (u32)menu_get((void *)0, &value, (void *)0);
        result[8 + i * 3] = (u32)value;
        if (result[6 + i * 3] != 1 || result[7 + i * 3] != 1 || value != values[i]) {
            finish(65 + (int)i);
        }
    }
#else
    if (result[4] != 0 || value != 5) {
        finish(68);
    }
    value = -99;
    result[6] = (u32)menu_get((void *)0, &value, (void *)0);
    result[7] = (u32)value;
    if (result[6] != 1 || value != 5) {
        finish(69);
    }
#endif

    result[19] = 0;
    finish(0);
}
