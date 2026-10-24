/* Linux x86_64; build/run instructions in trace_sharing.py. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error Linux x86_64 required
#endif
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "shared counters must not use libc locks");

/* No errno/TLS access in a CLONE_VM child (including on syscall failure). */
static long raw(long n, long a, long b, long c)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return result;
}

static void check(int ok, const char *message)
{
    if (!ok) {
        fprintf(stderr, "FAIL %s errno=%d\n", message, errno);
        _exit(1);
    }
}

static int raw_paths(void)
{
    char byte;
    long fd = raw(SYS_open, (long)"/dev/null", O_RDWR | O_CLOEXEC, 0);
    if (fd < 0) return 1;
    if (raw(SYS_write, fd, (long)"x", 1) != 1 || raw(SYS_read, fd, (long)&byte, 1) != 0)
        return 2;
    if (raw(SYS_close, fd, 0, 0)) return 3;
    fd = raw(SYS_open, (long)"/proc/self/status", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return 4;
    if (raw(SYS_read, fd, (long)&byte, 1) != 1 || byte != 'N') return 5;
    return raw(SYS_close, fd, 0, 0) ? 6 : 0;
}

static atomic_int phase;
static int probe_fd;
static int private_value;

static int clone_child(void *unused)
{
    (void)unused;
    for (int i = 0; i < 32; ++i) {
        if (raw(SYS_prctl, PR_SET_DUMPABLE, 0, 0) || raw_paths()
            || raw(SYS_prctl, PR_SET_DUMPABLE, 1, 0)) return 10;
    }
    private_value = 73;
    if (raw(SYS_close, probe_fd, 0, 0)) return 11;
    if (atomic_load(&phase) != 2) {
        atomic_store(&phase, 1);
        while (atomic_load(&phase) != 2) raw(SYS_sched_yield, 0, 0, 0);
    }
    return raw_paths() ? 12 : 0;
}

static void sharing(int vm)
{
    /* clone() supplies a separate stack; child uses only inline syscalls and atomics. */
    size_t size = 1024 * 1024;
    void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(stack != MAP_FAILED, "clone stack");
    probe_fd = open("/dev/null", O_RDWR);
    check(probe_fd >= 0, "probe fd");
    pid_t child = clone(clone_child, (char *)stack + size, (vm ? CLONE_VM : CLONE_FILES) | SIGCHLD, NULL);
    check(child > 0, "clone");
    if (vm) {
        while (!atomic_load(&phase)) {
            check(raw_paths() == 0, "parent paths during shared-mm transitions");
            sched_yield();
        }
        check(private_value == 73, "CLONE_VM memory shared");
        check(fcntl(probe_fd, F_GETFD) >= 0, "CLONE_VM file table separate");
        atomic_store(&phase, 2);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "clone child exit");
    check(raw_paths() == 0, "parent paths after clone exit");
    if (vm) check(close(probe_fd) == 0, "parent close separate fd");
    else {
        check(private_value == 0, "CLONE_FILES memory separate");
        errno = 0;
        check(fcntl(probe_fd, F_GETFD) == -1 && errno == EBADF, "CLONE_FILES close shared");
    }
    check(munmap(stack, size) == 0, "unmap clone stack");
    puts(vm ? "PASS clone-vm" : "PASS clone-files");
}

static _Noreturn void vfork_child(void)
{
    int code = raw(SYS_prctl, PR_SET_DUMPABLE, 0, 0) ? 20 : raw_paths();
    raw(SYS_exit, code, 0, 0);
    __builtin_unreachable();
}

static void vfork_case(void)
{
    size_t size = 1024 * 1024;
    void *stack = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(stack != MAP_FAILED, "vfork stack");
    long child;
    /* Real SYS_vfork, but switch the child to a dedicated aligned stack before
       entering C. Neither compiler spills nor calls can corrupt the parent's stack. */
    __asm__ volatile("syscall\n\ttest %%rax, %%rax\n\tjnz 1f\n\t"
                     "mov %%rdi, %%rsp\n\tcall *%%rsi\n\tud2\n1:"
                     : "=a"(child)
                     : "a"(SYS_vfork), "D"((char *)stack + size), "S"(vfork_child)
                     : "rcx", "r11", "memory", "cc");
    check(child > 0, "vfork");
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "vfork child exit after dumpability change");
    check(raw_paths() == 0, "parent paths after vfork resumes");
    check(prctl(PR_SET_DUMPABLE, 1) == 0, "restore parent dumpability");
    check(munmap(stack, size) == 0, "unmap vfork stack");
    puts("PASS vfork");
}

static atomic_int rounds[2];
static const char *self;
static int exiting;

static void *churn(void *arg)
{
    int slot = *(int *)arg;
    for (;;) {
        check(prctl(PR_SET_DUMPABLE, 0) == 0, "sibling disable dumpability");
        check(raw_paths() == 0, "sibling paths");
        check(prctl(PR_SET_DUMPABLE, 1) == 0, "sibling enable dumpability");
        atomic_fetch_add(&rounds[slot], 1);
    }
    return NULL;
}

static void *terminal(void *unused)
{
    (void)unused;
    check(syscall(SYS_gettid) != getpid(), "terminal caller nonleader");
    while (atomic_load(&rounds[0]) < 32 || atomic_load(&rounds[1]) < 32) sched_yield();
    puts("VERIFIED siblings=2 rounds>=32");
    if (exiting) {
        puts("READY exit-churn");
        syscall(SYS_exit_group, 37);
    } else execl(self, self, "after-exec", (char *)NULL);
    check(0, "terminal syscall returned");
    return NULL;
}

int main(int argc, char **argv)
{
    alarm(25);
    setbuf(stdout, NULL);
    check(argc == 2, "one case argument");
    self = argv[0];
    if (!strcmp(argv[1], "clone-vm")) sharing(1);
    else if (!strcmp(argv[1], "clone-files")) {
        /* Private-mm child does not handshake: its own phase starts released. */
        atomic_store(&phase, 2);
        sharing(0);
    } else if (!strcmp(argv[1], "vfork")) vfork_case();
    else if (!strcmp(argv[1], "exec-churn") || !strcmp(argv[1], "exit-churn")) {
        exiting = !strcmp(argv[1], "exit-churn");
        pthread_t threads[3];
        int slots[2] = {0, 1};
        for (int i = 0; i < 2; ++i)
            check(pthread_create(&threads[i], NULL, churn, &slots[i]) == 0, "create churn");
        check(pthread_create(&threads[2], NULL, terminal, NULL) == 0, "create terminal");
        for (;;) pause();
    } else if (!strcmp(argv[1], "after-exec")) {
        check(syscall(SYS_gettid) == getpid(), "exec became leader");
        check(raw_paths() == 0, "paths after exec");
        puts("PASS exec-churn");
    } else check(0, "unknown case");
    return 0;
}
