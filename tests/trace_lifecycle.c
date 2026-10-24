/* Standalone Linux x86_64 regression fixture; gcc -O2 -Wall -Wextra -Werror
 * -static tests/trace_lifecycle.c -o /tmp/weld-trace-lifecycle
 * Copy into ROOTFS/tmp and run trace_root ROOTFS STATE 30
 * '/tmp/weld-trace-lifecycle'. No engine build dependency. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t seen;

static void check(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "FAIL: %s (errno=%d: %s)\n", what, errno, strerror(errno));
        exit(1);
    }
}

static void handler(int sig)
{
    (void)sig;
    /* Leave syscall argument registers different from the interrupted context. */
    (void)syscall(SYS_getpid, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76);
    seen = 1;
}

static void delay(void)
{
    struct timespec t = { .tv_nsec = 100000000 };
    while (nanosleep(&t, &t) < 0)
        check(errno == EINTR, "nanosleep");
}

static void reap(pid_t pid)
{
    int status;
    pid_t result;
    do { result = waitpid(pid, &status, 0); } while (result < 0 && errno == EINTR);
    check(result == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "signal helper exit");
}

static void userspace_signal(void)
{
    pid_t parent = getpid();
    seen = 0;
    pid_t child = fork();
    check(child >= 0, "fork userspace signal helper");
    if (child == 0) {
        delay();
        _exit(kill(parent, SIGUSR1) == 0 ? 0 : 1);
    }
    unsigned long a = 0x11, b = 0x22, c = 0x33;
    register unsigned long d __asm__("r10") = 0x44;
    register unsigned long e __asm__("r8") = 0x55;
    register unsigned long f __asm__("r9") = 0x66;
    /* No syscall in this loop: rt_sigreturn must restore these user registers. */
    __asm__ volatile("1: cmpl $0, %[seen]\n\tje 1b"
                     : "+D"(a), "+S"(b), "+d"(c), "+r"(d), "+r"(e), "+r"(f)
                     : [seen] "m"(seen) : "cc", "memory");
    check(a == 0x11 && b == 0x22 && c == 0x33 && d == 0x44 && e == 0x55 && f == 0x66,
          "rt_sigreturn userspace registers");
    check(seen == 1, "userspace signal delivered");
    reap(child);
}

static void restarted_read(void)
{
    int pipefd[2];
    check(pipe(pipefd) == 0, "pipe");
    pid_t parent = getpid();
    seen = 0;
    pid_t child = fork();
    check(child >= 0, "fork read signal helper");
    if (child == 0) {
        close(pipefd[0]);
        delay();
        if (kill(parent, SIGUSR1) != 0) _exit(1);
        delay();
        _exit(write(pipefd[1], "R", 1) == 1 ? 0 : 1);
    }
    check(close(pipefd[1]) == 0, "close pipe writer");
    char byte = 0;
    check(read(pipefd[0], &byte, 1) == 1 && byte == 'R' && seen == 1,
          "SA_RESTART blocking read and restored arguments");
    check(close(pipefd[0]) == 0, "close pipe reader");
    reap(child);
}

static void paths(void)
{
    int fd = open("/dev/null", O_WRONLY);
    check(fd >= 0, "open /dev/null");
    check(write(fd, "x", 1) == 1, "write /dev/null");
    check(close(fd) == 0, "close /dev/null");
    fd = open("/proc/self/status", O_RDONLY);
    check(fd >= 0, "open /proc/self/status");
    char buf[64];
    check(read(fd, buf, sizeof(buf)) > 0, "read /proc/self/status");
    check(close(fd) == 0, "close /proc/self/status");
}

static void vfork_dumpability(void)
{
    pid_t child = vfork();
    if (child == 0) {
        /* No next syscall after PR_SET_DUMPABLE: die with the shared mm stale.
         * Inline assembly avoids function calls or writes to the parent's stack. */
        __asm__ volatile("syscall\n\ttest %%rax, %%rax\n\tjz 1f\n\tint3\n1:\tud2"
                         : : "a"((long)SYS_prctl), "D"((long)PR_SET_DUMPABLE),
                             "S"(0L), "d"(0L) : "rcx", "r11", "cc", "memory");
        __builtin_unreachable();
    }
    check(child > 0, "vfork");
    int status;
    check(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGILL,
          "vfork child died with SIGILL");
    paths();
}

static void pinned_ioctl(int mutate)
{
    int found = 0;
    for (int fd = 64; fd <= 128; ++fd) {
        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        ++found;
        if (mutate) {
            check(ioctl(fd, FIONCLEX) == 0, "pinned FIONCLEX allowed");
            check(fcntl(fd, F_GETFD) == 0, "pinned flags cleared");
            check(ioctl(fd, FIOCLEX) == 0, "pinned FIOCLEX spoofed success");
        }
        check(fcntl(fd, F_GETFD) == 0, "pinned descriptor remains inheritable");
    }
    check(found >= 2, "found both pinned directory descriptors in fd64..128");
}

int main(int argc, char **argv)
{
    alarm(20); /* Every loop/wait, including the post-exec phase, is bounded. */
    struct rlimit core = {0, 0};
    check(setrlimit(RLIMIT_CORE, &core) == 0, "disable core dumps");
    if (argc == 2 && strcmp(argv[1], "--after-exec") == 0) {
        pinned_ioctl(0);
        paths();
        puts("PASS: signal return, restartable read, vfork dumpability, pinned ioctl/exec");
        return 0;
    }
    check(argc == 1, "fixture arguments");
    struct sigaction action = {0};
    action.sa_handler = handler;
    action.sa_flags = SA_RESTART;
    check(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGUSR1, &action, NULL) == 0,
          "install signal handler");
    userspace_signal();
    restarted_read();
    vfork_dumpability();
    pinned_ioctl(1);
    execl("/tmp/weld-trace-lifecycle", "weld-trace-lifecycle", "--after-exec", (char *)NULL);
    check(0, "exec lifecycle fixture");
    return 1;
}
