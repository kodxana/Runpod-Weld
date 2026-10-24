/* Linux opt-in fixture; see trace_threads.py for build/run instructions. */
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
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static atomic_int ready, stop;
static const char *self;

static void check(int ok, const char *what)
{
    if (!ok) {
        fprintf(stderr, "FAIL: %s (errno=%d)\n", what, errno);
        _exit(1);
    }
}

static void thread_check(int result, const char *what)
{
    errno = result;
    check(result == 0, what);
}

static void paths(void)
{
    struct stat st;
    check(stat("/dev/null", &st) == 0 && S_ISCHR(st.st_mode), "stat null");
    check(stat("/proc/thread-self/status", &st) == 0 && S_ISREG(st.st_mode), "stat thread status");
    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    check(fd >= 0, "open null");
    check(fstat(fd, &st) == 0 && S_ISCHR(st.st_mode), "null is character device");
    char buf[4096];
    check(write(fd, "x", 1) == 1 && read(fd, buf, 1) == 0, "null I/O");
    check(close(fd) == 0, "close null");
    fd = open("/proc/thread-self/status", O_RDONLY | O_CLOEXEC);
    check(fd >= 0, "open thread status");
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    check(n > 0, "read thread status");
    buf[n] = '\0';
    char *pid = strstr(buf, "\nPid:\t");
    char *tgid = strstr(buf, "\nTgid:\t");
    check(pid && tgid && strtol(pid + 6, NULL, 10) == syscall(SYS_gettid)
          && strtol(tgid + 7, NULL, 10) == getpid(), "proc identifies calling thread");
    check(close(fd) == 0, "close proc");
}

static void *io_worker(void *arg)
{
    atomic_fetch_add(&ready, 1);
    while (atomic_load(&ready) < 4) sched_yield();
    for (int i = 0; i < 40; ++i) paths();
    return arg;
}

static void *live_worker(void *arg)
{
    (void)arg;
    paths();
    atomic_store(&ready, 1);
    while (!atomic_load(&stop)) usleep(1000);
    return NULL;
}

static void *exec_worker(void *arg)
{
    (void)arg;
    check(syscall(SYS_gettid) != getpid(), "exec caller is nonleader");
    paths();
    execl(self, self, "after-exec", (char *)NULL);
    check(0, "nonleader exec");
    return NULL;
}

static void *exit_worker(void *arg)
{
    (void)arg;
    paths();
    puts("READY exit-group");
    syscall(SYS_exit_group, 37);
    _exit(1);
}

static pthread_barrier_t transition_barrier;
static atomic_int path_rounds[2], verified;
static int transition_pipe[2], change_ids;

static void barrier(void)
{
    int result = pthread_barrier_wait(&transition_barrier);
    check(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "transition barrier");
}

static void verify_ids(void)
{
    if (change_ids) {
        uid_t ruid, euid, suid;
        gid_t rgid, egid, sgid;
        /* Raw reads prove each kernel task changed, not just libc's caller. */
        check(syscall(SYS_getresuid, &ruid, &euid, &suid) == 0
              && ruid == 65534 && euid == 65534 && suid == 65534, "thread uid transition");
        check(syscall(SYS_getresgid, &rgid, &egid, &sgid) == 0
              && rgid == 65534 && egid == 65534 && sgid == 65534, "thread gid transition");
    }
    paths();
    atomic_fetch_add(&verified, 1);
}

static void *transition_worker(void *arg)
{
    int slot = *(int *)arg;
    barrier();
    if (slot == 2) {
        char byte;
        ssize_t n;
        do { n = read(transition_pipe[0], &byte, 1); } while (n < 0 && errno == EINTR);
        check(n == 1 && byte == 'x', "blocked sibling released");
    } else {
        while (!atomic_load(&stop)) {
            paths();
            atomic_fetch_add(&path_rounds[slot], 1);
        }
    }
    barrier();
    verify_ids();
    return NULL;
}

static void wait_path_progress(void)
{
    int before[2];
    for (int i = 0; i < 2; ++i) before[i] = atomic_load(&path_rounds[i]);
    for (int i = 0; i < 2; ++i)
        while (atomic_load(&path_rounds[i]) <= before[i]) sched_yield();
}

static void transitions(int credentials)
{
    change_ids = credentials;
    if (credentials && geteuid() != 0) {
        fputs("PREREQUISITE credentials: root required\n", stderr);
        _exit(77);
    }
    check(pipe(transition_pipe) == 0, "transition pipe");
    thread_check(pthread_barrier_init(&transition_barrier, NULL, 4), "init transition barrier");
    pthread_t threads[3];
    int slots[3] = {0, 1, 2};
    for (int i = 0; i < 3; ++i)
        thread_check(pthread_create(&threads[i], NULL, transition_worker, &slots[i]), "create transition worker");
    barrier();
    wait_path_progress();
    if (credentials) {
        /* Use real libc wrappers: glibc signals and waits for every sibling. */
        check(setresgid(65534, 65534, 65534) == 0, "libc setresgid");
        wait_path_progress();
        check(setresuid(65534, 65534, 65534) == 0, "libc setresuid");
        wait_path_progress();
    } else {
        for (int i = 0; i < 80; ++i) {
            check(prctl(PR_SET_DUMPABLE, 0) == 0, "disable dumpability");
            wait_path_progress();
        }
    }
    atomic_store(&stop, 1);
    check(write(transition_pipe[1], "x", 1) == 1, "release blocked sibling");
    barrier();
    verify_ids();
    for (int i = 0; i < 3; ++i)
        thread_check(pthread_join(threads[i], NULL), "join transition worker");
    check(atomic_load(&verified) == 4, "all transition tasks verified");
    check(close(transition_pipe[0]) == 0 && close(transition_pipe[1]) == 0, "close transition pipe");
    thread_check(pthread_barrier_destroy(&transition_barrier), "destroy transition barrier");
    puts(credentials ? "VERIFIED credentials threads=4 uid=65534 gid=65534"
                     : "VERIFIED dumpable threads=4 rounds=80");
    puts(credentials ? "PASS credentials" : "PASS dumpable");
}

int main(int argc, char **argv)
{
    alarm(30);
    setbuf(stdout, NULL);
    check(argc == 2, "one case required");
    self = argv[0];
    if (!strcmp(argv[1], "dumpable") || !strcmp(argv[1], "credentials")) {
        transitions(!strcmp(argv[1], "credentials"));
    } else if (!strcmp(argv[1], "io")) {
        pthread_t threads[4];
        int tokens[4] = {0, 1, 2, 3};
        for (int i = 0; i < 4; ++i)
            thread_check(pthread_create(&threads[i], NULL, io_worker, &tokens[i]), "create io");
        for (int i = 0; i < 4; ++i) {
            void *result = NULL;
            thread_check(pthread_join(threads[i], &result), "join io");
            check(result == &tokens[i], "join return value");
        }
        puts("PASS io");
    } else if (!strcmp(argv[1], "fork") || !strcmp(argv[1], "cancel")) {
        pthread_t thread;
        thread_check(pthread_create(&thread, NULL, live_worker, NULL), "create live");
        while (!atomic_load(&ready)) sched_yield();
        int pipefd[2];
        check(pipe(pipefd) == 0, "pipe");
        int cancel = !strcmp(argv[1], "cancel");
        pid_t child = fork();
        check(child >= 0, "fork multithreaded parent");
        if (child == 0) {
            /* Only async-signal-safe operations after multithreaded fork. */
            alarm(30);
            close(pipefd[0]);
            if (cancel) {
                pid_t grandchild = fork();
                if (grandchild < 0) _exit(2);
                if (grandchild == 0) {
                    alarm(30);
                    close(pipefd[1]);
                    for (;;) pause();
                }
                if (write(pipefd[1], &grandchild, sizeof(grandchild)) != sizeof(grandchild)) _exit(3);
                close(pipefd[1]);
                for (;;) pause();
            }
            close(pipefd[1]);
            execl(self, self, "after-fork", (char *)NULL);
            _exit(4);
        }
        close(pipefd[1]);
        if (cancel) {
            pid_t grandchild;
            check(read(pipefd[0], &grandchild, sizeof(grandchild)) == sizeof(grandchild), "grandchild ready");
            close(pipefd[0]);
            printf("READY cancel %ld %ld %ld\n", (long)getpid(), (long)child, (long)grandchild);
            for (;;) pause();
        }
        close(pipefd[0]);
        int status;
        check(waitpid(child, &status, 0) == child && WIFEXITED(status)
              && WEXITSTATUS(status) == 0, "fork child status");
        paths();
        atomic_store(&stop, 1);
        thread_check(pthread_join(thread, NULL), "join live");
        puts("PASS fork");
    } else if (!strcmp(argv[1], "exec") || !strcmp(argv[1], "exit-group")) {
        pthread_t thread;
        thread_check(pthread_create(&thread, NULL,
                     !strcmp(argv[1], "exec") ? exec_worker : exit_worker, NULL), "create terminal worker");
        for (;;) pause();
    } else if (!strcmp(argv[1], "after-exec")) {
        check(syscall(SYS_gettid) == getpid(), "exec became leader");
        paths();
        puts("PASS exec");
    } else if (!strcmp(argv[1], "after-fork")) {
        paths();
        puts("PASS fork-child");
    } else {
        check(0, "unknown case");
    }
    return 0;
}
