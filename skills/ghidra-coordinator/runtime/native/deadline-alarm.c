/* MIT; first-party constructor for owned Frida helper execs, never injected into the target. */
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
__attribute__((constructor)) static void arm_owned_deadline(void) {
    const char *raw = getenv("INSIGHT_NATIVE_DEADLINE_UNIX_SECONDS");
    const char *directory = getenv("INSIGHT_NATIVE_DEADLINE_RECEIPTS");
    if (!raw || !directory || directory[0] != '/') _exit(70);
    errno = 0; char *end = NULL;
    long long deadline = strtoll(raw, &end, 10), now = (long long)time(NULL);
    if (errno || !end || *end || deadline <= now || deadline - now > 600) _exit(70);
    sigset_t signals;
    if (sigemptyset(&signals) || sigaddset(&signals, SIGALRM) ||
        sigprocmask(SIG_UNBLOCK, &signals, NULL) || signal(SIGALRM, SIG_DFL) == SIG_ERR) _exit(70);
    alarm((unsigned int)(deadline - now));
    struct proc_bsdinfo info;
    if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != sizeof(info)) _exit(70);
    char path[4096], body[512];
    int length = snprintf(path, sizeof(path), "%s/%d.json", directory, getpid());
    if (length < 0 || length >= (int)sizeof(path)) _exit(70);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) _exit(70);
    length = snprintf(body, sizeof(body), "{\"protocol\":1,\"pid\":%d,\"parentPid\":%d,\"birthSeconds\":%llu,\"birthMicroseconds\":%llu,\"deadlineUnixSeconds\":%lld}\n",
        getpid(), getppid(), info.pbi_start_tvsec, info.pbi_start_tvusec, deadline);
    if (length < 0 || length >= (int)sizeof(body) || write(fd, body, (size_t)length) != length || fsync(fd)) _exit(70);
    close(fd);
}
