/* MIT; first-party internal exec helper. A kernel alarm survives exec and owner loss. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        puts("insight-deadline-exec 1"); return 0;
    }
    if (argc < 4 || strcmp(argv[2], "--") != 0 || argv[3][0] != '/') return 64;
    char *end = NULL;
    errno = 0;
    long seconds = strtol(argv[1], &end, 10);
    if (errno || !end || *end || seconds < 1 || seconds > 600) return 64;
    sigset_t signals;
    if (sigemptyset(&signals) || sigaddset(&signals, SIGALRM) ||
        sigprocmask(SIG_UNBLOCK, &signals, NULL) || signal(SIGALRM, SIG_DFL) == SIG_ERR) return 70;
    alarm((unsigned int)seconds);
    execv(argv[3], &argv[3]);
    perror("Owned deadline executable could not start");
    return 127;
}
