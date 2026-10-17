/* MIT; first-party owned Linux launcher. PDEATHSIG also bounds tools that replace SIGALRM. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
static long integer(const char *s,long maximum){char *end=NULL;errno=0;long v=strtol(s,&end,10);return errno||!end||*end||v<1||v>maximum?-1:v;}
int main(int argc,char **argv){
 if(argc<4||argv[3][0]!='/')return 64;
 long seconds=integer(argv[1],600),owner=integer(argv[2],2147483647);if(seconds<0||owner<0)return 64;
 if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=(pid_t)owner)return 70;
 sigset_t signals;sigemptyset(&signals);sigaddset(&signals,SIGALRM);sigaddset(&signals,SIGTERM);sigaddset(&signals,SIGINT);
 if(sigprocmask(SIG_UNBLOCK,&signals,NULL)||signal(SIGALRM,SIG_DFL)==SIG_ERR)return 70;
 alarm((unsigned)seconds);pid_t parent=getpid(),child=fork();if(child<0)return 70;
 if(!child){if(prctl(PR_SET_PDEATHSIG,SIGKILL)||getppid()!=parent)_exit(70);alarm(0);execv(argv[3],argv+3);perror("Owned native executable could not start");_exit(127);}
 int status;while(waitpid(child,&status,0)<0){if(errno!=EINTR)return 70;}
 if(WIFEXITED(status))return WEXITSTATUS(status);
 if(WIFSIGNALED(status)){int sig=WTERMSIG(status);signal(sig,SIG_DFL);kill(getpid(),sig);return 128+sig;}
 return 70;
}
