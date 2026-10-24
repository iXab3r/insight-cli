/* MIT; first-party read-only process proof. Never prints argv or environment values. */
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/proc_info.h>
#include <sys/proc.h>
#include <CommonCrypto/CommonDigest.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
static void json(const char *s) {
 putchar('"'); for(const unsigned char *p=(const unsigned char *)s;*p;p++) {
  if(*p=='"'||*p=='\\')printf("\\%c",*p); else if(*p<32)printf("\\u%04x",*p);else putchar(*p);
 } putchar('"');
}
int main(int argc,char **argv) {
 if(argc==2&&!strcmp(argv[1],"--version")){puts("insight-process-identity 1");return 0;}
 char *end=NULL;errno=0;long value=argc==2?strtol(argv[1],&end,10):0;
 if(errno||!end||*end||value<1||value>2147483647)return 64;
 int pid=(int)value;struct proc_bsdinfo before,after;char executable[PROC_PIDPATHINFO_MAXSIZE];
 if(proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&before,sizeof before)!=sizeof before||before.pbi_uid!=geteuid()||before.pbi_status==SZOMB)return 11;
 memset(executable,0,sizeof executable);int has_path=proc_pidpath(pid,executable,sizeof executable)>0;
 char owned_root[PROC_PIDPATHINFO_MAXSIZE]={0};
 int mib[3]={CTL_KERN,KERN_PROCARGS2,pid};size_t size=0;
 if(sysctl(mib,3,NULL,&size,NULL,0)||size<sizeof(int)||size>2*1024*1024)return 13;
 char *data=calloc(size+1,1);if(!data)return 70;
 if(sysctl(mib,3,data,&size,NULL,0)){free(data);return 14;}
 int nargs;memcpy(&nargs,data,sizeof nargs);if(nargs<1||nargs>65536){free(data);return 1;}
 char *p=data+sizeof(int),*limit=data+size;size_t executable_length=strnlen(p,(size_t)(limit-p));
 if(executable_length>=sizeof executable||p+executable_length>=limit){free(data);return 1;}
 if(!has_path)memcpy(executable,p,executable_length+1);
 while(p<limit&&*p)p++;while(p<limit&&!*p)p++;
 for(int i=0;i<nargs&&p<limit;i++){while(p<limit&&*p)p++;if(p<limit)p++;}
 unsigned char digest[CC_SHA256_DIGEST_LENGTH];int found=0;const char key[]="GHIDRA_MCP_AUTH_TOKEN=";
 while(p<limit&&!*p)p++;
 while(p<limit&&*p){size_t n=strnlen(p,(size_t)(limit-p));
  if(n>sizeof(key)-1&&!memcmp(p,key,sizeof(key)-1)){if(found){free(data);return 1;}CC_SHA256(p+sizeof(key)-1,(CC_LONG)(n-sizeof(key)+1),digest);found=1;}
  const char root_key[]="GHIDRA_MCP_FILE_ROOT=";
  if(n>sizeof(root_key)-1&&!memcmp(p,root_key,sizeof(root_key)-1)){size_t length=n-sizeof(root_key)+1;if(owned_root[0]||length>=sizeof owned_root){free(data);return 1;}memcpy(owned_root,p+sizeof(root_key)-1,length);}
  p+=n+1;
 }
 memset(data,0,size);free(data);
 if(!found||!owned_root[0]||proc_pidinfo(pid,PROC_PIDTBSDINFO,0,&after,sizeof after)!=sizeof after||before.pbi_start_tvsec!=after.pbi_start_tvsec||before.pbi_start_tvusec!=after.pbi_start_tvusec||before.pbi_uid!=after.pbi_uid)return 15;
 printf("{\"pid\":%d,\"uid\":%u,\"birthSeconds\":%llu,\"birthMicroseconds\":%llu,\"executable\":",pid,before.pbi_uid,before.pbi_start_tvsec,before.pbi_start_tvusec);json(executable);
 printf(",\"root\":");json(owned_root);printf(",\"tokenSha256\":\"");for(size_t i=0;i<sizeof digest;i++)printf("%02x",digest[i]);puts("\"}");return 0;
}
