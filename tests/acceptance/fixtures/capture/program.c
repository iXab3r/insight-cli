// MIT disposable native subject; no external service, filesystem fixture or borrowed process.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(int argc,char **argv){
 const char *mode=argc>1?argv[1]:"normal";
 if(!strcmp(mode,"stdin")){unsigned char bytes[1024];size_t n=fread(bytes,1,sizeof(bytes),stdin);fwrite(bytes,1,n,stdout);return 0;}
 if(!strcmp(mode,"binary")){const unsigned char bytes[]={0,255,65,10};fwrite(bytes,1,sizeof(bytes),stdout);fputs("owned stderr\n",stderr);return 17;}
 if(!strcmp(mode,"flood")){for(int n=0;n<6000000;n++)putchar('x');return 0;}
 if(!strcmp(mode,"wait")){
  fputs("WAITING37\n",stdout);fflush(stdout);FILE *progress=fopen("progress.txt","wb");fputs("Retained37\n",progress);fclose(progress);
  if(argc>2){int server=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in address={0};address.sin_len=sizeof(address);address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons((unsigned short)atoi(argv[2]));if(bind(server,(struct sockaddr*)&address,sizeof(address))||listen(server,1))return 18;int client=accept(server,0,0);write(client,"READY37",7);close(client);close(server);}
  for(;;)usleep(100000);
 }
 FILE *input=fopen("settings.txt","rb");if(!input)return 19;int rate=0;if(fscanf(input,"%d",&rate)!=1)return 20;fclose(input);
 int total=rate*11+10;printf("quote=%d\n",total);fputs("owned observation\n",stderr);FILE *result=fopen("result.txt","wb");fprintf(result,"%d\n",total);fclose(result);
 if(!strcmp(mode,"mutate")){input=fopen("settings.txt","wb");fputs("13\n",input);fclose(input);}
 return 0;
}
