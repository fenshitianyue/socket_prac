#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>

#include "sniffer.h"
#include "tools.h"

int exec_cmd(char* buf, int len){
  if(strncmp(buf, "quit", 4) == 0){
    return 1;
  }
  return 0;
}

int command_interpreter(int sd) {//命令解释器
  int len;
  char buf[512];
  len = read(0, buf, 512);
  if(len > 0){
    if(exec_cmd(buf, len) == 1){
      return 1;
    }
  }
  return 0;
}


void display_time_and_date(){
  INITCOLOR(READ_COLOR);
  printf("[%s]",__DATE__);
  INITCOLOR(GREEN_COLOR);
  printf("[%s]  ",__TIME__ );
  INITCOLOR(ZERO_COLOR);
}

void getting_started(){
  CLEARSCREEN();
  display_time_and_date();
  printf("Getting started of Network sniffer\n\n");
}

int main() {
  int sd;
  int res;
  int saddr_size;
  int date_size;
  struct sockaddr* saddr;
  unsigned char* buffer;
  t_sniffer sniffer;
  fd_set fd_read;
  buffer = (unsigned char*)malloc(sizeof(unsigned char*) * 65536);
  sniffer.logfile = fopen("log.txt", "w");
  if(NULL == sniffer.logfile){
    perror("fopen():");
    return EXIT_FAILURE;
  }
  return 0;
}
