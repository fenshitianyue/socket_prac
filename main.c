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
  printf("[%s]",__DATE__);
  printf("[%s]  ",__TIME__ );
}


int main() {
  
  return 0;
}
