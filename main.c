#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
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

void ProcessPacket(unsigned char* buffer, int size, t_sniffer* sniffer){
  buffer = buffer + 6 + 6 + 2;
  struct iphdr* iph = (struct iphdr*)buffer;
  ++sniffer->prot->total; //数据包+1
  switch(iph->protocol){
    case 1:
      ++sniffer->prot->icmp;
      print_icmp_packet(buffer, size, sniffer);
      break;
    case 2:
      ++sniffer->prot->igmp;
      break;
    case 6:
      ++sniffer->prot->tcp;
      print_tcp_packet(buffer, size, sniffer);
      break;
    case 17:
      ++sniffer->prot->udp;
      print_udp_packet(buffer, size, sniffer);
      break;
    default:
      ++sniffer->prot->others;
      break;
  }
  display_time_and_date();
  printf("TCP: %d UDP: %d ICMP: %d IGMP: %d Others: %d Total: %d\n",
      sniffer->prot->tcp, sniffer->prot->udp,
      sniffer->prot->icmp, sniffer->prot->igmp,
      sniffer->prot->others, sniffer->prot->total);
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
  fprintf(sniffer.logfile, "***LOGFILE(%s - %s)***\n", __DATE__, __TIME__);
  sniffer.prot = (t_protocol*)malloc(sizeof(t_protocol*));
  sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  if(sd < 0){
    perror("socket():");
    return EXIT_FAILURE;
  }
  getting_started();
  signal(SIGINT, &signal_white_now);
  signal(SIGQUIT, &signal_white_now);
  while(1){

  }
  return 0;
}
