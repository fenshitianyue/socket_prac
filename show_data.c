#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "sniffer.h"
#include "tools.h"

void print_ip_header(unsigned char* buf, int size, t_sniffer* sniffer){
  unsigned short iphdrlen;
  struct iphdr* iph;
  struct sockaddr_in source;
  struct sockaddr_in dest;
  iph = (struct iphdr*)buf;
  iphdrlen = iph->ihl * 4;
  (void)iphdrlen;
  (void)size;
  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;
  memset(&dest, 0, sizeof(dest));
  fprintf(sniffer->logfile, "\n");
  fprintf(sniffer->logfile, "IP Header\n");
  fprintf(sniffer->logfile, "   |-IP Version        : %d\n", (unsigned int)iph->version);
  fprintf(sniffer->logfile, "   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
  fprintf(sniffer->logfile, "   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
  fprintf(sniffer->logfile, "   |-IP Total Length   : %d  Bytes(size of Packet)\n", ntohs(iph->tot_len));
  fprintf(sniffer->logfile, "   |-Identification    : %d\n", ntohs(iph->id));
  fprintf(sniffer->logfile, "   |-TTL      : %d\n", (unsigned int)iph->ttl);
  fprintf(sniffer->logfile, "   |-Protocal : %d\n", (unsigned int)iph->protocol);
  fprintf(sniffer->logfile, "   |-Checksum : %d\n", ntohs(iph->check));
  fprintf(sniffer->logfile, "   |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
  fprintf(sniffer->logfile, "   |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}


void print_tcp_packet(unsigned char* buf, int size, t_sniffer* sniffer){
  unsigned short iphdrlen;
  struct iphdr* iph;
  struct tcphdr* tcph;
  iph = (struct iphdr*)buf;
  iphdrlen = iph->ihl * 4;
  tcph = (struct tcphdr*)(buf + iphdrlen);
  print_ip_header(buf, size, sniffer);
  
  fprintf(sniffer->logfile, "\n");
  fprintf(sniffer->logfile, "TCP Header\n");
  fprintf(sniffer->logfile, "");
  fprintf(sniffer->logfile, "");
  fprintf(sniffer->logfile, "");
  fprintf(sniffer->logfile, "");
  fprintf(sniffer->logfile, "");
  fprintf(sniffer->logfile, "");
  fprintf(sniffer->logfile, "");
  fprintf(sniffer->logfile, "");
  fprintf(sniffer->logfile, "");
  fprintf(sniffer->logfile, "\n");
  fprintf(sniffer->logfile, "\n");
}


