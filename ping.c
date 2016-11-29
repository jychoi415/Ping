#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

int seq=0;
int failed=0;
int sended=0, received=0;
char dst_addr[20];
char src_addr[20];

unsigned short checksum(unsigned short*, int);
void set_ip_header(struct iphdr*,int);
void set_icmp_header(struct icmphdr*);
void sig_close(int);
void analysis_argvs(char**);
char* host_to_ip(char*);

int main(int argc, char* argv[])
{
    struct iphdr* ip, *ip_reply;
    struct icmphdr* icmp;
    struct sockaddr_in servaddr;
    char* packet, *buffer;
    int packet_size, size;
    int sockfd;
    int optval=1;
    int addrlen;

    if (getuid() != 0)
    {
      perror("Must be root :");
      exit(1);
    }
    if (!argv[1])   //  no IP
    {
      printf("[usage] : [source address][destination address] :\n");
      exit(1);
    }

    signal(SIGINT,(void*)sig_close);    // ctrl+c로 ping 종료

    memset(dst_addr,0,sizeof(dst_addr));
    memset(src_addr,0,sizeof(src_addr));
    analysis_argvs(argv);   // dst,src 설정

    packet_size = sizeof(struct iphdr)+sizeof(struct icmphdr);
    packet = (char*)malloc(packet_size);
    memset(packet,0,packet_size);

    ip = (struct iphdr*)packet;   // 전체 패킷에서 IP와 ICMP 패킷 구분
    icmp = (struct icmphdr*)(packet+sizeof(struct iphdr));    // icmphdr에서 iphdr 사이즈 만큼 뒤부터 icmp

    sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if (sockfd < 0)
    {
      perror("socket() ::");
      exit(1);
    }

    //  IP_HDRINCL : 커널이 패킷에 디폴트 iphdr 자동 추가 시도하지 않도록 소켓 설정
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int)) < 0)
    {
      perror("setsockopt() ::");
      exit(1);
    }

    printf("PING %s (%s) 56(84) bytes of data.\n",argv[2],dst_addr);

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(dst_addr);
    servaddr.sin_port = 0;
    memset(&servaddr.sin_zero,0,sizeof(servaddr.sin_zero));

    while(1)  // 패킷 송수신
    {
      set_ip_header(ip,packet_size);
      set_icmp_header(icmp);
      if (sendto(sockfd, packet, packet_size, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr)) == -1)  // 패킷 송신
      {
        perror("sendto():");
        exit(1);
      }

      ++sended;   // packet num

      buffer = (char*)malloc(packet_size);
      memset(buffer,0,sizeof(packet_size));

      addrlen = sizeof(servaddr);
      size = recvfrom(sockfd, buffer, packet_size, 0, (struct sockaddr *)&servaddr, &addrlen);   // 패킷 수신
      if (size == -1)
      {
        perror("recvfrom() ::");
        ++failed;
        continue;
      }
      received = sended;
      if (size >= 28)
      {
        ip_reply = (struct iphdr*)buffer;   // 응답 받은 데이터
        printf("%d bytes from %s: icmp_seq=%d ttl=%d\n",size,dst_addr,seq,ip_reply->ttl);
      }
      usleep(100000);
    }

    free(packet);
    free(buffer);
    close(sockfd);

    return 0;
}
void sig_close(int sig)
{
  if (received == 0)
  {
    printf("\n--- %s ping statistics ---\n",dst_addr);
    printf("0 packets transmitted, 0 received, 100.0%% packet loss\n");
    exit(0);
  }
  float loss = ((float)failed/sended*100);
  printf("--- %s ping statistics ---\n",dst_addr);
  printf("%d packets trasmitted, %d received, %.1f%% packet loss\n",sended,received,loss);
  exit(0);
}
void set_ip_header(struct iphdr *ip,int packet_size)
{
  ip->version = 4;    // IPv4
  ip->ihl = 5;    // Header length 20
  ip->tos = 0;    // types of service
  ip->tot_len = packet_size;
  ip->id = rand();
  ip->frag_off = 0;
  ip->ttl = 64;   // time to live
  ip->protocol = IPPROTO_ICMP;
  ip->saddr = inet_addr(src_addr);
  ip->daddr = inet_addr(dst_addr);
  //ip->check = 0;
  //ip->check = checksum((unsigned short*)ip, sizeof(struct iphdr));
}
void set_icmp_header(struct icmphdr *icmp)
{
  icmp->type = ICMP_ECHO;   // 8(송신)
  icmp->code = 0;
  icmp->un.echo.id = rand();
  icmp->un.echo.sequence = ++seq;
  icmp->checksum = 0;
  icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr));
}
void analysis_argvs(char** argv)
{
    sprintf(dst_addr,"%s",host_to_ip(argv[2]));
    sprintf(src_addr,"%s",argv[1]);
}
char* host_to_ip(char* buffer)
{
    struct hostent* h = gethostbyname(buffer);
    if (!h)
    {
      perror("gethostbyname() :");
      exit(1);
    }

    return inet_ntoa(*(struct in_addr *)h->h_addr_list[0]);
}
unsigned short checksum(unsigned short *addr, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = addr;
    register int nleft = len;

    while (nleft > 1)
    {
      sum += *w++;  // 연속된 16비트 정수로 만듬
      nleft -= 2;
    }
    if (nleft)
    {
      *(u_char *)(&answer) = *(u_char *)w;  // 홀수 비트 처리
      sum += answer;
    }
     //add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff);   // 상위 16비트 + 하위 16비트
    sum += (sum >> 16);   // carry bit 더함
    answer = ~sum;    //1의 보수로 만들어 리턴
    return (answer);
}
