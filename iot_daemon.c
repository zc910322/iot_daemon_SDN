/*
 * Copyright (c) 2001, Adam Dunkels.
 * Copyright (c) 2009, 2010 Joakim Eriksson, Niclas Finne, Dogan Yazar.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack.
 *
 *
 */

 /* Below define allows importing saved output into Wireshark as "Raw IP" packet type */
#define WIRESHARK_IMPORT_FORMAT 1
 
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>

#include <err.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>
#include "socket.h"


typedef enum _BDROUTER_MODE {
	BDROUTER_MODE_MONITOR,
	BDROUTER_MODE_CAPTURE,
	BDROUTER_MODE_NORMAL,
} BDROUTER_MODE;

//define the work mode of the bdrouter
//the default work mode of the bdroute is monitor
BDROUTER_MODE bdrouter_mode=BDROUTER_MODE_NORMAL;

extern int s_c4;
//---add 20140817---
extern int sc4flg;
extern int pcs_c4;
extern int pcsc4flg;
extern int mps_c4;
extern int mpsc4flg;
extern int xmpps_c4;
extern int xmppsc4flg;
//---end add---
extern int sdn_fd;
extern int sock_sniffer_client;
pthread_t  thread_do[5];
int verbose = 1;
const char *ipaddr;
const char *netmask;
int slipfd = 0;
uint16_t basedelay=0,delaymsec=0;
uint32_t startsec,startmsec,delaystartsec,delaystartmsec;
int timestamp = 0, flowcontrol=0;
struct mappingtable{
	char ipaddress[50];
    char macaddress[50];
	char routeid[5];
	char srcaddress[5];
	char dstaddress[5];
	char ipaddress_dst[50];
    char macaddress_dst[50];
	char routeid_dst[5];
	char srcaddress_dst[5];
	char dstaddress_dst[5];
	struct mappingtable *next;
};
typedef struct mappingtable *maptable;
maptable map_list;
typedef unsigned short UNIT16;

#define IPV6_HEADER_LEN      sizeof(struct ip6_hdr)
#define UDP_HEADER_LEN       sizeof(struct udphdr)
#define IPV6_UDP_HEADER_LEN    IPV6_HEADER_LEN+UDP_HEADER_LEN


int ssystem(const char *fmt, ...)
	__attribute__((__format__ (__printf__, 1, 2)));
void write_to_serial(int outfd, void *inbuf, int len);

void slip_send(int fd, unsigned char c);
void slip_send_char(int fd, unsigned char c);

//#define PROGRESS(s) fprintf(stderr, s)
#define PROGRESS(s) do { } while (0)

char tundev[32] = { "" };

int
ssystem(const char *fmt, ...) __attribute__((__format__ (__printf__, 1, 2)));

int
ssystem(const char *fmt, ...)
{
  char cmd[128];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(cmd, sizeof(cmd), fmt, ap);
  va_end(ap);
  printf("%s\n", cmd);
  fflush(stdout);
  return system(cmd);
}

#define SLIP_END     0300
#define SLIP_ESC     0333
#define SLIP_ESC_END 0334
#define SLIP_ESC_ESC 0335


/* get sockaddr, IPv4 or IPv6: */
void *
get_in_addr(struct sockaddr *sa)
{
  if(sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }
  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}
void
stamptime(void)
{
  static long startsecs=0,startmsecs=0;
  long secs,msecs;
  struct timeval tv;
  time_t t;
  struct tm *tmp;
  char timec[20];
 
  gettimeofday(&tv, NULL) ;
  msecs=tv.tv_usec/1000;
  secs=tv.tv_sec;
  if (startsecs) {
    secs -=startsecs;
    msecs-=startmsecs;
    if (msecs<0) {secs--;msecs+=1000;}
    fprintf(stderr,"%04lu.%03lu ", secs, msecs);
  } else {
    startsecs=secs;
    startmsecs=msecs;
    t=time(NULL);
    tmp=localtime(&t);
    strftime(timec,sizeof(timec),"%T",tmp);
//    fprintf(stderr,"\n%s.%03lu ",timec,msecs);
    fprintf(stderr,"\n%s ",timec);
  }
}

int
is_sensible_string(const unsigned char *s, int len)
{
  int i;
  for(i = 1; i < len; i++) {
    if(s[i] == 0 || s[i] == '\r' || s[i] == '\n' || s[i] == '\t') {
      continue;
    } else if(s[i] < ' ' || '~' < s[i]) {
      return 0;
    }
  }
  return 1;
}


// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t
checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}

// Build IPv6 UDP pseudo-header and call checksum function (Section 8.1 of RFC 2460).
uint16_t
udp6_checksum (struct ip6_hdr iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_src.s6_addr, sizeof (iphdr.ip6_src.s6_addr));
  ptr += sizeof (iphdr.ip6_src.s6_addr);
  chksumlen += sizeof (iphdr.ip6_src.s6_addr);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr.ip6_dst.s6_addr, sizeof (iphdr.ip6_dst.s6_addr));
  ptr += sizeof (iphdr.ip6_dst.s6_addr);
  chksumlen += sizeof (iphdr.ip6_dst.s6_addr);

  // Copy UDP length into buf (32 bits)
  memcpy (ptr, &udphdr.uh_ulen, sizeof (udphdr.uh_ulen));
  ptr += sizeof (udphdr.uh_ulen);
  chksumlen += sizeof (udphdr.uh_ulen);

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr.ip6_nxt, sizeof (iphdr.ip6_nxt));
  ptr += sizeof (iphdr.ip6_nxt);
  chksumlen += sizeof (iphdr.ip6_nxt);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.uh_sport, sizeof (udphdr.uh_sport));
  ptr += sizeof (udphdr.uh_sport);
  chksumlen += sizeof (udphdr.uh_sport);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.uh_dport, sizeof (udphdr.uh_dport));
  ptr += sizeof (udphdr.uh_dport);
  chksumlen += sizeof (udphdr.uh_dport);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.uh_ulen, sizeof (udphdr.uh_ulen));
  ptr += sizeof (udphdr.uh_ulen);
  chksumlen += sizeof (udphdr.uh_ulen);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen * sizeof (uint8_t));
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}


// Allocate memory for an array of chars.
char *
allocate_strmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}


// Allocate memory for an array of unsigned chars.
uint8_t *
allocate_ustrmem (int len)
{
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

int ipv6send(int fd, int data_len, char* interface, char* macaddr, char* ip, char* ip_dst, unsigned char flow,\
int port, int port_dst,unsigned char* buff){
    int sd, status;
    // UDP data

    char *src_ip, *dst_ip;
    char ret_len;
    unsigned char sdn_buf[ IPV6_UDP_HEADER_LEN + data_len];
    uint8_t *src_mac, *dst_mac, *data;
    struct addrinfo hints, *res;
    struct ip6_hdr* ipv6_header;
    struct udphdr* udp_header;
    struct sockaddr_in6 *dst_addr;
    struct sockaddr_ll device;
    struct ifreq ifr;
    void *tmp;
    int i;
    char *tmp1;

    src_mac = allocate_ustrmem (6);
    dst_mac = allocate_ustrmem (6);
    data = allocate_ustrmem (IP_MAXPACKET);
    src_ip = allocate_strmem (INET6_ADDRSTRLEN);
    dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
//    interface = allocate_strmem (INET6_ADDRSTRLEN);

    //interface to send packet through
//    strcpy(interface, "br-lan");

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit (EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its MAC address.
    memset (&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror ("ioctl() failed to get source MAC address ");
        exit (EXIT_FAILURE);
    }
    close (sd);

    // Copy source MAC address.
    memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

    // Report source MAC address to stdout.
    printf ("MAC address for interface %s is ", interface);
    for (i=0; i<5; i++) {
        printf ("%02x:", src_mac[i]);
    }
    printf ("%02x\n", src_mac[5]);

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    memset (&device, 0, sizeof (device));
    if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit (EXIT_FAILURE);
    }
//    tmp1 = p1->macaddress_dst;
    printf("1\n");
    tmp1 = macaddr;
    for (i = 0; i < 6; i++) {
        macaddr[2 + i * 3] = '\0';
        dst_mac[i] = (unsigned char)strtol(tmp1, NULL, 16);
        tmp1 = tmp1 + 3;
    }
    //set destination MAC address
//			dst_mac[0] = 0x78;
//			dst_mac[1] = 0x20;
//			dst_mac[2] = 0x04;
//			dst_mac[3] = 0x04;
//			dst_mac[4] = 0xc2;
//			dst_mac[5] = 0x9c;

    // Source IPv6 address: you need to fill this out
    for (i=0; i<5; i++) {
        printf ("%02x:", dst_mac[i]);
    }
    printf ("%02x\n", dst_mac[5]);
    strcpy (src_ip, ip);
    // Destination URL or IPv6 address: you need to fill this out
    printf("src ip: %s\n", src_ip);
    strcpy (dst_ip, ip_dst);
    printf("dst ip: %s\n", dst_ip);
    // Fill out hints for getaddrinfo().
//    memset (&hints, 0, sizeof (hints));
//    hints.ai_family = AF_INET6;
//    hints.ai_socktype = SOCK_STREAM;
//    hints.ai_flags = hints.ai_flags | AI_CANONNAME;
//
//    // Resolve target using getaddrinfo().
//    if ((status = getaddrinfo (src_ip, NULL, &hints, &res)) != 0) {
//        fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
//        exit (EXIT_FAILURE);
//    }
//    printf("getaddrinfo\n");
//    dst_addr = (struct sockaddr_in6 *) res->ai_addr;
//    tmp = &(dst_addr->sin6_addr);
//    if (inet_ntop (AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
//        status = errno;
//        fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
//        exit (EXIT_FAILURE);
//    }
//    printf("inet_ntop\n");
//    freeaddrinfo (res);

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    device.sll_protocol = htons (ETH_P_IPV6);
    memcpy (device.sll_addr, dst_mac, 6 * sizeof (uint8_t));
    device.sll_halen = 6;

    //form ipv6 header
    ipv6_header = (struct ip6_hdr *)malloc(IPV6_HEADER_LEN);
//    if(uip.inbuf[22] == 0x01){
//        ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000001);     //����ǩλ��1
//    }
//    else{
//        ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
//    }
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000|flow);
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(UDP_HEADER_LEN + data_len);
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;                 //next header:udp
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = 0xff;
    inet_pton(AF_INET6,src_ip,&(ipv6_header->ip6_src));
    inet_pton(AF_INET6,dst_ip,&(ipv6_header->ip6_dst));

    //form udp header
    udp_header = (struct udphdr *)malloc(UDP_HEADER_LEN);
    udp_header->uh_sport = htons(port);
    udp_header->uh_dport = htons(port_dst);
    udp_header->uh_ulen = htons(UDP_HEADER_LEN + data_len);
    udp_header->uh_sum = udp6_checksum(*ipv6_header, *udp_header, buff, data_len);

    //form packet
    bzero(sdn_buf, IPV6_UDP_HEADER_LEN + data_len);
    memcpy(sdn_buf, ipv6_header, IPV6_HEADER_LEN);
    memcpy(sdn_buf + IPV6_HEADER_LEN, udp_header, UDP_HEADER_LEN);
    memcpy(sdn_buf + IPV6_UDP_HEADER_LEN, buff, data_len);

    i=0;
    while((i < (IPV6_UDP_HEADER_LEN + data_len -1)) && (sdn_buf != '\0'))
    {
        printf("%02x   ", sdn_buf[i]);
        i++;
    }
    printf("%02x\n", sdn_buf[IPV6_UDP_HEADER_LEN + data_len -1]);

    ret_len = sendto(fd, sdn_buf, IPV6_UDP_HEADER_LEN + data_len, 0, (struct sockaddr*) &device, sizeof(device));
    if(ret_len > 0){
        printf("send ok\n");
    }
    else{
        printf("send fail\n");
    }

    // Free allocated memory.
    free (src_mac);
    free (dst_mac);
    free (data);
    free (interface);
    free (src_ip);
    free (dst_ip);
    return ret_len;

}
/*
 * Read from serial, when we have a packet write it to tun. No output
 * buffering, input buffered by stdio.
 */
void
serial_to_otherfd(FILE *inslip, int outfd)
{
  static union {
    unsigned char inbuf[2000];
  } uip;
  static int inbufptr = 0;
  int ret;
  unsigned char c;

#ifdef linux
  ret = fread(&c, 1, 1, inslip);
  if(ret == -1 || ret == 0) err(1, "serial_to_tun: read");
  goto after_fread;
#endif

 read_more:
  if(inbufptr >= sizeof(uip.inbuf)) {
     if(timestamp) stamptime();
     fprintf(stderr, "*** dropping large %d byte packet\n",inbufptr);
	 inbufptr = 0;
  }
  ret = fread(&c, 1, 1, inslip);
#ifdef linux
 after_fread:
#endif
  if(ret == -1) {
    err(1, "serial_to_tun: read");
  }
  if(ret == 0) {
    clearerr(inslip);
    return;
  }
  /*  fprintf(stderr, ".");*/
  switch(c) {
	  case SLIP_END:
	    if(inbufptr > 0) {
#ifdef DEBUG
	int i;
	printf("the number of data is:%d\n",inbufptr);
	for(i=0; i<inbufptr; i++){
		printf("0x%2x ",uip.inbuf[i]);
	}printf("\n");
#endif
	      if(uip.inbuf[0] == '!') {
		      if(uip.inbuf[1] == 'M') {
			 	/* Read gateway MAC address and autoconfigure tap0 interface */
			  	char macs[24];
			  	int i, pos;
			  	for(i = 0, pos = 0; i < 16; i++) {
			    		macs[pos++] = uip.inbuf[2 + i];
			    		if((i & 1) == 1 && i < 14) {
			      			macs[pos++] = ':';
		    			}
		  		}
	          		if(timestamp) stamptime();
		  		macs[pos] = '\0';
					//printf("*** Gateway's MAC address: %s\n", macs);
		  		fprintf(stderr,"*** Gateway's MAC address: %s\n", macs);
	          		if (timestamp) stamptime();
		  		ssystem("ifconfig %s down", tundev);
			        if (timestamp) stamptime();
		  		ssystem("ifconfig %s hw ether %s", tundev, &macs[6]);
			        if (timestamp) stamptime();
		  		ssystem("ifconfig %s up", tundev);
			}
	      }

	      else if(uip.inbuf[0] == '?') {
		//now, we recieve a command request from the bdrouter.
		//we need to forward the command request to the bdrouter GUI software
		if(uip.inbuf[1] == 'P') {
	          /* Prefix info requested */
	          struct in6_addr addr;
		  int i;
		  char *s = strchr(ipaddr, '/');
		  if(s != NULL) {
		    *s = '\0';
		  }
	          inet_pton(AF_INET6, ipaddr, &addr);
	          if(timestamp) stamptime();
	          fprintf(stderr,"*** Address:%s => %02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
	          //printf("*** Address:%s => %02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
			 			ipaddr,
			 			addr.s6_addr[0], addr.s6_addr[1],
			 			addr.s6_addr[2], addr.s6_addr[3],
			 			addr.s6_addr[4], addr.s6_addr[5],
			 			addr.s6_addr[6], addr.s6_addr[7]);
	          slip_send(slipfd, '!');
	          slip_send(slipfd, 'P');
	          for(i = 0; i < 8; i++) {
	         	 /* need to call the slip_send_char for stuffing */
	         	 slip_send_char(slipfd, addr.s6_addr[i]);
	          }
		  slip_send(slipfd, SLIP_END);
	        }
		#define DEBUG_LINE_MARKER '\r'


		//forword the command request to the bdrouter GUI software
		//if(s_c4!=-1){
		//	if(-1==write(s_c4, uip.inbuf, inbufptr)){
		//		close(s_c4);
		//	}//inbufptr
		//}
	      }

		else if ((uip.inbuf[0] == 0xA1) && (uip.inbuf[1] == 0xA2)&&(uip.inbuf[4] == 0x02)){  //����
			maptable p1;
//              UNIT16 routeid;
//              UNIT16 routeid_tmp;
//              UNIT16 routeid_up;
//              UNIT16 routeid_down;
              UNIT16 dstaddress;
              UNIT16 srcaddress;
              UNIT16 srcaddress_tmp;
              int sign = 0;
              p1 = map_list->next;
              while (p1 != NULL) {
                  srcaddress = strtol(p1->dstaddress, NULL, 16);
//                  printf("srcaddress: %s\n", p1->dstaddress);
//                  printf("ip: %s\n", p1->ipaddress);
//                  printf("atoi: %X\n", atoi(p1->dstaddress));
//                  routeid = (UNIT16) atoi(p1->routeid);
//                  routeid_up = uip.inbuf[16];
//                  routeid_down = uip.inbuf[17];
//                  routeid_tmp = routeid_up & routeid_down;
                  srcaddress_tmp = (uip.inbuf[7] << 8) | uip.inbuf[8];
                  printf("srcaddress: 0x%02X,srcaddress_tmp: 0x%02X.\n", srcaddress, srcaddress_tmp);
                  if (srcaddress == srcaddress_tmp) {
                      uip.inbuf[2] = 0x00;
                      dstaddress = strtol(p1->dstaddress_dst, NULL, 16);
                      uip.inbuf[7] = (unsigned char)(dstaddress >> 8);
                      uip.inbuf[8] = (unsigned char)dstaddress;
//                      uip.inbuf[12] = uip.inbuf[7];
//                      uip.inbuf[13] = uip.inbuf[8];
//                      uip.inbuf[14] = 0x00;
//                      uip.inbuf[15] = 0x01;
                      sign = 1;
                      break;
                  }
                  p1 = p1->next;
              }
            if(sign == 0) {
                fprintf(stderr, "Can not found mapping!\n");
                if(s_c4!=-1 && (sc4flg==1||(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0))) {
                    fprintf(stderr,"Application data, forward to background GUI. \n");
                    sc4flg = 0;
                    if(-1==write(s_c4, uip.inbuf, inbufptr)){
                        close(s_c4);
                    }
                }
                if(pcs_c4!=-1 && (pcsc4flg==1||(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0))) {
                    fprintf(stderr,"Application data, forward to pc background software. \n");
                    pcsc4flg = 0;
                    if(-1==write(pcs_c4, uip.inbuf, inbufptr)){
                        close(pcs_c4);
                    }
                }

                if(mps_c4!=-1 && (mpsc4flg==1||(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0))){
                    fprintf(stderr,"Application data, forward to mobile phone background software. \n");
                    mpsc4flg = 0;
                    if(-1==write(mps_c4, uip.inbuf, inbufptr)){
                        close(mps_c4);
                    }
                }
            }else{
                int data_len;
                char interface[] = "eth0";
                // UDP data
                data_len = (uip.inbuf[9]<<8) + uip.inbuf[10] + 11;
                ipv6send(sdn_fd, data_len, interface, p1->macaddress_dst, p1->ipaddress, p1->ipaddress_dst, \
            uip.inbuf[22], SDN_SRC_PORT6, SDN_DST_PORT6, uip.inbuf);
            }

#if 0
			char *interface, *src_ip, *dst_ip;
			char ret_len;
			unsigned char sdn_buf[ IPV6_UDP_HEADER_LEN + data_len];
			uint8_t *src_mac, *dst_mac, *data;
			struct addrinfo hints, *res;
			struct ip6_hdr* ipv6_header;
			struct udphdr* udp_header;
			struct sockaddr_in6 *dst_addr;
			struct sockaddr_ll device;
			struct ifreq ifr;
			void *tmp;
			int i;
              char *tmp1;

			src_mac = allocate_ustrmem (6);
			dst_mac = allocate_ustrmem (6);
			data = allocate_ustrmem (IP_MAXPACKET);
			src_ip = allocate_strmem (INET6_ADDRSTRLEN);
			dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
			interface = allocate_strmem (INET6_ADDRSTRLEN);

			//interface to send packet through
			strcpy(interface, "br-lan");

			// Submit request for a socket descriptor to look up interface.
			if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
			    perror ("socket() failed to get socket descriptor for using ioctl() ");
			    exit (EXIT_FAILURE);
			}

			// Use ioctl() to look up interface name and get its MAC address.
			memset (&ifr, 0, sizeof (ifr));
			snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
			if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
			    perror ("ioctl() failed to get source MAC address ");
			    exit (EXIT_FAILURE);
			}
			close (sd);

			// Copy source MAC address.
			memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

			// Report source MAC address to stdout.
			printf ("MAC address for interface %s is ", interface);
			for (i=0; i<5; i++) {
			  printf ("%02x:", src_mac[i]);
			}
			printf ("%02x\n", src_mac[5]);

			// Find interface index from interface name and store index in
			// struct sockaddr_ll device, which will be used as an argument of sendto().
			memset (&device, 0, sizeof (device));
			if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
			  perror ("if_nametoindex() failed to obtain interface index ");
			  exit (EXIT_FAILURE);
			}
              tmp1 = p1->macaddress_dst;
              for (i = 0; i < 6; i++) {
                  p1->macaddress_dst[2 + i * 3] = '\0';
                  dst_mac[i] = (unsigned char)strtol(tmp1, NULL, 16);
                  tmp1 = tmp1 + 3;
              }
			//set destination MAC address
//			dst_mac[0] = 0x78;
//			dst_mac[1] = 0x20;
//			dst_mac[2] = 0x04;
//			dst_mac[3] = 0x04;
//			dst_mac[4] = 0xc2;
//			dst_mac[5] = 0x9c;

			 // Source IPv6 address: you need to fill this out
		  	 strcpy (src_ip, p1->ipaddress);
		  	 // Destination URL or IPv6 address: you need to fill this out
		 	 strcpy (dst_ip, p1->ipaddress_dst);

			 // Fill out hints for getaddrinfo().
			 memset (&hints, 0, sizeof (hints));
			 hints.ai_family = AF_INET6;
			 hints.ai_socktype = SOCK_STREAM;
			 hints.ai_flags = hints.ai_flags | AI_CANONNAME;

			   // Resolve target using getaddrinfo().
		 	 if ((status = getaddrinfo (dst_ip, NULL, &hints, &res)) != 0) {
		  	  fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
		  	  exit (EXIT_FAILURE);
		 	 }
			 dst_addr = (struct sockaddr_in6 *) res->ai_addr;
			 tmp = &(dst_addr->sin6_addr);
			 if (inet_ntop (AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
			    status = errno;
			    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
		    	    exit (EXIT_FAILURE);
		 	  }
		 	  freeaddrinfo (res);

		  	 // Fill out sockaddr_ll.
		 	 device.sll_family = AF_PACKET;
		 	 device.sll_protocol = htons (ETH_P_IPV6);
			 memcpy (device.sll_addr, dst_mac, 6 * sizeof (uint8_t));
			 device.sll_halen = 6;

			//form ipv6 header
			ipv6_header = (struct ip6_hdr *)malloc(IPV6_HEADER_LEN);
			if(uip.inbuf[22] == 0x01){
				ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000001);     //����ǩλ��1
			}
			else{
				ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000000);
			}
			ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(UDP_HEADER_LEN + data_len);
			ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;                 //next header:udp
			ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = 0xff;
			inet_pton(AF_INET6,src_ip,&(ipv6_header->ip6_src));
			inet_pton(AF_INET6,dst_ip,&(ipv6_header->ip6_dst));

			//form udp header
			udp_header = (struct udphdr *)malloc(UDP_HEADER_LEN);
			udp_header->uh_sport = htons(SDN_SRC_PORT6);
			udp_header->uh_dport = htons(SDN_DST_PORT6);
			udp_header->uh_ulen = htons(UDP_HEADER_LEN + data_len);
			udp_header->uh_sum = udp6_checksum(*ipv6_header, *udp_header, uip.inbuf, data_len);

			//form packet
			bzero(sdn_buf, IPV6_UDP_HEADER_LEN + data_len);
			memcpy(sdn_buf, ipv6_header, IPV6_HEADER_LEN);
			memcpy(sdn_buf + IPV6_HEADER_LEN, udp_header, UDP_HEADER_LEN);
			memcpy(sdn_buf + IPV6_UDP_HEADER_LEN, uip.inbuf, data_len);

			i=0;
			while((i < (IPV6_UDP_HEADER_LEN + data_len -1)) && (sdn_buf != '\0'))
			{
				printf("%02x   ", sdn_buf[i]);
				i++;
			}
			printf("%02x\n", sdn_buf[IPV6_UDP_HEADER_LEN + data_len -1]);

			ret_len = sendto(sdn_fd, sdn_buf, IPV6_UDP_HEADER_LEN + data_len, 0, (struct sockaddr*) &device, sizeof(device));
			if(ret_len > 0){
				printf("send ok\n");
			}
			else{
				printf("send fail\n");
			}

			  // Free allocated memory.
			  free (src_mac);
			  free (dst_mac);
			  free (data);
			  free (interface);
			  free (src_ip);
			  free (dst_ip);
#endif
#if 0

			unsigned char date_len = (uip.inbuf[9]<<8) + uip.inbuf[10] + 11;
			char ret_len;
			char sdn_buf[date_len+ UDP_HEADER_LEN +IPV6_HEADER_LEN];
			struct ip6_hdr* ipv6_header;
			struct udphdr* udp_header;
			struct sockaddr_in6 dst_addr;
			dst_addr.sin6_family = AF_INET6;
			dst_addr.sin6_port = htons(5229);
			inet_pton(AF_INET6,DST_IP,&dst_addr.sin6_addr);

			ipv6_header = (struct ip6_hdr *)malloc(IPV6_HEADER_LEN);
			if(uip.inbuf[8] == 0x01){
				ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = 0x60000001;     //����ǩλ��1
			}
			else{
				ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = 0x60000000;
			}

			ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen = (uip.inbuf[9]<<8) + uip.inbuf[10] + 11 + UDP_HEADER_LEN;
			ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt = 0x00;
			ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = 0xff;
			ipv6_header->ip6_ctlun.ip6_un2_vfc = 0x60;
			ipv6_header->ip6_src.s6_addr32[0] = 0x2016; ipv6_header->ip6_src.s6_addr32[1] = 0x0; ipv6_header->ip6_src.s6_addr32[2] = 0x0; ipv6_header->ip6_src.s6_addr32[3] = 0x0010;
			ipv6_header->ip6_dst.s6_addr32[0] = 0x2016; ipv6_header->ip6_dst.s6_addr32[1] = 0x0; ipv6_header->ip6_dst.s6_addr32[2] = 0x0; ipv6_header->ip6_dst.s6_addr32[3] = 0x0011;


   			udp_header = (struct udphdr *)malloc(UDP_HEADER_LEN);
			udp_header->uh_sport = htons(5228);
 			udp_header->uh_dport = htons(5229);
  			udp_header->uh_ulen = (uip.inbuf[9]<<8) + uip.inbuf[10] + 11;
 			udp_header->uh_sum = 0;

			bzero(sdn_buf, date_len + UDP_HEADER_LEN +IPV6_HEADER_LEN);
			memcpy(sdn_buf, ipv6_header, IPV6_HEADER_LEN);
			memcpy(sdn_buf + IPV6_HEADER_LEN, udp_header, UDP_HEADER_LEN);
			memcpy(sdn_buf + IP_TCP_HEADER_LEN, uip.inbuf, date_len);

			ret_len = sendto(sdn_fd, sdn_buf, date_len + UDP_HEADER_LEN +IPV6_HEADER_LEN, 0,(struct sockaddr*) &dst_addr , sizeof(struct sockaddr));
			if(ret_len > 0){
				printf("send ok\n");
			}
			else{
				printf("send fail\n");
			}


			if(xmpps_c4!=-1 && (xmppsc4flg==1||(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0))) {
				fprintf(stderr,"Application data, forward to background GUI. \n");
				xmppsc4flg = 0;
				unsigned char loadbuf[12];
				//if(inbufptr >= 23)
				//{
					for(i=0; i<=11; i++)
					{
						loadbuf[i] =  uip.inbuf[i + 11];
					}
				//}

				//if(-1==write(xmpps_c4, uip.inbuf, inbufptr)){
				if(-1==write(xmpps_c4, loadbuf, 12)){
					close(xmpps_c4);
				}
			}
#endif
	    }

		else if ((uip.inbuf[0] == 0xA1) && (uip.inbuf[1] == 0xA2)&&(uip.inbuf[4] == 0x01)) {  //����
	      //now, we recieve a application data from the coordinator
	      //we need to forward the data to the background GUI
			/*/-----add 20140817 for tr069 and background managment software------------------
			//-----forward scheduling report message
			if(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0){
				if(pcs_c4!=-1) {
					fprintf(stderr,"Application data, forward to pc background software. \n");
					if(-1==write(pcs_c4, uip.inbuf, inbufptr)){
						close(pcs_c4);
					}
				}

				if(mps_c4!=-1) {
					fprintf(stderr,"Application data, forward to mobile phone background software. \n");
					if(-1==write(mps_c4, uip.inbuf, inbufptr)){
						close(mps_c4);
					}
				}
			}
			//-----end add 20140817 for tr069 and background managment software---------------*/
			if(s_c4!=-1 && (sc4flg==1||(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0))) {
				fprintf(stderr,"Application data, forward to background GUI. \n");
				sc4flg = 0;
				if(-1==write(s_c4, uip.inbuf, inbufptr)){
					close(s_c4);
				}
			}
			//-----add 20140817 for tr069 and background managment software------------------
			if(pcs_c4!=-1 && (pcsc4flg==1||(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0))) {
				fprintf(stderr,"Application data, forward to pc background software. \n");
				pcsc4flg = 0;
				if(-1==write(pcs_c4, uip.inbuf, inbufptr)){
					close(pcs_c4);
				}
			}

			if(mps_c4!=-1 && (mpsc4flg==1||(sc4flg==0&&pcsc4flg==0&&mpsc4flg==0))){
				fprintf(stderr,"Application data, forward to mobile phone background software. \n");
				mpsc4flg = 0;
				if(-1==write(mps_c4, uip.inbuf, inbufptr)){
					close(mps_c4);
				}
			}
			//-----end add 20140817 for tr069 and background managment software---------------
	    }

		else if ((uip.inbuf[0] == 0xB7) && (uip.inbuf[1] == 0xB8)) {
	      //now, we recieve a sinffer IEEE 802.15.4 packet from the sinffer
	      //we need to forward the sinffer data to the sinffer GUI software
		fprintf(stderr,"IEEE 802.15.4 packet, forward to sniffer GUI. \n");
	  	   if(sock_sniffer_client !=-1){
		   	if(-1==write(sock_sniffer_client, uip.inbuf, inbufptr)){
				close(sock_sniffer_client);
			}//inbufptr
		   }

	      }


	      else if(uip.inbuf[0] == DEBUG_LINE_MARKER) {
		fwrite(uip.inbuf + 1, inbufptr - 1, 1, stdout);
	      }

	      else if(is_sensible_string(uip.inbuf, inbufptr)) {
	        if(verbose==1) {   /* strings already echoed below for verbose>1 */
	          if (timestamp) stamptime();
	          fwrite(uip.inbuf, inbufptr, 1, stdout);
	        }
	      }
	      else {
	        if(verbose>2) {
	          if (timestamp) stamptime();
	          printf("Packet from SLIP of length %d - write TUN\n", inbufptr);
	          if (verbose>4) {
                  int i;
#if WIRESHARK_IMPORT_FORMAT
	            printf("0000");
		        	for(i = 0; i < inbufptr; i++) printf(" %02x",uip.inbuf[i]);
#else
	            printf("         ");
	            for(i = 0; i < inbufptr; i++) {
	              printf("%02x", uip.inbuf[i]);
	              if((i & 3) == 3) printf(" ");
	              if((i & 15) == 15) printf("\n         ");
	            }
#endif
	            printf("\n");
	          }
	        }

		//now, we recieve a ipv6 packet.
		// Maybe we can do some checking. It is useful but out of the scope of this daemon.
		//we should forward the packet to orther node or capture it,
		//according to the work mode of the bdrouter.
		//BDROUTER_MODE_MONITOR---forward the ipv6 packte and copy it to the bdroute GUI software.
		//BDROUTER_MODE_CAPTURE---capture the packet and send it to the bdroute GUI software.
		//BDROUTER_MODE_MORMAL---just forward the ipv6 packet to the next hop.
		if(bdrouter_mode == BDROUTER_MODE_NORMAL){	//normal
			printf("the bdroute in working in the normal mode\n");
			if(write(outfd, uip.inbuf, inbufptr) != inbufptr) {
			   err(1, "serial_to_tun: write");
			}
		}else if(bdrouter_mode == BDROUTER_MODE_CAPTURE){	//capture
			printf("the bdroute in working in the capture mode\n");
			if(s_c4!=-1){
				if(-1==write(s_c4, uip.inbuf, inbufptr)){
					close(s_c4);
				}
			}
		}else if(bdrouter_mode == BDROUTER_MODE_MONITOR){	//nornitor
			printf("the bdroute in working in the mointor mode\n");
			if(write(outfd, uip.inbuf, inbufptr) != inbufptr) {
			   err(1, "serial_to_tun: write");
			}
			if(s_c4!=-1){
				if(-1==write(s_c4, uip.inbuf, inbufptr)){
					close(s_c4);
				}
			}

		}
	      }
	      inbufptr = 0;
	    }
	    memset(uip.inbuf, '\0', sizeof(uip.inbuf));
	    break;

	  case SLIP_ESC:
	    if(fread(&c, 1, 1, inslip) != 1) {
	      clearerr(inslip);
	      /* Put ESC back and give up! */
	      ungetc(SLIP_ESC, inslip);
	      return;
	    }

	    switch(c) {
	    	case SLIP_ESC_END:
	      	c = SLIP_END;
	     		break;
	    	case SLIP_ESC_ESC:
	      	c = SLIP_ESC;
	      	break;
	    }
	    /* FALLTHROUGH */
	  default:
	    uip.inbuf[inbufptr++] = c;

	    /* Echo lines as they are received for verbose=2,3,5+ */
	    /* Echo all printable characters for verbose==4 */
	    if((verbose==2) || (verbose==3) || (verbose>4)) {
	      if(c=='\n') {
	        if(is_sensible_string(uip.inbuf, inbufptr)) {
	          if (timestamp) stamptime();
	          fwrite(uip.inbuf, inbufptr, 1, stdout);
	          inbufptr=0;
	        }
	      }
	    } else if(verbose==4) {
	      if(c == 0 || c == '\r' || c == '\n' || c == '\t' || (c >= ' ' && c <= '~')) {
					fwrite(&c, 1, 1, stdout);
	        if(c=='\n') if(timestamp) stamptime();
	      }
	    }
    	break;
  }

  goto read_more;
}

unsigned char slip_buf[2000];
int slip_end, slip_begin;

void
slip_send_char(int fd, unsigned char c)
{
  switch(c) {
  case SLIP_END:
    slip_send(fd, SLIP_ESC);
    slip_send(fd, SLIP_ESC_END);
    break;
  case SLIP_ESC:
    slip_send(fd, SLIP_ESC);
    slip_send(fd, SLIP_ESC_ESC);
    break;
  default:
    slip_send(fd, c);
    break;
  }
}

void
slip_send(int fd, unsigned char c)
{
  if(slip_end >= sizeof(slip_buf)) {
    err(1, "slip_send overflow");
  }
  slip_buf[slip_end] = c;
  slip_end++;
}

int
slip_empty()
{
  return slip_end == 0;
}

void
slip_flushbuf(int fd)
{
  int n;
  
  if(slip_empty()) {
    return;
  }

  n = write(fd, slip_buf + slip_begin, (slip_end - slip_begin));

  if(n == -1 && errno != EAGAIN) {
    err(1, "slip_flushbuf write failed");
  } else if(n == -1) {
    PROGRESS("Q");		/* Outqueueis full! */
  } else {
    slip_begin += n;
    if(slip_begin == slip_end) {
      slip_begin = slip_end = 0;
    }
  }
}

void
write_to_serial(int outfd, void *inbuf, int len)
{
  u_int8_t *p = inbuf;
  int i;

  if(verbose>2) {
    if (timestamp) stamptime();
    printf("Packet from TUN of length %d - write SLIP\n", len);
    if (verbose>4) {
#if WIRESHARK_IMPORT_FORMAT
      printf("0000");
	  for(i = 0; i < len; i++) printf(" %02x", p[i]);
#else
      printf("         ");
      for(i = 0; i < len; i++) {
        printf("%02x", p[i]);
        if((i & 3) == 3) printf(" ");
        if((i & 15) == 15) printf("\n         ");
      }
#endif
      printf("\n");
    }
  }

  /* It would be ``nice'' to send a SLIP_END here but it's not
   * really necessary.
   */
  /* slip_send(outfd, SLIP_END); */

  for(i = 0; i < len; i++) {
    switch(p[i]) {
    case SLIP_END:
      slip_send(outfd, SLIP_ESC);
      slip_send(outfd, SLIP_ESC_END);
      break;
    case SLIP_ESC:
      slip_send(outfd, SLIP_ESC);
      slip_send(outfd, SLIP_ESC_ESC);
      break;
    default:
      slip_send(outfd, p[i]);
      break;
    }
  }
  slip_send(outfd, SLIP_END);
  PROGRESS("t");
}


/*
 * Read from tun, write to slip.
 */
int
tun_to_serial(int infd, int outfd)
{
  struct {
    unsigned char inbuf[2000];
  } uip;    
  uip.inbuf[0]='\0';

  int size, i;
  if((size = read(infd, uip.inbuf, 41)) == -1){
  	err(1, "tun_to_serial: read");
  }
  else{
	for(i=0; i<41; i++){
		printf("%x  ", uip.inbuf[i]);
	}
  }
  //write_to_serial(outfd, uip.inbuf, size);
  return size;
}

/* 解析storyinfo节点，打印keyword节点的内容 */
void parseStory(xmlDocPtr doc, xmlNodePtr cur, maptable list){
    xmlChar* key;
    xmlNodePtr tmp;
    maptable p;
    p = (maptable)malloc(sizeof(struct mappingtable));
    p->next = NULL;
    cur=cur->xmlChildrenNode;
    while(cur != NULL){
        /* 找到keyword子节点 */
        if(!xmlStrcmp(cur->name, (const xmlChar *)"src")){
            tmp = cur->xmlChildrenNode;
            while(tmp != NULL){
                if(!xmlStrcmp(tmp->name, (const xmlChar *)"ip")){
                    key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
                    strcpy(p->ipaddress, key);
                    printf("ip: %s\n", key);
                }
                if (!xmlStrcmp(tmp->name, (const xmlChar *) "macaddress")) {
                    key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
                    strcpy(p->macaddress, key);
                    printf("macaddress: %s\n", key);
                }
                if(!xmlStrcmp(tmp->name, (const xmlChar *)"routeID")){
                    key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
                    strcpy(p->routeid, key);
                    printf("routeID: %s\n", key);
                }
                if(!xmlStrcmp(tmp->name, (const xmlChar *)"srcshortaddr")){
                    key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
                    strcpy(p->srcaddress, key);
                    printf("srcshortaddr: %s\n", key);
                }
                if(!xmlStrcmp(tmp->name, (const xmlChar *)"dstshortaddr")){
                    key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
                    strcpy(p->dstaddress, key);
                    printf("dstshortaddr: %s\n", key);
                }
                tmp = tmp->next;
            }
            xmlFree(key);
        }
        if(!xmlStrcmp(cur->name, (const xmlChar *)"dst")){

            tmp = cur->xmlChildrenNode;
            while(tmp != NULL){
                if(!xmlStrcmp(tmp->name, (const xmlChar *)"ip")){
                    key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
                    strcpy(p->ipaddress_dst, key);
                    printf("ip: %s\n", key);
                }
                if (!xmlStrcmp(tmp->name, (const xmlChar *) "macaddress")) {
                    key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
                    strcpy(p->macaddress_dst, key);
                    printf("macaddress: %s\n", key);
                }
                if(!xmlStrcmp(tmp->name, (const xmlChar *)"routeID")){
                    key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
                    strcpy(p->routeid_dst, key);
                    printf("routeID: %s\n", key);
                }
                if(!xmlStrcmp(tmp->name, (const xmlChar *)"srcshortaddr")){
                    key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
                    strcpy(p->srcaddress_dst, key);
                    printf("srcshortaddr: %s\n", key);
                }
                if(!xmlStrcmp(tmp->name, (const xmlChar *)"dstshortaddr")){
                    key = xmlNodeListGetString(doc, tmp->xmlChildrenNode, 1);
                    strcpy(p->dstaddress_dst, key);
                    printf("dstshortaddr: %s\n", key);
                }
                tmp = tmp->next;
            }
            xmlFree(key);
        }
        cur=cur->next; /* 下一个子节点 */
    }
    list->next = p;

    return;
}

/*
 * 解析字符串内容
 */
int parseDoc(char *docname, maptable list){
	/* 定义文档和节点指针 */
	xmlDocPtr doc;
	xmlNodePtr cur;
	maptable tmp;
	int num;

	tmp = list;
	while(tmp->next != NULL){
		tmp = tmp->next;
	}
	/* 进行解析，如果没成功，显示一个错误并停止 */
	num = strlen(docname);
	doc = xmlParseMemory(docname, num);
//    doc = xmlParseFile(docname);
	if(doc == NULL){
		fprintf(stderr, "Document not parse successfully. \n");
		return -1;
	}

	/* 获取文档根节点，若无内容则释放文档树并返回 */
	cur = xmlDocGetRootElement(doc);
	if(cur == NULL){
		fprintf(stderr, "empty document\n");
		xmlFreeDoc(doc);
		return 0;
	}

	/* 确定根节点名是否为story，不是则返回 */
	if(!xmlStrcmp(cur->name, (const xmlChar *)"mappingtable")){
		/* 遍历文档树 */
		cur = cur->xmlChildrenNode;
		while(cur != NULL){
			/* 找到storyinfo子节点 */
			if(!xmlStrcmp(cur->name, (const xmlChar *)"mapping")){
				parseStory(doc, cur, tmp); /* 解析storyinfo子节点 */
				if(tmp->next != NULL) {
					tmp = tmp->next;
				}
			}
			cur = cur->next; /* 下一个子节点 */
		}
//        fprintf(stderr, "document of the wrong type, root node != mappingtable\n");
//        fprintf(stderr, "document of the root node = %s\n", cur->name);
		xmlFreeDoc(doc);
		return 1;
	} else{
		fprintf(stderr, "document of the wrong type, root node != mappingtable\n");
		fprintf(stderr, "document of the root node = %s\n", cur->name);
		xmlFreeDoc(doc); /* 释放文档树 */
		return 2;
	}
//    xmlFreeDoc(doc); /* 释放文档树 */
//    return;
}
/*
 * 解析mapping数据
 */
int recvxml(char *str){
//    maptable map_list;
	maptable p;
//    map_list = (maptable)malloc(sizeof(struct mappingtable));
//    map_list->next = NULL;
	char *tmp[4];
	char address[] = "001";
	char address1[] = "002";
	char category[] = "1";
	int res = 0;
//    char docname[] = "./phone_book.xml";
//    char docname[1000] = "<mappingtable xmlns=\"cquptSDN:mappingtable\">\r\n<mapping>\r\n<src>\r\n<ip>192.168.1.2</ip>\r\n</src>\r\n</mapping>\r\n</mappingtable>";

	tmp[1] = address;
	tmp[0] = category;
	tmp[3] = address1;
	tmp[2] = category;
	if(1){
		printf("Usage: %s docname\n", str);
	}
	res = parseDoc(str, map_list);

	p = map_list->next;
	while(p != NULL){
		printf("ip: %s\n", p->ipaddress);
		p = p->next;
	}

//    creatXMLstring(1, tmp);

	return 1;
}
/*
 * Read from socket, write to slip.
 */
int
bdrtfd_to_serial(int infd, int outfd)
{
	char *p;
    char *tmp;
  struct {
    unsigned char inbuf[2000];
  } uip;
  int size;
    int num;
  //*uip.inbuf='!';
 // *(uip.inbuf+1)='P';
//  if((size = read(infd, uip.inbuf, 2000)) == -1) err(1, "tun_to_serial: read");
    size = read(infd, uip.inbuf, 2000);

  	if(size <=0){
		close(infd);printf("close the socket %d\n",infd);
		return 0;//indicate the socket has been closed on the remote side
	}
	if(size > 0){
		//添加字符串比较，比较post字符串，如果前4个字符串是post，则调用解析函数
		if (strncmp(uip.inbuf, "POST", 4) == 0) {
            p = strstr(uip.inbuf, "Content-Length:");
            p = p + 15;
            num = atoi(p);
            printf("%d\n", num);
			p = strchr(uip.inbuf, '<');
            tmp = p + num;
            tmp = '\0';
            printf("p: %s\n", p);
            recvxml(p);
		}
		if(0x2A==uip.inbuf[0]){
		//control the work mode of the bdrouter
			if(0x01==uip.inbuf[1]){	
			//set The bdrouter works in the monitor mode
				bdrouter_mode = BDROUTER_MODE_MONITOR;
				printf("set the bdroute work in monitor mode\n");
			}else if(0x02==uip.inbuf[1]){	
			//set the bdrouter works in the capture mode
				bdrouter_mode = BDROUTER_MODE_CAPTURE;
				printf("set the bdroute work in capture mode\n");
			}
			else if(0x03==uip.inbuf[1]){	
			//set the bdrouter works in the normal mode
				bdrouter_mode = BDROUTER_MODE_NORMAL;
				printf("set the bdroute work in normal mode\n");
			}
			return 1;
		}
		//forward the control command to the bdrouter
	 	write_to_serial(outfd, uip.inbuf, size);
	}
  return size;
}


/*
 * Read from socket, write to slip.
 */
int
sniffd_to_serial(int infd, int outfd)
{
  struct {
    unsigned char inbuf[2000];
  } uip;
  int size;
  //*uip.inbuf='!';
  //*(uip.inbuf+1)='P';
//  if((size = read(infd, uip.inbuf+2, 2000)) == -1) err(1, "tun_to_serial: read");
  	//if((size = read(infd, uip.inbuf, 2000)) == -1) err(1, "tun_to_serial: read");
  	size = read(infd, uip.inbuf, 2000);
  	if(size <=0){
		close(infd);printf("close the socket %d\n",infd);
		return 0;//indicate the socket has been closed on the remote side
	}
	if(size > 0){
//	  printf("478 the data counet:%d\n",size+2);
//	  write_to_serial(outfd, uip.inbuf, size+2);
	  write_to_serial(outfd, uip.inbuf, size);

	}
  return size;
}



#ifndef BAUDRATE
#define BAUDRATE B115200
#endif
speed_t b_rate = BAUDRATE;

void
stty_telos(int fd)
{
  struct termios tty;
  speed_t speed = b_rate;
  int i;

  if(tcflush(fd, TCIOFLUSH) == -1) err(1, "tcflush");

  if(tcgetattr(fd, &tty) == -1) err(1, "tcgetattr");

  cfmakeraw(&tty);

  /* Nonblocking read. */
  tty.c_cc[VTIME] = 0;
  tty.c_cc[VMIN] = 0;
  if (flowcontrol)
    tty.c_cflag |= CRTSCTS;
  else
    tty.c_cflag &= ~CRTSCTS;
  tty.c_cflag &= ~HUPCL;
  tty.c_cflag &= ~CLOCAL;

  cfsetispeed(&tty, speed);
  cfsetospeed(&tty, speed);

  if(tcsetattr(fd, TCSAFLUSH, &tty) == -1) err(1, "tcsetattr");

#if 1
  /* Nonblocking read and write. */
  /* if(fcntl(fd, F_SETFL, O_NONBLOCK) == -1) err(1, "fcntl"); */

  tty.c_cflag |= CLOCAL;
  if(tcsetattr(fd, TCSAFLUSH, &tty) == -1) err(1, "tcsetattr");

  i = TIOCM_DTR;
  if(ioctl(fd, TIOCMBIS, &i) == -1) err(1, "ioctl");
#endif

  usleep(10*1000);		/* Wait for hardware 10ms. */

  /* Flush input and output buffers. */
  if(tcflush(fd, TCIOFLUSH) == -1) err(1, "tcflush");
}

int
devopen(const char *dev, int flags)
{
  char t[32];
  strcpy(t, "/dev/");
  strncat(t, dev, sizeof(t) - 5);
  return open(t, flags);
}

#ifdef linux
#include <linux/if.h>
#include <linux/if_tun.h>

int
tun_alloc(char *dev, int tap)
{
  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    return -1;
  }

  memset(&ifr, 0, sizeof(ifr));

  /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
   *        IFF_TAP   - TAP device
   *
   *        IFF_NO_PI - Do not provide packet information
   */
  ifr.ifr_flags = (tap ? IFF_TAP : IFF_TUN) | IFF_NO_PI;
  if(*dev != 0)
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
    close(fd);
    return err;
  }
  strcpy(dev, ifr.ifr_name);
  return fd;
}
#else
int
tun_alloc(char *dev, int tap)
{
  return devopen(dev, O_RDWR);
}
#endif

void
cleanup(void)
{
#ifndef __APPLE__
  if (timestamp) stamptime();
  ssystem("ifconfig %s down", tundev);
#ifndef linux
  ssystem("sysctl -w net.ipv6.conf.all.forwarding=1");
#endif
  /* ssystem("arp -d %s", ipaddr); */
  if (timestamp) stamptime();
  ssystem("netstat -nr"
	  " | awk '{ if ($2 == \"%s\") print \"route delete -net \"$1; }'"
	  " | sh",
	  tundev);
#else
  {
    char *  itfaddr = strdup(ipaddr);
    char *  prefix = index(itfaddr, '/');
    if (timestamp) stamptime();
    ssystem("ifconfig %s inet6 %s remove", tundev, ipaddr);
    if (timestamp) stamptime();
    ssystem("ifconfig %s down", tundev);
    if ( prefix != NULL ) *prefix = '\0';
    ssystem("route delete -inet6 %s", itfaddr);
    free(itfaddr);
  }
#endif
}

void
sigcleanup(int signo)
{
  fprintf(stderr, "signal %d\n", signo);
  exit(0);			/* exit(0) will call cleanup() */
}

static int got_sigalarm;

void
sigalarm(int signo)
{
  got_sigalarm = 1;
  return;
}

void
sigalarm_reset()
{
#ifdef linux
#define TIMEOUT (997*1000)
#else
#define TIMEOUT (2451*1000)
#endif
  ualarm(TIMEOUT, TIMEOUT);
  got_sigalarm = 0;
}

void
ifconf(const char *tundev, const char *ipaddr)
{
#ifdef linux
  if (timestamp) stamptime();
  ssystem("ifconfig %s inet `hostname` up", tundev);
  if (timestamp) stamptime();
  ssystem("ifconfig %s add %s", tundev, ipaddr);

/* radvd needs a link local address for routing */
#if 0
/* fe80::1/64 is good enough */
  ssystem("ifconfig %s add fe80::1/64", tundev);
#elif 1
/* Generate a link local address a la sixxs/aiccu */
/* First a full parse, stripping off the prefix length */
  {
    char lladdr[40];
    char c, *ptr=(char *)ipaddr;
    uint16_t digit,ai,a[8],cc,scc,i;
    for(ai=0; ai<8; ai++) {
      a[ai]=0;
    }
    ai=0;
    cc=scc=0;
    while((c=*ptr++)) {
      if(c=='/') break;
      if(c==':') {
	if(cc)
	  scc = ai;
	cc = 1;
	if(++ai>7) break;
      } 
      else {
	cc=0;
	digit = c-'0';
	if (digit > 9) 
	  digit = 10 + (c & 0xdf) - 'A';
	a[ai] = (a[ai] << 4) + digit;
      }
    }
    /* Get # elided and shift what's after to the end */
    cc=8-ai;
    for(i=0;i<cc;i++) {
      if ((8-i-cc) <= scc) {
	a[7-i] = 0;
      } else {
	a[7-i] = a[8-i-cc];
	a[8-i-cc]=0;
      }
    }
    sprintf(lladdr,"fe80::%x:%x:%x:%x",a[1]&0xfefd,a[2],a[3],a[7]);
    if (timestamp) stamptime();
    ssystem("ifconfig %s add %s/64", tundev, lladdr);
  }
#endif /* link local */
#elif defined(__APPLE__)
  {
	char * itfaddr = strdup(ipaddr);
	char * prefix = index(itfaddr, '/');
	if ( prefix != NULL ) {
		*prefix = '\0';
		prefix++;
	} else {
		prefix = "64";
	}
    if (timestamp) stamptime();
    ssystem("ifconfig %s inet6 up", tundev );
    if (timestamp) stamptime();
    ssystem("ifconfig %s inet6 %s add", tundev, ipaddr );
    if (timestamp) stamptime();
    ssystem("sysctl -w net.inet6.ip6.forwarding=1");
    free(itfaddr);
  }
#else
  if (timestamp) stamptime();
  ssystem("ifconfig %s inet `hostname` %s up", tundev, ipaddr);
  if (timestamp) stamptime();
  ssystem("sysctl -w net.inet.ip.forwarding=1");
#endif /* !linux */

  if (timestamp) stamptime();
  ssystem("ifconfig %s\n", tundev);
}

int udp_send(int recv_fd, int fd){
    struct sockaddr_in6 c_addr;
    socklen_t addr_len;
    addr_len = sizeof(c_addr);
    int len;
    int res;
    char buff[1000];
    char buf_ip[128];



    len = recvfrom(recv_fd, buff, sizeof(buff) - 1, 0,
                       (struct sockaddr *) &c_addr, &addr_len);
    if (len < 0) {
        perror("recvfrom");
        return -1;
    }

    buff[len] = '\0';
    printf("receive from %s: buffer:%s\n\r",
           inet_ntop(AF_INET6, &c_addr.sin6_addr, buf_ip, sizeof(buf_ip)),
           buff);

    res = write(fd, buff, len + 1);
    if(res < 0){
        perror("write");
        return -1;
    }
    return res;
}

int
main(int argc, char **argv)
{
  int c;
  int maxfd;
  int ret;
  int tunfd;
  fd_set rset, wset;
  FILE *inslip;
  const char *siodev = NULL;
  const char *host = NULL;
  const char *port = NULL;
  const char *prog;
  int baudrate = -2;
  int tap = 0;
  slipfd = 0;

	map_list = (maptable)malloc(sizeof(struct mappingtable));
	map_list->next = NULL;
  fprintf(stderr, "******** IoT Daemon, Ver. 1.1 ********'\n");

//======================================================================
// .bref: start of parsing typical unix command line options
//======================================================================
  prog = argv[0];
  setvbuf(stdout, NULL, _IOLBF, 0); /* Line buffered output. */

  while((c = getopt(argc, argv, "B:HLhs:t:v::d::a:p:T")) != -1) {
    switch(c) {
    case 'B':
      baudrate = atoi(optarg);
      break;

    case 'H':
      flowcontrol=1;
      break;
 
    case 'L':
      timestamp=1;
      break;

    case 's':
      if(strncmp("/dev/", optarg, 5) == 0) {
	siodev = optarg + 5;
      } else {
	siodev = optarg;
      }
      break;

    case 't':
      if(strncmp("/dev/", optarg, 5) == 0) {
	strncpy(tundev, optarg + 5, sizeof(tundev));
      } else {
	strncpy(tundev, optarg, sizeof(tundev));
      }
      break;

    case 'a':
      host = optarg;
      break;

    case 'p':
      port = optarg;
      break;

    case 'd':
      basedelay = 10;
      if (optarg) basedelay = atoi(optarg);
      break;

    case 'v':
      verbose = 2;
      if (optarg) verbose = atoi(optarg);
      break;

    case 'T':
      tap = 1;
      break;
 
    case '?':
    case 'h':
    default:
fprintf(stderr,"usage:  %s [options] ipaddress\n", prog);
fprintf(stderr,"example: iot_daemon -L -v2 -s ttyUSB1 aaaa::1/64\n");
fprintf(stderr,"Options are:\n");
#ifndef __APPLE__
fprintf(stderr," -B baudrate    9600,19200,38400,57600,115200 (default),230400,460800,921600\n");
#else
fprintf(stderr," -B baudrate    9600,19200,38400,57600,115200 (default),230400\n");
#endif
fprintf(stderr," -H             Hardware CTS/RTS flow control (default disabled)\n");
fprintf(stderr," -L             Log output format (adds time stamps)\n");
fprintf(stderr," -s siodev      Serial device (default /dev/ttyUSB0)\n");
fprintf(stderr," -T             Make tap interface (default is tun interface)\n");
fprintf(stderr," -t tundev      Name of interface (default tap0 or tun0)\n");
fprintf(stderr," -v[level]      Verbosity level\n");
fprintf(stderr,"    -v0         No messages\n");
fprintf(stderr,"    -v1         Encapsulated SLIP debug messages (default)\n");
fprintf(stderr,"    -v2         Printable strings after they are received\n");
fprintf(stderr,"    -v3         Printable strings and SLIP packet notifications\n");
fprintf(stderr,"    -v4         All printable characters as they are received\n");
fprintf(stderr,"    -v5         All SLIP packets in hex\n");
fprintf(stderr,"    -v          Equivalent to -v3\n");
fprintf(stderr," -d[basedelay]  Minimum delay between outgoing SLIP packets.\n");
fprintf(stderr,"                Actual delay is basedelay*(#6LowPAN fragments) milliseconds.\n");
fprintf(stderr,"                -d is equivalent to -d10.\n");
fprintf(stderr," -a serveraddr  \n");
fprintf(stderr," -p serverport  \n");
exit(1);
      break;
    }
  }

//======================================================================
//.bref: end of parsing typical unix command line options
//======================================================================
//.bref: start to configrate arguments and open  
//======================================================================
  
  argc -= (optind - 1);
  argv += (optind - 1);

  if(argc != 2 && argc != 3) {
    err(1, "usage: %s [-B baudrate] [-H] [-L] [-s siodev] [-t tundev] [-T] [-v verbosity] [-d delay] [-a serveraddress] [-p serverport] ipaddress", prog);
  }
  ipaddr = argv[1];

  switch(baudrate) {
  case -2:
    break;			/* Use default. */
  case 9600:
    b_rate = B9600;
    break;
  case 19200:
    b_rate = B19200;
    break;
  case 38400:
    b_rate = B38400;
    break;
  case 57600:
    b_rate = B57600;
    break;
  case 115200:
    b_rate = B115200;
    break;
  case 230400:
    b_rate = B230400;
    break;
#ifndef __APPLE__
  case 460800:
    b_rate = B460800;
    break;
  case 921600:
    b_rate = B921600;
    break;
#endif
  default:
    err(1, "unknown baudrate %d", baudrate);
    break;
  }

  if(*tundev == '\0') {
    /* Use default. */
    if(tap) {
      strcpy(tundev, "tap0");
    } else {
      strcpy(tundev, "tun0");
    }
  }
  
  if(host != NULL) {//creat tunnel via network interface
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    if(port == NULL) {
      port = "60001";
    }

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
      err(1, "getaddrinfo: %s", gai_strerror(rv));
    }

    /* loop through all the results and connect to the first we can */
    for(p = servinfo; p != NULL; p = p->ai_next) {
      if((slipfd = socket(p->ai_family, p->ai_socktype,
                          p->ai_protocol)) == -1) {
        perror("client: socket");
        continue;
      }

      if(connect(slipfd, p->ai_addr, p->ai_addrlen) == -1) {
        close(slipfd);
        perror("client: connect");
        continue;
      }
      break;
    }

    if(p == NULL) {
      err(1, "can't connect to ``%s:%s''", host, port);
    }

    fcntl(slipfd, F_SETFL, O_NONBLOCK);

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
              s, sizeof(s));
    fprintf(stderr, "slip connected to ``%s:%s''\n", s, port);

    /* all done with this structure */
    freeaddrinfo(servinfo);

  } 
  else {//creat tunnel via other native devices(.e.g usb interface, serial interface)
    if(siodev != NULL) {
      slipfd = devopen(siodev, O_RDWR | O_NONBLOCK);
      if(slipfd == -1) {
				err(1, "can't open siodev ``/dev/%s''", siodev);
      }
    } 
    else {
      static const char *siodevs[] = {
        "ttyUSB0", "cuaU0", "ucom0" /* linux, fbsd6, fbsd5 */
      };
      int i;
      for(i = 0; i < 3; i++) {
        siodev = siodevs[i];
        slipfd = devopen(siodev, O_RDWR | O_NONBLOCK);
        if(slipfd != -1) {
          break;
        }
      }
      if(slipfd == -1) {
        err(1, "can't open siodev");
      }
    }
	
    if (timestamp) stamptime();
	
    fprintf(stderr, "********SLIP started on ``/dev/%s''\n", siodev);
    stty_telos(slipfd);
  }
  
  slip_send(slipfd, SLIP_END);
  inslip = fdopen(slipfd, "r");
  if(inslip == NULL) err(1, "main: fdopen");

  tunfd = tun_alloc(tundev, tap);
  if(tunfd == -1) err(1, "main: open");
  
  if (timestamp) stamptime();
  
  fprintf(stderr, "opened %s device ``/dev/%s''\n",
          tap ? "tap" : "tun", tundev);
  
  //enable ipv6 packet forwarding function
 ssystem("sysctl -w net.ipv6.conf.all.forwarding=1");
  
  atexit(cleanup);
  signal(SIGHUP, sigcleanup);
  signal(SIGTERM, sigcleanup);
  signal(SIGINT, sigcleanup);
  signal(SIGALRM, sigalarm);
  ifconf(tundev, ipaddr);




 //=================================================================
 //.bref: start---creat pthread processing client ipv4 connection request
 //=================================================================
 pthread_create(&thread_do[0],		
			NULL,			
			handle_connect4,	
			NULL);
  pthread_create(&thread_do[1],		
			NULL,			
			sniffer_connect,	
			NULL);
  //-----------------------------
  //add : 20140817
  pthread_create(&thread_do[2],		
			NULL,			
			handle_pcbms_connect4,	
			NULL);
  pthread_create(&thread_do[3],		
			NULL,			
			handle_mpbms_connect4,	
			NULL);
  //end add.
  //-----------------------------
  pthread_create(&thread_do[4],
  			NULL,
  			handle_xmpps_connect4,
  			NULL);
 //=================================================================
 //.bref: end---creat pthread processing client ipv4 connection request
 //=================================================================
  struct sockaddr_in6 local_addr6;
    struct sockaddr_in6 local_address6;
    int recv_fd;
  creat_sockfd6(&sdn_fd, &local_addr6, SDN_SRC_PORT6);
    if ((recv_fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
        perror("socket");
        exit(errno);
    } else
        printf("create socket.\n\r");
    memset(&local_address6, 0, sizeof(struct sockaddr_in6));
    local_address6.sin6_family = AF_INET6;
    local_address6.sin6_port = htons(SDN_DST_PORT6);
    local_address6.sin6_addr = in6addr_any;
    if ((bind(recv_fd, (struct sockaddr *) &local_address6, sizeof(local_address6))) == -1) {
        perror("bind");
        exit(errno);
    } else
        printf("bind address to socket.\n\r");



    while(1) {
    maxfd = 0;
    FD_ZERO(&rset);
    FD_ZERO(&wset);

#if 0

int sd, data_len, status, i;
// UDP data
data_len = 4;

char *interface, *src_ip, *dst_ip;
char ret_len;
char sdn_buf[ IPV6_UDP_HEADER_LEN + data_len];
uint8_t *src_mac, *dst_mac, *data;
struct addrinfo hints, *res;
struct ip6_hdr* ipv6_header;
struct udphdr* udp_header;
struct sockaddr_in6 *dst_addr;
struct sockaddr_ll device;
struct ifreq ifr;
void *tmp;

src_mac = allocate_ustrmem (6);
dst_mac = allocate_ustrmem (6);
data = allocate_ustrmem (IP_MAXPACKET);
src_ip = allocate_strmem (INET6_ADDRSTRLEN);
dst_ip = allocate_strmem (INET6_ADDRSTRLEN);
interface = allocate_strmem (INET6_ADDRSTRLEN);

//interface to send packet through
strcpy(interface, "br-lan");

// Submit request for a socket descriptor to look up interface.
if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
	perror ("socket() failed to get socket descriptor for using ioctl() ");
	exit (EXIT_FAILURE);
}

// Use ioctl() to look up interface name and get its MAC address.
memset (&ifr, 0, sizeof (ifr));
snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
	perror ("ioctl() failed to get source MAC address ");
	exit (EXIT_FAILURE);
}
close (sd);

// Copy source MAC address.
memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

// Report source MAC address to stdout.
printf ("MAC address for interface %s is ", interface);
for (i=0; i<5; i++) {
  printf ("%02x:", src_mac[i]);
}
printf ("%02x\n", src_mac[5]);

// Find interface index from interface name and store index in
// struct sockaddr_ll device, which will be used as an argument of sendto().
memset (&device, 0, sizeof (device));
if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
  perror ("if_nametoindex() failed to obtain interface index ");
  exit (EXIT_FAILURE);
}

//set destination MAC address
/*
dst_mac[0] = 0x00;
dst_mac[1] = 0x00;
dst_mac[2] = 0x00;
dst_mac[3] = 0x00;
dst_mac[4] = 0x00;
dst_mac[5] = 0x00;
*/

dst_mac[0] = 0x7a;
dst_mac[1] = 0x20;
dst_mac[2] = 0x04;
dst_mac[3] = 0x04;
dst_mac[4] = 0xc2;
dst_mac[5] = 0x9c;


 // Source IPv6 address: you need to fill this out
 strcpy (src_ip, "2016::10");
 // Destination URL or IPv6 address: you need to fill this out
 strcpy (dst_ip, "2016::101");
 
 // Fill out hints for getaddrinfo().
 memset (&hints, 0, sizeof (hints));
 hints.ai_family = AF_INET6;
 hints.ai_socktype = SOCK_STREAM;
 hints.ai_flags = hints.ai_flags | AI_CANONNAME;

   // Resolve target using getaddrinfo().
 if ((status = getaddrinfo (dst_ip, NULL, &hints, &res)) != 0) {
  fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
  exit (EXIT_FAILURE);
 }
 dst_addr = (struct sockaddr_in6 *) res->ai_addr;
 tmp = &(dst_addr->sin6_addr);
 if (inet_ntop (AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
	status = errno;
	fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
  }
  freeaddrinfo (res);

 // Fill out sockaddr_ll.
 device.sll_family = AF_PACKET;
 device.sll_protocol = htons (ETH_P_IPV6);
 memcpy (device.sll_addr, dst_mac, 6 * sizeof (uint8_t));
 device.sll_halen = 6;

data[0] = 'T';
data[1] = 'e';
data[2] = 's';
data[3] = 't';



//form ipv6 header
ipv6_header = (struct ip6_hdr *)malloc(IPV6_HEADER_LEN);
ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl(0x60000001);	 //����ǩλ��1
ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(UDP_HEADER_LEN + data_len);
ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_UDP;				  //next header:udp
ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = 0xff;
inet_pton(AF_INET6,src_ip,&(ipv6_header->ip6_src));  
inet_pton(AF_INET6,dst_ip,&(ipv6_header->ip6_dst));  

//form udp header
udp_header = (struct udphdr *)malloc(UDP_HEADER_LEN);
udp_header->uh_sport = htons(SDN_SRC_PORT6);
udp_header->uh_dport = htons(SDN_DST_PORT6);
udp_header->uh_ulen = htons(UDP_HEADER_LEN + data_len);
udp_header->uh_sum = udp6_checksum(*ipv6_header, *udp_header, data, data_len);

//form packet
bzero(sdn_buf, IPV6_UDP_HEADER_LEN + data_len);
memcpy(sdn_buf, ipv6_header, IPV6_HEADER_LEN);
memcpy(sdn_buf + IPV6_HEADER_LEN, udp_header, UDP_HEADER_LEN);
memcpy(sdn_buf + IPV6_UDP_HEADER_LEN, data, data_len);

ret_len = sendto(sdn_fd, sdn_buf, IPV6_UDP_HEADER_LEN + data_len, 0, (struct sockaddr*) &device, sizeof(device));
if(ret_len > 0){
	printf("send ok\n");
}
else{
	printf("send fail\n");
}

  // Free allocated memory.
  free (src_mac);
  free (dst_mac);
  free (data);
  free (interface);
  free (src_ip);
  free (dst_ip);

#endif

/* do not send IPA all the time... - add get MAC later... */
/*     if(got_sigalarm) { */
/*       /\* Send "?IPA". *\/ */
/*       slip_send(slipfd, '?'); */
/*       slip_send(slipfd, 'I'); */
/*       slip_send(slipfd, 'P'); */
/*       slip_send(slipfd, 'A'); */
/*       slip_send(slipfd, SLIP_END); */
/*       got_sigalarm = 0; */
/*     } */

    if(!slip_empty() ) {	/* Anything to flush? */
      FD_SET(slipfd, &wset);
    }

    /* We only have one packet at a time queued for slip output. */
    if(slip_empty()) {
      FD_SET(tunfd, &rset);
      if(tunfd > maxfd) maxfd = tunfd;
    }
	
    if(slip_empty() && s_c4 !=-1) {
       FD_SET(s_c4, &rset);
      if(s_c4 > maxfd) maxfd = s_c4;
    }
	//-----------------------------
	//add : 20140817
    if(slip_empty() && pcs_c4 !=-1) {
       FD_SET(pcs_c4, &rset);
      if(pcs_c4 > maxfd) maxfd = pcs_c4;
    }
	
    if(slip_empty() && mps_c4 !=-1) {
       FD_SET(mps_c4, &rset);
      if(mps_c4 > maxfd) maxfd = mps_c4;
    }
	//end add : 20140817
	//-----------------------------
    if(slip_empty() && xmpps_c4 !=-1) {
       FD_SET(xmpps_c4, &rset);
      if(xmpps_c4 > maxfd) maxfd = xmpps_c4;
    }

	
    if(slip_empty() && sock_sniffer_client!=-1) {
       FD_SET(sock_sniffer_client, &rset);
      if(sock_sniffer_client > maxfd) maxfd = sock_sniffer_client;
    }	
	
    FD_SET(slipfd, &rset);	/* Read from slip ASAP! */
    if(slipfd > maxfd) maxfd = slipfd;
        FD_SET(recv_fd, &rset);	/* Read from slip ASAP! */
        if(recv_fd > maxfd) maxfd = recv_fd;

	

    ret = select(maxfd + 1, &rset, &wset, NULL, NULL);
    if(ret == -1 && errno != EINTR) {
      err(1, "select");
    } 
    else if(ret > 0) {          //read data from slip interface
      if(FD_ISSET(slipfd, &rset)) {
        serial_to_otherfd(inslip, tunfd);
      }
      
      if(FD_ISSET(slipfd, &wset)) {
				slip_flushbuf(slipfd);
				sigalarm_reset();
      }
        if (FD_ISSET(recv_fd, &rset)) {
            udp_send(recv_fd, slipfd);
        }

 
      /* Optional delay between outgoing packets */
      /* Base delay times number of 6lowpan fragments to be sent */
      if(delaymsec) {
       struct timeval tv;
       int dmsec;
       gettimeofday(&tv, NULL) ;
       dmsec=(tv.tv_sec-delaystartsec)*1000+tv.tv_usec/1000-delaystartmsec;
       if(dmsec<0) delaymsec=0;
       if(dmsec>delaymsec) delaymsec=0;
      }
	  
      if(delaymsec==0) {
        int size;
#if 0
        if(slip_empty() && FD_ISSET(tunfd, &rset)) {//tun--to--serial
          size=tun_to_serial(tunfd, slipfd);
          slip_flushbuf(slipfd);
          sigalarm_reset();
          if(basedelay) {
            struct timeval tv;
            gettimeofday(&tv, NULL) ;
 //         delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
            delaymsec=basedelay;
            delaystartsec =tv.tv_sec;
            delaystartmsec=tv.tv_usec/1000;
          }
        }
#endif
	
		if(s_c4 != -1){
	    	if(slip_empty() && FD_ISSET(s_c4, &rset)) {//socket--to--serial
	            size=bdrtfd_to_serial(s_c4, slipfd);
		    	if(0==size){ 
					s_c4=-1;
					sc4flg = 0;
		    	}
	            else{
					sc4flg = 1;
					slip_flushbuf(slipfd);
	                sigalarm_reset();
	                if(basedelay) {
	                   struct timeval tv;
	                   gettimeofday(&tv, NULL) ;
					   //delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
	                   delaymsec=basedelay;
	                   delaystartsec =tv.tv_sec;
	                   delaystartmsec=tv.tv_usec/1000;
		        	}
	        	}
	        }
		}
	
		//----add 20140817 for tr069 and background managment software------
		if(pcs_c4 != -1){
        	if(slip_empty() && FD_ISSET(pcs_c4, &rset)) {//socket--to--serial
            	size=bdrtfd_to_serial(pcs_c4, slipfd);
	    		if(0==size){ 
					pcs_c4=-1;
					pcsc4flg = 0;
	    		}
            	else{
					pcsc4flg = 1;
					slip_flushbuf(slipfd);
                	sigalarm_reset();
                	if(basedelay) {
                		struct timeval tv;
                		gettimeofday(&tv, NULL) ;
      					//delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
                	   	delaymsec=basedelay;
                   		delaystartsec =tv.tv_sec;
                   		delaystartmsec=tv.tv_usec/1000;
	        		}
            	}
        	}
		}

	
		if(mps_c4 != -1){
        	if(slip_empty() && FD_ISSET(mps_c4, &rset)) {//socket--to--serial
	            size=bdrtfd_to_serial(mps_c4, slipfd);
		    	if(0==size){ 
					mps_c4=-1;
					mpsc4flg = 0;
		    	}
	            else{
					mpsc4flg = 1;
					slip_flushbuf(slipfd);
	                sigalarm_reset();
	                if(basedelay) {
	                   struct timeval tv;
	                   gettimeofday(&tv, NULL) ;
	      			   //delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
	                   delaymsec=basedelay;
	                   delaystartsec =tv.tv_sec;
	                   delaystartmsec=tv.tv_usec/1000;
		        	}
	            }
			}
		}

		if(xmpps_c4 != -1){
        	  if(slip_empty() && FD_ISSET(xmpps_c4, &rset)) {//socket--to--serial
	            size=bdrtfd_to_serial(xmpps_c4, slipfd);
		    	if(0==size){ 
					xmpps_c4=-1;
					xmppsc4flg = 0;
		    	}
	            else{
					xmppsc4flg = 1;
					slip_flushbuf(slipfd);
	                sigalarm_reset();
	                if(basedelay) {
	                   struct timeval tv;
	                   gettimeofday(&tv, NULL) ;
	      			   //delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
	                   delaymsec=basedelay;
	                   delaystartsec =tv.tv_sec;
	                   delaystartmsec=tv.tv_usec/1000;
		        	}
	            }
		  }
		}

	//----end add 20140817 for tr069 and background managment software------
	
	if(sock_sniffer_client!= -1){
          if(slip_empty() && FD_ISSET(sock_sniffer_client, &rset)) {//socket--to--serial
            size=sniffd_to_serial(sock_sniffer_client, slipfd);
	    if(0==size){ 
		sock_sniffer_client=-1;
	    }
            else{
		slip_flushbuf(slipfd);
                sigalarm_reset();
                if(basedelay) {
                   struct timeval tv;
                   gettimeofday(&tv, NULL) ;
      //         delaymsec=basedelay*(1+(size/120));//multiply by # of 6lowpan packets?
                   delaymsec=basedelay;
                   delaystartsec =tv.tv_sec;
                   delaystartmsec=tv.tv_usec/1000;
	        }
            }
          }
	}
      }
    }
  }
}
