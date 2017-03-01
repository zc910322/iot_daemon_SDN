#ifndef _HANDLE_CONNECT_H_
#define _HANDLE_CONNECT_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD



//#define SERVER_PORT4 5222		//servier port
//------------------------------------------------------------------------------
/*add new TL port number for TR069-Proxier and Background-management-software--20140816*/
#define TR069_SERVER_PORT4	5222	//for tr069 proxier 
#define MPBMS_SERVER_PORT4	5225	//for mobile phone background managment software
#define PCBMS_SERVER_PORT4	5226	//for pc background managment software
#define XMPPS_SERVER_PORT4 5227 //for xmpp server

#define SERVER_PORT4 TR069_SERVER_PORT4
//------------------------------------------------------------------------------
#define SDN_SRC_PORT6 5228
#define SDN_DST_PORT6 5228

#define SNIFFER_PORT 5224
#define SERVER_PORT6 5223
#define BACKLOG 7			//the max number of unaccepted connections in the queue
#define YES 1
#define NO 0



void * handle_connect4(void * arg);
void * handle_pcbms_connect4(void * arg);
void * handle_mpbms_connect4(void * arg);
void * handle_xmpps_connect4(void * arg);

void* sniffer_connect(void * arg);
void * handle_connect6(void * arg);
void creat_server_sockfd6(int *sockfd,struct sockaddr_in6 *local6);
void creat_server_sockfd4(int *sockfd,struct sockaddr_in *local ,int portnum);
void creat_sockfd6(int *sockfd, struct sockaddr_in6 *local, int portnum);



#endif

