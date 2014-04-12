/*
 *  Author: Luis Martin Garcia. luis.martingarcia [.at.] gmail [d0t] com  
 *  Copyright (c) 2013 Aurélien Bauchet <aurelien@niamia.org>	
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pcap.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

// For daemonizing
#include <signal.h>
#include <fcntl.h>

// For logging
#include <syslog.h>


#define RUNNING_DIR	"/tmp"
//#define LOCK_FILE	"exampled.lock"
#define DAEMON_NAME	"wakeonarp"
#define LOG_FILE	"wakeonarp.log"

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
typedef struct arphdr {
	u_int16_t htype;    /* Hardware Type           */ 
	u_int16_t ptype;    /* Protocol Type           */ 
	u_char hlen;        /* Hardware Address Length */
	u_char plen;        /* Protocol Address Length */ 
	u_int16_t oper;     /* Operation Code          */ 
	u_char sha[6];      /* Sender hardware address */ 
	u_char spa[4];      /* Sender IP address       */ 
	u_char tha[6];      /* Target hardware address */ 
	u_char tpa[4];      /* Target IP address       */ 
}arphdr_t; 

#define MAXBYTES2CAPTURE 2048 
#define BUFLEN 102

int g_ignore_ip_found;
int g_mac_addr[6], g_ip_addr[4], g_ignore_ip[4];
char * g_if;

//struct in_addr bcast

int check_for_mac_address(const char * mac_addr_str, int * mac_addr )
{
	int i;
	int res = -1;
	int addr[6];
	//mac_addr = NULL;
	
	if(strlen(mac_addr_str) != 17)
		return 0;

	res = sscanf(mac_addr_str,"%x:%x:%x:%x:%x:%x",&addr[0],&addr[1],&addr[2],&addr[3],&addr[4],&addr[5]);
    
	if(res != 6)
		return 0;
	
	for(i = 0; i < 6; ++i)
	{
		mac_addr[i] = addr[i];
	}

	return 1;
}

int check_for_ip_address(const char * ip_addr_str, int * ip_addr )
{
	int i;
	int res = -1;
	int addr[4];
	//ip_addr = NULL;

	res = sscanf(ip_addr_str,"%u.%u.%u.%u",&addr[0],&addr[1],&addr[2],&addr[3]); 
	if(res != 4)
		return 0;
   
	for(i = 0; i < 4; ++i)
	{
		if(addr[i] < 0 || addr[i] > 255)
			return 0;
	}
   
	
	for(i = 0; i < 4; ++i)
	{
		ip_addr[i] = addr[i];
	}
	
	return 1;
}

void make_magic_packet(const int * mac_addr, char * mesg)
{
	int i,j;
	
	for(i = 0; i < 6; ++i)
	{
		mesg[i] = 0xFF;
	}

	for(j = 1; j <= 16; ++j)
	{
		for(i = 0; i < 6; ++i)
		{
			mesg[6*j+i] = (char)mac_addr[i]; 
		}
	}
}


void send_magic_packet(const char * mesg)
{
	int senderSocket;
	struct sockaddr_in wt;
	memset(&wt, 0, sizeof(wt));
	wt.sin_family = AF_INET;
	wt.sin_port = htons(9);
	inet_aton("255.255.255.255", &wt.sin_addr);

	int i;
	for(i = 0; i < 102; ++i)
	{
		printf("%x",mesg[i]);
		if(i != 101)
			printf("-");
		else
			printf("\n");
	}
 
	senderSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int udpflag = 1;
	int retval;
	retval = setsockopt(senderSocket, SOL_SOCKET, SO_BROADCAST, &udpflag, sizeof(udpflag));
	if (retval < 0)
	{
//        sprintf (str,"failed to setsockopt: %s",strerror(errno));
//        printf("%s\n",str);
        }

	int res;
	res = sendto(senderSocket,mesg,BUFLEN,0,(struct sockaddr *)&wt,sizeof(wt));
 
	if(res < 0)
	{
 //       sprintf (str,"failed to send: %s",strerror(errno));
 //       printf("%s\n", str);
        }
	else 
	{
		printf("Sent WoL on port %i\n",9);
	} 
}

void process_arp_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	int i=0;
	int * count = (int *)user;


	//struct pcap_pkthdr pkthdr;        /* Packet information (timestamp,size...) */ 
	//const unsigned char *packet=NULL; /* Received raw data                      */ 
	arphdr_t *arpheader = NULL;       /* Pointer to the ARP header              */ 

	arpheader = (struct arphdr *)(bytes+14); /* Point to the ARP header */

	if((ntohs(arpheader->htype) != 1) || 
			(ntohs(arpheader->ptype) != 0x0800) ||
			(ntohs(arpheader->oper) != ARP_REQUEST))
		return;

	if((arpheader->tpa[0] == g_ip_addr[0]) &&
			(arpheader->tpa[1] == g_ip_addr[1]) &&
			(arpheader->tpa[2] == g_ip_addr[2]) &&
			(arpheader->tpa[3] == g_ip_addr[3]))
	{
		time_t nowtime;
		struct tm *nowtm;
		char tmbuf[64], buf[64];

		nowtime = h->ts.tv_sec;
		nowtm = localtime(&nowtime);
		strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
		snprintf(buf, sizeof buf, "%s.%06d", tmbuf, (int)nowtime);

		printf("\n\nReceived Packet No: %d \n", ++(*count));
		printf("Received Packet Timestamp: %s \n\n", buf);


		printf("Received Packet Size: %d bytes\n", h->len); 
		printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown"); 
		printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
		printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply"); 
	 
		/* If is Ethernet and IPv4, print packet contents */ 
		if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
		{ 
			printf("Sender MAC: "); 
			for(i=0; i<6;i++)
				printf("%02X:", arpheader->sha[i]); 

			printf("\nSender IP: "); 
			for(i=0; i<4;i++)
				printf("%d.", arpheader->spa[i]); 

			printf("\nTarget MAC: "); 
			for(i=0; i<6;i++)
				printf("%02X:", arpheader->tha[i]); 
			
			printf("\nTarget IP: "); 
			for(i=0; i<4; i++)
				printf("%d.", arpheader->tpa[i]); 
			
			printf("\n"); 
		}


		if(g_ignore_ip_found &&
				arpheader->spa[0] == g_ignore_ip[0] &&
				arpheader->spa[1] == g_ignore_ip[1] &&
				arpheader->spa[2] == g_ignore_ip[2] &&
				arpheader->spa[3] == g_ignore_ip[3])
		{
			printf("Ignoring request from this IP");
		}
		else
		{
			syslog(LOG_INFO,"ARP Request from %d.%d.%d.%d",
					arpheader->spa[0],
					arpheader->spa[1],
					arpheader->spa[2],
					arpheader->spa[3]);
			syslog(LOG_INFO,"Sending Wake-On-Lan packet");
			
			char magic_packet[BUFLEN];
			make_magic_packet(g_mac_addr,magic_packet);
			send_magic_packet(magic_packet);
		}
	}
}

void daemonize()
{
	int i,lfp;
	char str[10];
	if(getppid()==1) return; /* already a daemon */
	i=fork();
	if (i<0) exit(1); /* fork error */
	if (i>0) exit(0); /* parent exits */
	/* child (daemon) continues */
	setsid(); /* obtain a new process group */
	for (i=getdtablesize();i>=0;--i) close(i); /* close all descriptors */
	i=open("/dev/null",O_RDWR); dup(i); dup(i); /* handle standart I/O */
	umask(027); /* set newly created file permissions */
	chdir(RUNNING_DIR); /* change running directory */
	//lfp=open(LOCK_FILE,O_RDWR|O_CREAT,0640);
	//if (lfp<0) exit(1); /* can not open */
	//if (lockf(lfp,F_TLOCK,0)<0) exit(0); /* can not lock */
	/* first instance continues */
	//sprintf(str,"%d\n",getpid());
	//write(lfp,str,strlen(str)); /* record pid to lockfile */
	signal(SIGCHLD,SIG_IGN); /* ignore child */
	signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);
	//signal(SIGHUP,signal_handler); /* catch hangup signal */
	//signal(SIGTERM,signal_handler); /* catch kill signal */
}

int check_args(int argc, char *argv[])
{
	int i;
	int if_found = 0, ip_found = 0, mac_found = 0, start_as_daemon = 0;

	for(i = 0; i < argc; ++i)
	{
		if(strncmp(argv[i],"-i",2) == 0)
		{
			if(argc > (i + 1))
			{
				int if_number, res;
				res = sscanf(argv[i+1],"eth%u",&if_number);
				if(res == 1)
				{
					g_if = argv[i+1];
					i = i+1;
					if_found = 1;
					printf("Interface : %s\n",g_if);
					continue;
				}
				else
				{
					printf("The interface parameter %s is invalid\n",argv[i+1]);
					return 0;
				}
			}
			else
			{
				printf("No interface parameter was present after -i option\n");
				return 0;
			}
		}

		if(strncmp(argv[i],"--ip-address",12) == 0)
		{
			if(argc > (i + 1))
			{
				if(check_for_ip_address(argv[i+1], g_ip_addr))
				{
					ip_found = 1;
					i = i+1;
					continue;
				}
				else
				{
					printf("The IP address %s is invalid\n",argv[i+1]);
					return 0;
				}
			}
			else
			{
				printf("No IP address parameter was present after --ip-address option\n");
				return 0;
			}
		}

		if(strncmp(argv[i],"--mac-address",13) == 0)
		{
			if(argc > (i + 1))
			{
				if(check_for_mac_address(argv[i+1], g_mac_addr))
				{
					mac_found = 1;
					i = i+1;
					continue;
				}
				else
				{
					printf("The MAC address %s is invalid\n",argv[i+1]);
					return 0;
				}
			}
			else
			{
				printf("No MAC address parameter was present after --mac-address option\n");
				return 0;
			}
		}

		if(strncmp(argv[i],"--ignore-ip",11) == 0)
		{
			if(argc > (i + 1))
			{
				if(check_for_ip_address(argv[i+1], g_ignore_ip))
				{
					g_ignore_ip_found = 1;
					i = i+1;
					continue;
				}
				else
				{
					printf("The IP address %s is invalid\n",argv[i+1]);
					return 0;
				}
			}
			else
			{
				printf("No IP address parameter was present after --ignore-ip option\n");
				return 0;
			}
		}


		if(strncmp(argv[i],"-d",2) == 0)
		{
			start_as_daemon = 1;
			continue;
		}

/*		if (argc < 4)
		{ 
			exit(1); 
		}
		
		
		if (!check_for_mac_address(argv[3], g_mac_addr))
		{ 
			printf("USAGE: wakeonarp <interface> <ipaddress> <macaddress>\n"); 
			exit(1); 
		}
		
		
		if (!check_for_ip_address(argv[2], g_ip_addr)){ 
			printf("USAGE: wakeonarp <interface> <ipaddress> <macaddress>\n"); 
			exit(1); 
		}*/
		
		//if(argc == 5 && strncmp(argv[4],"-d",2) == 0)
		//{
		//}
	}

	if(!if_found || !ip_found || !mac_found)
	{
		printf("Some parameters are missing\n");
		return 0;
	}

	if(start_as_daemon)
	{
		printf("Starting as daemon\n");
		daemonize();
	}

	return 1;
}

int main(int argc, char *argv[])
{
	int i;
	int count=0;
	bpf_u_int32 netaddr=0, mask=0;    /* To Store network address and netmask   */ 
	struct bpf_program filter;        /* Place to store the BPF filter program  */ 
	char errbuf[PCAP_ERRBUF_SIZE];    /* Error buffer                           */ 
	pcap_t *descr = NULL;             /* Network interface handler              */ 
	memset(errbuf,0,PCAP_ERRBUF_SIZE); 
	memset(g_ignore_ip,0,4*sizeof(int));
	g_ignore_ip_found = 0;


	if(!check_args(argc,argv))
	{
		printf("USAGE: wakeonarp -d -i <interface> --ip-address <ipaddress> --mac-address <macaddress> --ignore-ip <ip-address>\n"); 
		exit(1); 
	}

	openlog(DAEMON_NAME, LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO,"Arguments checked, starting...");
	
	if(g_ignore_ip_found)
	{
		syslog(LOG_INFO,"Configure : ignoring ARP request from %d.%d.%d.%d",
				g_ignore_ip[0],
				g_ignore_ip[1],
				g_ignore_ip[2],
				g_ignore_ip[3]);
	}

	printf("MAC and IP address :\n");

	for(i=0; i<6; i++)
	{
		printf("%x", g_mac_addr[i]);
		if(i!=5)
			printf(":");
	}

	printf("\n");

	for(i=0; i<4; i++)
	{
		printf("%d", g_ip_addr[i]);
		if(i!=3)
			printf(".");
	}
	
	printf("\n");
    

	/* Open network device for packet capture */ 
	if ((descr = pcap_open_live(g_if, MAXBYTES2CAPTURE, 0,  512, errbuf))==NULL)
	{
		fprintf(stderr, "ERROR: %s\n", errbuf);
		exit(1);
	}
    
	/* Look up info from the capture device. */ 
	if( pcap_lookupnet(g_if , &netaddr, &mask, errbuf) == -1)
	{
		fprintf(stderr, "ERROR: %s\n", errbuf);	
		exit(1);	
	}

	/* Compiles the filter expression into a BPF filter program */ 
	if ( pcap_compile(descr, &filter, "arp", 1, mask) == -1)
	{
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
		exit(1);
	}

	/* Load the filter program into the packet capture device. */ 
	if (pcap_setfilter(descr,&filter) == -1)
	{
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
		exit(1);
	}

	/* while(1){ 
	   if ( (packet = pcap_next(descr,&pkthdr)) == NULL){  /* Get one packet */ 
  /*  fprintf(stderr, "ERROR: Error getting the packet.\n", errbuf);
    exit(1);
 }*/

	syslog(LOG_INFO,"Sarting sniffing of ARP Packet");
	syslog(LOG_INFO,"Listing ARP Request for %d.%d.%d.%d",
			g_ip_addr[0],
			g_ip_addr[1],
			g_ip_addr[2],
			g_ip_addr[3]);
	pcap_loop(descr,-1,process_arp_packet,(u_char*)&count);

	closelog();

	return 0; 
}
/* EOF */
