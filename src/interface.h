
#ifndef INTERFACE_H_
#define INTERFACE_H_

#ifdef _WIN32
	#define WPCAP
	#define HAVE_REMOTE
	#define WIN32_LEAN_AND_MEAN
	#define LITTLE_ENDIAN
#endif

#include <pcap.h>
#include <stdlib.h>

extern unsigned char bufIn[2048];
extern unsigned char bufOut[2048];

extern pcap_t *fp;

void start();
void stop();
int sendPacket(unsigned char *buf, int len);
int readPacket();
int setCallback(void (*packet_handler)(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data));

#endif /* INTERFACE_H_ */
