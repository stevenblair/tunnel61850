/**
 * IEC 61850 Ethernet to UDP tunnel
 *
 * Copyright (c) 2012 Steven Blair
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

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
