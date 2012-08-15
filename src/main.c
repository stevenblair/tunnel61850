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

#define REMOVE_ETHERNET_FRAME	1

#include "interface.h"
#include "udp.h"

UDP *udp;
unsigned char bufOut[2048] = {0};

// filters GOOSE and SV packets which use the recommended MAC address ranges, and forwards via UDP
void gse_sv_packet_filter(unsigned char *buf, int len) {
	int lenOut = 0;
	int offset = 0;

	if (len >= 64) {

#if REMOVE_ETHERNET_FRAME == 1
		offset = 14;

		// check for VLAN tag
		if (buf[12] == 0x81 && buf[13] == 0x00) {
			offset = 18;
		}
#endif

		// GOOSE: 01-0C-CD-01-00-00 to 01-0C-CD-01-01-FF
		// SV:    01-0C-CD-04-00-00 to 01-0C-CD-04-01-FF
		if (buf[0] == 0x01 && buf[1] == 0x0C && buf[2] == 0xCD) {
			if (buf[3] == 0x01 || buf[3] == 0x04) {
				lenOut = encodeUDP(bufOut, udp, (const char*) &buf[offset], len - offset);
			}
		}

		if (lenOut > 0) {
			sendPacket(bufOut, lenOut);
		}
	}
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    gse_sv_packet_filter((unsigned char *) pkt_data, header->len);
}

int main() {
	udp = initUDP();

	start();

	int status = 0;
	while (status == 0) {
		status = setCallback(&packet_handler);
	}

	return 0;
}
