
#include <inttypes.h>

#define UDP_HEADER_BYTES    8
#define IP_HEADER_BYTES     20
#define ETH_HEADER_BYTES    14

#define UDP_DEFAULT_PORT    17000

#define IP_DEFAULT_TTL      100
#define IP_VERSION          0x4
#define IP_IHL              0x5
#define IP_PROTOCOL_UDP     0x11

uint8_t IP_SOURCE[4] = {192, 168, 1, 73};	// TODO: get local IP address at runtime
uint8_t IP_DEST[4] = {192, 168, 1, 255};

uint8_t ETH_SOURCE[6] = {0x00, 0x26, 0x9e, 0x53, 0x4b, 0x09};
uint8_t ETH_DEST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

typedef struct eth_header {
    uint8_t dest[6];
    uint8_t source[6];
    uint16_t ethertype;
} ETH;

typedef struct ip_header {
    uint16_t info;
    uint16_t length;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t source;
    uint32_t dest;
    ETH *eth;
} IP;

typedef struct udp_header {
    uint16_t source;
    uint16_t dest;
    uint16_t length;
    uint16_t checksum;
    IP *ip;
} UDP;

// a simple memcpy implementation, that reverses endian-ness
void reversememcpy(unsigned char *dst, const unsigned char *src, unsigned int len) {
	while (len--) {
		*dst++ = src[len];
	}
}

// copies bytes to network format (big-endian)
void netmemcpy(void *dst, const void *src, unsigned int len) {
#ifdef LITTLE_ENDIAN
	reversememcpy((unsigned char *) dst, (const unsigned char *) src, len);
#else
	memcpy((unsigned char *) dst, (const unsigned char *) src, len);
#endif
}

int encodeETH(unsigned char* data, ETH* eth, const char *payload, int payload_length) {
    int size = 0;
    
    netmemcpy(&data[size], (const void*) eth->dest, 6);
    size += sizeof eth->dest;
    netmemcpy(&data[size], (const void*) eth->source, 6);
    size += sizeof eth->dest;
    netmemcpy(&data[size], (const void*) &eth->ethertype, sizeof eth->ethertype);
    size += sizeof eth->ethertype;
    
    return size;
}

uint16_t getIPChecksum(IP *ip) {
    uint32_t sum = ip->info + ip->length + ip->id + ip->flags_frag + ((ip->ttl << 8) | (ip->protocol)) + (ip->source & 0x0000FFFF) + ((ip->source & 0xFFFF0000) >> 16) + (ip->dest & 0x0000FFFF) + ((ip->dest & 0xFFFF0000) >> 16);
    uint8_t carry = (sum & 0x000F0000) >> 16;
    
    sum = sum + carry;
    
    return ~sum;
}

int encodeIP(unsigned char* data, IP* ip, const char *payload, int payload_length) {
    int size = 0;
    
    size += encodeETH(&data[size], ip->eth, payload, payload_length);
    
    ip->length = IP_HEADER_BYTES + UDP_HEADER_BYTES + payload_length;
    //ip->checksum = 0xd06B;
    //ip->checksum = 0xcfb4;
    ip->checksum = getIPChecksum(ip);
    
    netmemcpy(&data[size], (const void*) &ip->info, sizeof ip->info);
    size += sizeof ip->info;
    netmemcpy(&data[size], (const void*) &ip->length, sizeof ip->length);
    size += sizeof ip->length;
    netmemcpy(&data[size], (const void*) &ip->id, sizeof ip->id);
    size += sizeof ip->id;
    netmemcpy(&data[size], (const void*) &ip->flags_frag, sizeof ip->flags_frag);
    size += sizeof ip->flags_frag;
    netmemcpy(&data[size], (const void*) &ip->ttl, sizeof ip->ttl);
    size += sizeof ip->ttl;
    netmemcpy(&data[size], (const void*) &ip->protocol, sizeof ip->protocol);
    size += sizeof ip->protocol;
    netmemcpy(&data[size], (const void*) &ip->checksum, sizeof ip->checksum);
    size += sizeof ip->checksum;
    netmemcpy(&data[size], (const void*) &ip->source, sizeof ip->source);
    size += sizeof ip->source;
    netmemcpy(&data[size], (const void*) &ip->dest, sizeof ip->dest);
    size += sizeof ip->dest;
    
    return size;
}

int encodeUDP(unsigned char* data, UDP* udp, const char *payload, int payload_length) {
    int size = 0;
    
    size += encodeIP(&data[size], udp->ip, payload, payload_length);
    
    udp->length = UDP_HEADER_BYTES + payload_length;
    udp->checksum = 0;
    
    netmemcpy(&data[size], (const void*) &udp->source, sizeof udp->source);
    size += sizeof udp->source;
    netmemcpy(&data[size], (const void*) &udp->dest, sizeof udp->dest);
    size += sizeof udp->dest;
    netmemcpy(&data[size], (const void*) &udp->length, sizeof udp->length);
    size += sizeof udp->length;
    netmemcpy(&data[size], (const void*) &udp->checksum, sizeof udp->checksum);
    size += sizeof udp->checksum;
    
    memcpy(&data[size], (const void*) payload, payload_length);
    size += payload_length;
    
    return size;
}

UDP *initUDP() {
    UDP *udp = (UDP*) malloc(sizeof(UDP));
    udp->ip = (IP*) malloc(sizeof(IP));
    udp->ip->eth = (ETH*) malloc(sizeof(ETH));
  
    udp->source = UDP_DEFAULT_PORT;
    udp->dest = UDP_DEFAULT_PORT;
    
    udp->ip->info = ((IP_VERSION << 12) | (IP_IHL << 8)) & 0xFFFF;
    udp->ip->id = 0;
    udp->ip->flags_frag = 0;
    udp->ip->ttl = IP_DEFAULT_TTL;
    udp->ip->protocol = IP_PROTOCOL_UDP;
    
    netmemcpy((void *) &(udp->ip->source), IP_SOURCE, 4);
    netmemcpy((void *) &(udp->ip->dest), IP_DEST, 4);
    
    memcpy((void *) (udp->ip->eth->source), ETH_SOURCE, 6);
    memcpy((void *) (udp->ip->eth->dest), ETH_DEST, 6);
    udp->ip->eth->ethertype = 0x0800;
    
    return udp;
}
