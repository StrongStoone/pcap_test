#include <stdio.h>
#include <pcap.h>

#define LINE_LEN 16

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct packet_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}packet_header;


typedef struct port_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}port_header;


void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
char source[PCAP_BUF_SIZE];

  fp = pcap_open_offline("tcpex.pcap", errbuf);
  if (fp == NULL) {
      fprintf(stderr,"\nUnable to open the file %s.\n", fp);
      return 1;
  }

    // read and dispatch packets until EOF is reached
    pcap_loop(fp, 0, dispatcher_handler, NULL);

    return 0;
}



void dispatcher_handler(u_char *temp1,
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm *ltime;
    char timestr[16];
    packet_header *pch;
    port_header *ph;
    u_int ip_len;
    u_short sport,dport;
    time_t local_tv_sec;
	int i;

    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

    /* print timestamp and length of the packet */
    printf("Time: %s.%.6d\nlen:%d\n", timestr, header->ts.tv_usec, header->len);

    /* retireve the position of the ip header */
    pch = (packet_header *) (pkt_data +
        14); //length of ethernet header
	// Source MAC Address
	printf("Source MAC Address :");
	for(i=6;i<12; i++) printf("%02X ", pkt_data[i]);
	printf("\n");
	// Destination MAC Address
	printf("Destination MAC Address :");
	for(i=0;i<6; i++) printf("%02X ", pkt_data[i]);
	printf("\n");

    /* retireve the position of the tcp header */
    ip_len = (pch->ver_ihl & 0xf) * 4;
    ph = (port_header *) ((u_char*)pch + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs( ph->sport );
    dport = ntohs( ph->dport );

    /* print ip addresses and tcp ports */
    printf("Source: %d.%d.%d.%d/%d -> Destination: %d.%d.%d.%d/%d\n",
        pch->saddr.byte1,
        pch->saddr.byte2,
        pch->saddr.byte3,
        pch->saddr.byte4,
        sport,
        pch->daddr.byte1,
        pch->daddr.byte2,
        pch->daddr.byte3,
        pch->daddr.byte4,
        dport);

}
