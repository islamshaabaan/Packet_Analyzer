/**
 * @file packet_parser.c
 * @brief Packet parsing implementation with protocol classification
 */

#include "packet_parser.h"

void init_packet_stats(packet_stats_t *stats)
{
   atomic_init(&stats->tcp_count, 0);
   atomic_init(&stats->udp_count, 0);
   atomic_init(&stats->icmp_count, 0);
   atomic_init(&stats->other_count, 0);
   atomic_init(&stats->total_packets, 0);
}

int get_packet_protocol(const unsigned char *packet)
{
   
   /* Check for NULL packet */
   if (packet == NULL )
   {
      return INVALID_PACKET;
   }
   
   const struct eth_header *eth = (struct eth_header *)packet;
   
   /* Check for IP packets (0x0800 in network byte order) or truncated Ethernet header in unit test case only */
   if (ntohs(eth->ether_type) != ETHERTYPE_IP)
   {
      return OTHER_PROTOCOL_TYPE; /* Not an IP packet */
   }

   /* Get IP header (after Ethernet header = skip 14 byte) */
   const struct iphdr *ip_hdr = (struct iphdr *)(packet + ETHERNET_HEADER_LEN);

   /* Validate IP header length and version IPv4 */
   if (ip_hdr->ihl < MIN_IP_HEADER_LEN || ip_hdr->version != IP_VERSION_4)
   {
      return INVALID_PACKET;
   }

   return ip_hdr->protocol; /* Return protocol number */
}

void process_packet(const unsigned char *packet, packet_stats_t *stats)
{
   atomic_fetch_add(&stats->total_packets, 1);

   switch (get_packet_protocol(packet))
   {
   case IPPROTO_TCP:
      atomic_fetch_add(&stats->tcp_count, 1);
      break;
   case IPPROTO_UDP:
      atomic_fetch_add(&stats->udp_count, 1);
      break;
   case IPPROTO_ICMP:
      atomic_fetch_add(&stats->icmp_count, 1);
      break;
   case OTHER_PROTOCOL_TYPE:
      atomic_fetch_add(&stats->other_count, 1);
      break;
   default:
      /* These are counted in total_packets but not in protocol-specific counts */
      break;
   }
}

void print_stats(const packet_stats_t *stats)
{
   unsigned int total = atomic_load(&stats->total_packets);
   unsigned int tcp = atomic_load(&stats->tcp_count);
   unsigned int udp = atomic_load(&stats->udp_count);
   unsigned int icmp = atomic_load(&stats->icmp_count);
   unsigned int other = atomic_load(&stats->other_count);

   /* Get memory usage */
   struct rusage usage;
   getrusage(RUSAGE_SELF, &usage);

   printf("Packets captured: %u\n", total);
   printf("TCP: %u (%.1f%%)\n", tcp, total ? (tcp * 100.0) / total : 0.0);
   printf("UDP: %u (%.1f%%)\n", udp, total ? (udp * 100.0) / total : 0.0);
   printf("ICMP: %u (%.1f%%)\n", icmp, total ? (icmp * 100.0) / total : 0.0);
   printf("Other: %u (%.1f%%)\n", other, total ? (other * 100.0) / total : 0.0);
   printf("Memory usage: %.1f KB\n", usage.ru_maxrss / 1024.0); 
   printf("=======================\n");
}
