/**
 * @file packet_parser.c
 * @brief Packet parsing implementation
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
   const struct eth_header *eth = (struct eth_header *)packet;

   /* Check for IP packets (0x0800 in network byte order) */
   if (ntohs(eth->ether_type) != 0x0800)
   {
      return -1; /* Not an IP packet */
   }

   /* Get IP header (after Ethernet header = skip 14 byte) */
   const struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct eth_header));

   /* Validate IP header length and version IPv4 */
   if (ip_hdr->ihl < 5 || ip_hdr->version != 4)
   {
      return -1;
   }

   return ip_hdr->protocol; /* Return protocol number */
}

void process_packet(const unsigned char *packet, packet_stats_t *stats)
{
   stats->total_packets++;

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
   default:
      atomic_fetch_add(&stats->other_count, 1);
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

   struct rusage usage;
   getrusage(RUSAGE_SELF, &usage);

   printf("Packets captured: %u\n", total);
   printf("TCP: %u (%.1f%%)\n", tcp, total ? (tcp * 100.0) / total : 0.0);
   printf("UDP: %u (%.1f%%)\n", udp, total ? (udp * 100.0) / total : 0.0);
   printf("ICMP: %u (%.1f%%)\n", icmp, total ? (icmp * 100.0) / total : 0.0);
   printf("Other: %u (%.1f%%)\n", other, total ? (other * 100.0) / total : 0.0);
   printf("Memory usage: %.1ld KB\n", usage.ru_maxrss); // Convert to KB like in example
   printf("=======================\n");
}
