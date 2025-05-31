/**
 * @file test_parser.c
 * @brief Unit tests for packet parser
 */

#include "packet_parser.h"
#include <assert.h>
#include <string.h>

void test_protocol_identification()
{
   /* Test TCP packet */
   unsigned char tcp_packet[] = {
       /* Ethernet */
       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* dst */
       0x00, 0x11, 0x22, 0x33, 0x44, 0x55, /* src */
       0x08, 0x00,                         /* IP */
       /* IP */
       0x45, 0x00, 0x00, 0x00, /* ver/ihl */
       0x00, 0x00, 0x40, 0x00, /* flags */
       0x40, 0x06, 0x00, 0x00, /* proto=TCP */
       0x00, 0x00, 0x00, 0x00, /* src ip */
       0x00, 0x00, 0x00, 0x00  /* dst ip */
   };

   assert(get_packet_protocol(tcp_packet) == IPPROTO_TCP);

   /* Modify to UDP */
   tcp_packet[23] = 0x11;
   assert(get_packet_protocol(tcp_packet) == IPPROTO_UDP);

   /* Modify to ICMP */
   tcp_packet[23] = 0x01;
   assert(get_packet_protocol(tcp_packet) == IPPROTO_ICMP);

   printf("Protocol identification tests passed\n");
}

void test_packet_processing()
{
   packet_stats_t stats;
   init_packet_stats(&stats);

   unsigned char packet[60] = {0};
   /* Make it an IP packet */
   packet[12] = 0x08;
   packet[13] = 0x00;
   /* Set IP header length and version */
   packet[14] = 0x45;

   /* TCP test */
   packet[23] = 0x06;
   process_packet(packet, &stats);
   assert(stats.tcp_count == 1);

   /* UDP test */
   packet[23] = 0x11;
   process_packet(packet, &stats);
   assert(stats.udp_count == 1);

   printf("Packet processing tests passed\n");
}

void test_edge_cases()
{
   packet_stats_t stats;
   init_packet_stats(&stats);

   printf("\nEdge Case Tests:\n");

   /* Test 1: Empty packet */
   unsigned char empty_packet[1] = {0};
   process_packet(empty_packet, &stats);
   assert(stats.other_count == 1);
   printf("✓ Handles empty packet\n");

   /* Test 2: Truncated Ethernet header */
   unsigned char short_eth[10] = {0}; // <14 bytes
   process_packet(short_eth, &stats);
   assert(stats.other_count == 2);
   printf("✓ Handles truncated Ethernet header\n");
   /* Test 3: Non-IP packet (ARP) */
   unsigned char arp_packet[60] = {0};
   arp_packet[12] = 0x08;
   arp_packet[13] = 0x06; // ARP type
   process_packet(arp_packet, &stats);
   assert(stats.other_count == 3);
   printf("✓ Handles non-IP packets\n");

   /* Test 4: Malformed IP header (invalid version) */
   unsigned char bad_ver_packet[60] = {0};
   // Ethernet
   bad_ver_packet[12] = 0x08;
   bad_ver_packet[13] = 0x00; // IP type
   // IP header
   bad_ver_packet[14] = 0x60; // Version=6, IHL=0 (invalid)
   process_packet(bad_ver_packet, &stats);
   assert(stats.other_count == 4);
   printf("✓ Handles invalid IP version\n");

   /* Test 5: Invalid IP header length */
   unsigned char bad_len_packet[60] = {0};
   // Ethernet
   bad_len_packet[12] = 0x08;
   bad_len_packet[13] = 0x00;
   // IP header
   bad_len_packet[14] = 0x44; // Version=4, IHL=4 (<5)
   process_packet(bad_len_packet, &stats);
   assert(stats.other_count == 5);
   printf("✓ Handles invalid IP header length\n");

   /* Test 6: Truncated IP packet */
   unsigned char truncated_ip[30] = {0}; // < min Ethernet+IP headers
   truncated_ip[12] = 0x08;
   truncated_ip[13] = 0x00;
   truncated_ip[14] = 0x45; // Valid IP v4, IHL=5
   process_packet(truncated_ip, &stats);
   assert(stats.other_count == 6);
   printf("✓ Handles truncated IP packets\n");
}

int main()
{
   test_protocol_identification();
   test_packet_processing();
   test_edge_cases();
   return 0;
}