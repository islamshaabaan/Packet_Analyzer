/**
 * @file packet_parser.h
 * @brief Network packet parsing and statistics header
 */

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <stdatomic.h>
#include <sys/resource.h> // For memory usage tracking

/* Ethernet header 14 Bytes */
struct eth_header
{
   unsigned char ether_dhost[6]; /* Destination host address */
   unsigned char ether_shost[6]; // Source host address
   unsigned short ether_type;    // IP? ARP? RARP? etc
};

/* Packet statistics structure */
typedef struct
{
   _Atomic unsigned int tcp_count;
   _Atomic unsigned int udp_count;
   _Atomic unsigned int icmp_count;
   _Atomic unsigned int other_count;
   _Atomic unsigned int total_packets;
} packet_stats_t;

/* Function prototypes */

/**
 * @brief Initialize statistics structure
 * @param stats Pointer to statistics structure
 */
void init_packet_stats(packet_stats_t *stats);

/**
 * @brief Process a network packet and update statistics
 * @param packet Pointer to packet data
 * @param stats Pointer to statistics structure
 */
void process_packet(const unsigned char *packet, packet_stats_t *stats);

/**
 * @brief Identify packet protocol type
 * @param packet Pointer to packet data
 * @return Protocol type (IPPROTO_TCP/IPPROTO_UDP/IPPROTO_ICMP) or -1 if not IP
 */
int get_packet_protocol(const unsigned char *packet);

/**
 * @brief Print current statistics
 * @param stats Pointer to statistics structure
 */
void print_stats(const packet_stats_t *stats);

#endif /* PACKET_PARSER_H */