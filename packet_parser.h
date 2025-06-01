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

/* Error codes */
#define ERROR_RETURN -1
#define OTHER_PROTOCOL_TYPE -1
#define INVALID_PACKET -2

/* Timing constants */
#define SLEEP_INTERVAL_SEC 5
#define PCAP_TIMEOUT_MS    1000

/* Network protocol constants */
#define MIN_IP_HEADER_LEN  5
#define IP_VERSION_4 4
#define ETHERNET_HEADER_LEN 14
#define ETHERTYPE_IP 0x0800
#define SNAP_LEN 1518  // Maximum bytes per packet, Safe for Ethernet with full headers

/* Capture settings */
#define ALL_AVAILABLE_PACKETS -1
#define PROCESS_PACKETS_NUMBER 100
#define PROMISC_MODE 1
#define NOT_FILTER_OPTIMIZE 0

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
 * @brief Initialize statistics counters to zero
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
 * @brief Safely identify packet protocol type
 * @param packet Pointer to packet data starting from Ethernet header
 * @return Protocol type (IPPROTO_TCP/IPPROTO_UDP/IPPROTO_ICMP) or OTHER_PROTOCOL_TYPE  if not IP or invalid
 */
int get_packet_protocol(const unsigned char *packet);

/**
 * @brief Print current statistics
 * @param stats Pointer to statistics structure
 */
void print_stats(const packet_stats_t *stats);

#endif /* PACKET_PARSER_H */