/**
 * @file main.c
 * @brief Packet counter main program
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h> // For clock_gettime()
#include <time.h>
#include <getopt.h>

#include "packet_parser.h"

volatile sig_atomic_t stop_capture = 0;

void signal_handler(int sig)
{
   stop_capture = 1;
   printf("\nReceived signal %d, Shutting down...\n", SIGINT);
}

/**
 * @brief Packet handler callback for libpcap
 */
void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
   packet_stats_t *stats = (packet_stats_t *)user;
   process_packet(packet, stats);
}

typedef struct
{
   char *interface;
   char *filter_exp;
   unsigned int duration;
} config_t;

void parse_args(int argc, char **argv, config_t *config)
{
   int opt;
   config->interface = NULL;
   config->filter_exp = NULL;
   config->duration = -1;

   while ((opt = getopt(argc, argv, "i:f:t:")) != -1)
   {
      switch (opt)
      {
      case 'i':
         config->interface = optarg;
         break;
      case 'f':
         config->filter_exp = optarg;
         break;
      case 't':
         config->duration = atoi(optarg);
         if (config->duration <= 0)
         {
            fprintf(stderr, "Duration must be a positive integer\n");
            exit(EXIT_FAILURE);
         }
         break;
      default:
         fprintf(stderr, "Usage: %s -i <interface> [-f <filter>] [-t <seconds>]\n", argv[0]);
         exit(EXIT_FAILURE);
      }
   }

   if (!config->interface)
   {
      fprintf(stderr, "Error: Network interface (-i) is required.\n");
      exit(EXIT_FAILURE);
   }
}

int main(int argc, char *argv[])
{
   config_t config;
   parse_args(argc, argv, &config);

   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *handle = pcap_open_live(config.interface, BUFSIZ, 1, 1000, errbuf);
   if (!handle)
   {
      fprintf(stderr, "Couldn't open device interface %s: %s\n", config.interface, errbuf);
      
      return EXIT_FAILURE;
   }

   if (config.filter_exp)
   {
      struct bpf_program fp;
      if (pcap_compile(handle, &fp, config.filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1)
      {
         fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
         pcap_close(handle);

         return EXIT_FAILURE;
      }

      pcap_freecode(&fp);
   }

   packet_stats_t stats;
   init_packet_stats(&stats);

   signal(SIGINT, signal_handler);

   printf("Packet Analyzer (E-VAS Tel Team)\n---------------------------------\n");
   printf("Interface: %s\n", config.interface);
   printf("Buffer Size: %d packet\n", BUFSIZ);
   printf("Filter: %s\n", config.filter_exp ? config.filter_exp : "none");
   printf("Duration: %d seconds\n", config.duration > 0 ? config.duration : 0);
   printf("Output File: %s\n", "none");

   printf("\n");

   time_t start_time = time(NULL);
   
   struct timespec next_print; // Stores the exact timestamp for the next statistics print
   clock_gettime(1, &next_print); // Initialize first print time, CLOCK_MONOTONIC: Uses a steady clock (unaffected by system time changes)
   
   if(pcap_setnonblock(handle, 1, errbuf)== -1)
   {
      fprintf(stderr, "Couldn't Set non blocking mode as: %s\n", errbuf);
      pcap_close(handle);

      return EXIT_FAILURE;
   }
   
   while (!stop_capture)
   {  
      // Process packets (returns immediately if none)
      if (pcap_dispatch(handle, 100, packet_handler, (unsigned char *)&stats) == -1)
      {
         fprintf(stderr, "Capture Error: %s\n", pcap_geterr(handle));
         break;
      }

      struct timespec now;
      clock_gettime(1, &now);

      if ((now.tv_sec - next_print.tv_sec) >= 5)
      {
         print_stats(&stats);

         // Set next print time to exact 5-second intervals
         next_print.tv_sec += 5;
         next_print.tv_nsec = 0; // Reset nanoseconds to zero
      }
      
      // Small sleep to prevent CPU overload
      struct timespec sleep_time = {0, 1000000}; // 1ms
      nanosleep(&sleep_time, NULL);
      
      if (config.duration > 0 && (time(NULL) - start_time) >= config.duration)
      {
         break;
      }
   }

   // Final statistics
   time_t elapsedt = time(NULL) - start_time;

   printf("\nFinal Statistics:\n");
   printf("[%ld seconds elapsed]\n", elapsedt);
   print_stats(&stats);

   // Clean up
   pcap_close(handle);
   printf("\nPacket analyzer terminated.\n");
}
