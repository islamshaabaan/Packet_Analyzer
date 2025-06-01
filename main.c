/**
 * @file main.c
 * @brief Network packet analyzer program
 * 
 * Captures packets on a specified interface, classifies them by protocol,
 * and displays statistics every 5 seconds.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h> 
#include <time.h>
#include <pthread.h>
#include <getopt.h>

#include "packet_parser.h"

/* Arguments configurations for args parsing handling */
typedef struct
{
   char *interface;
   char *filter_exp;
   unsigned int duration;
} config_t;

/* Global state for signal handling */
typedef struct {
    volatile sig_atomic_t stop_capture;
    time_t start_time;
    unsigned int duration;
    pcap_t *handle;
    packet_stats_t *stats;
} app_state_t;

static app_state_t global_state = {0};

/**
 * @brief Signal handler for graceful shutdown
 * @param sig Signal number
 */
void signal_handler(int sig)
{
   printf("\nReceived signal %d, Shutting down...\n", sig);
   global_state.stop_capture = 1;

   if (global_state.handle)
   {
      pcap_breakloop(global_state.handle);  // Force pcap_dispatch to exit
   }
}

/**
 * @brief Packet handler callback for libpcap
 */
void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{ 
   packet_stats_t *stats = (packet_stats_t *)user;
   size_t packet_length = pkthdr->caplen;
   if (packet_length < ETHERNET_HEADER_LEN)
   {
      // Truncated Ethernet header
      printf("Truncated Ethernet header: %zu bytes\n", packet_length);
      return;
   }
   process_packet(packet, stats);
}

void parse_args(int argc, char **argv, config_t *config)
{
   int opt;
   config->interface = NULL;
   config->filter_exp = NULL;
   config->duration = -1;

   while ((opt = getopt(argc, argv, "i:f:t:")) != ERROR_RETURN)
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

/**
 * @brief Thread function for periodic statistics display - runs every 5 seconds
 * @param arg Pointer to packet_stats_t structure
 * @return NULL
 */
void *stats_timer_thread(void *arg)
{
   packet_stats_t *stats = (packet_stats_t *)arg;

   struct timespec next_time;
   clock_gettime(CLOCK_MONOTONIC, &next_time); // Set initial time

   while (!global_state.stop_capture)
   {
      next_time.tv_sec += SLEEP_INTERVAL_SEC ;
      clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next_time, NULL);
      
      /* Only print if we're not shutting down */
      if (!global_state.stop_capture) 
      {
         print_stats(stats);
      }
      
      /* Check if duration limit reached */
      if (global_state.duration > 0 && (time(NULL) - global_state.start_time) >= global_state.duration) 
      {   
         printf("\nCapture duration reached: %d seconds. Stopping capture...\n", global_state.duration);
         global_state.stop_capture = 1; // Stop capture after duration
         
         if (global_state.handle) 
         {
            pcap_breakloop(global_state.handle);
         }
         
         break; // Exit if duration reached
      }
   }

   return NULL;
}

/**
 * @brief Run the main capture loop
 * @return 0 on success, non-zero on error
 */
int run_capture_loop(pcap_t *handle, packet_stats_t *stats, int duration, const char *interface)
{
   pthread_t timer_thread;

   /* Initialize global state */
   global_state.start_time = time(NULL);
   global_state.duration = duration;
   global_state.handle = handle;
   global_state.stats = stats;
   global_state.stop_capture = 0;

   /* Create statistics timer thread */
   if (pthread_create(&timer_thread, NULL, stats_timer_thread, stats) != 0)
   {
      perror("Failed to create timer thread");
      
      return EXIT_FAILURE;
   }

   while (!global_state.stop_capture)
   {
      /* Dispatch PROCESS_PACKETS_NUMBER packets at a time to avoid blocking, 
      But if want to process all available packets, use ALL_AVAILABLE_PACKETS */
      if (pcap_dispatch(handle, PROCESS_PACKETS_NUMBER, packet_handler, (unsigned char *)stats) == ERROR_RETURN)
      {
         fprintf(stderr, "Capture error on %s: %s\n", interface, pcap_geterr(handle));
         break;
      }
   }

   /* Cleanup */
   pthread_join(timer_thread, NULL);

   time_t elapsed = time(NULL) -  global_state.start_time;
   printf("\nFinal Statistics:\n");
   printf("[%ld seconds elapsed]\n", elapsed);
   print_stats(stats);
   
   return 0;
}

int main(int argc, char *argv[])
{
   config_t config;
   parse_args(argc, argv, &config);

   /* Initialize pcap */
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *handle = pcap_open_live(config.interface, SNAP_LEN, PROMISC_MODE, PCAP_TIMEOUT_MS, errbuf);
   
   if (!handle)
   {
      fprintf(stderr, "Couldn't open device interface %s: %s\n", config.interface, errbuf);

      return EXIT_FAILURE;
   }

   /* Apply filter if specified */
   if (config.filter_exp)
   {
      struct bpf_program fp;
      if (pcap_compile(handle, &fp, config.filter_exp, NOT_FILTER_OPTIMIZE, PCAP_NETMASK_UNKNOWN) == ERROR_RETURN || 
            pcap_setfilter(handle, &fp) == ERROR_RETURN)
      {
         fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
         pcap_close(handle);

         return EXIT_FAILURE;
      }

      pcap_freecode(&fp);
   }

   /* Initialize statistics and signal handling */
   packet_stats_t stats;
   init_packet_stats(&stats);

   signal(SIGINT, signal_handler);

   printf("Packet Analyzer (E-VAS Tel Team)\n---------------------------------\n");
   printf("Interface: %s\n", config.interface);
   printf("Buffer Size: %d packets\n", PROCESS_PACKETS_NUMBER);
   printf("Filter: %s\n", config.filter_exp ? config.filter_exp : "none");
   printf("Duration: %d seconds\n", config.duration > 0 ? config.duration : 0);
   printf("Output File: %s\n", "none");

   printf("\n");

   int ret = run_capture_loop(handle, &stats, config.duration, config.interface);
   
   /* Cleanup */
   pcap_close(handle);
   printf("\nPacket analyzer terminated.\n");

   return ret;
}
