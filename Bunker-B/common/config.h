#ifndef SGBOX_CONFIG_H
#define SGBOX_CONFIG_H

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif


#define BATCH_SIZE 130000

#define SNAPLENGTH 1514
#define MAX_PACKET_LEN 1500
#define MSS 20*1024 // 20KB

/* Classification */
#define IP_PROTO_TCP                  6
#define IP_PROTO_UDP                  17

#if LIVE_TRAFFIC==1
#define IP_OFFSET 14
#define TRANS_OFFSET 34
// start from L3
#define TCP_PAYLOAD_OFFSET 52 // tcpkali use 12 bytes in tcp header option field
#define UDP_PAYLOAD_OFFSET 28 // should never be used
#else
// CAIDA
#define IP_OFFSET 0
#define TRANS_OFFSET 20
#define TCP_PAYLOAD_OFFSET 40
#define UDP_PAYLOAD_OFFSET 28
#endif

/* Indexing */
#define PER_FLOW_KEYWORDS 100

/* Multithreading */
#define READY_QUEUE_CAP 3000

/* Flow timeout */
#define FLOW_TIMEOUT 10
#endif
