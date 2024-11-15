#ifndef C_PACKET_JA4_H
#define C_PACKET_JA4_H

#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <openssl/sha.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CLIENT_HELLO 0x01
#define TLS_HANDSHAKE 0x16
#define PROTOCOL_TCP 't'
#define PROTOCOL_QUIC 'q'
#define PROTOCOL_DTLS 'd'
#define SUPPORTED_VERSIONS_EXT 0x002b
#define SNI_EXT 0x0000
#define ALPN_EXT 0x0010
#define SIGNATURE_ALGORITHMS_EXT 0x000d

void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet);
char *compute_truncated_sha256(const char *data, size_t len);
int parse_client_hello_for_ja4(const u_char *payload, int payload_len,
                               char *ja4_str, size_t ja4_str_len,
                               char protocol);
int is_grease_value(uint16_t val);
int compare_uint16_t(const void *a, const void *b);
void find_tls_version(uint16_t version, char *tls_version);
int run(void);


#endif
