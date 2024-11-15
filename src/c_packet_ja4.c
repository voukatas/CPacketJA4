// currently working only for ethernet & lo interface & ipv4/ipv6.
// ToDo: - I need to figure out the tcp reassembly
//       - Investigate further the IPv6 extensions
//       - Implement UDP/QUIC functionality
//
//
// gcc main.c -o main -lpcap -lssl -lcrypto && sudo ./main
// sudo apt install libpcap-dev libssl-dev
//
//
#ifndef DEBUG
#define DEBUG 1
#endif

#ifdef TESTING
// #warning "testing enabled"
#undef DEBUG
#define DEBUG 0
#endif
#include "../include/c_packet_ja4.h"

int run(void) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf);
  // pcap_t *handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
  //       if (handle == NULL) {
  //         fprintf(stderr, "Could not open device: %s\n", errbuf);
  //         return 1;
  //       }
  //      pcap_t *handle = pcap_open_offline("pcap/badcurveball.pcap", errbuf);
  //       pcap_t *handle = pcap_open_offline("pcap/browsers-x509.pcapng",
  //       errbuf); pcap_t *handle =
  //           pcap_open_offline("pcap/chrome-cloudflare-quic-with-secrets.pcapng",
  //                             errbuf); // tcp/ipv6 | quic also
  //       pcap_t *handle = pcap_open_offline("pcap/dtls-udp.notest.cap",
  //       errbuf);
  //       //
  //       ====================== dtls not working
  //       pcap_t *handle = pcap_open_offline("pcap/http2-with-cookies.pcapng",
  //       errbuf);
  //       pcap_t *handle = pcap_open_offline("pcap/ipv6.pcapng", errbuf); //
  //       ======================= not working no ethernet headers only lo
  //       pcap_t *handle =
  //           pcap_open_offline("pcap/latest.pcapng",
  //                             errbuf); // ipv4 udp quic not working all the
  //                             others ok
  //       pcap_t *handle = pcap_open_offline("pcap/macos_tcp_flags.pcap",
  //       errbuf); pcap_t *handle =
  //       pcap_open_offline("pcap/quic-tls-handshake.pcapng", errbuf); // not
  //       working - probably invalid pcap pcap_t *handle =
  //       pcap_open_offline("pcap/quic-with-several-tls-frames.pcapng",
  //       errbuf);
  //       // not working - quic pcap_t *handle =
  //       pcap_open_offline("pcap/tls-alpn-h2.pcap", errbuf); // not working
  //       loopback
  // pcap_t *handle = pcap_open_offline("pcap/tls-handshake.pcapng", errbuf);
  // pcap_t
  //        *handle = pcap_open_offline("pcap/tls-non-ascii-alpn.pcapng",
  //        errbuf); pcap_t *handle =
  //        pcap_open_offline("pcap/tls-sni.pcapng", errbuf); pcap_t *handle
  //        = pcap_open_offline("pcap/tls3.pcapng", errbuf);
  // pcap_t *handle = pcap_open_offline("pcap/tls12.pcap", errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Could not open pcap file: %s\n", errbuf);
    return 1;
  }

  // Get the data link type
  int link_type = pcap_datalink(handle);

  // Check if it's Ethernet
  if (link_type == DLT_EN10MB) { // Ethernet
    printf("This is an Ethernet interface\n");
  } else if (link_type == DLT_NULL) {
    printf("This is a Loopback interface\n");
    // ip_packet = packet + 4;
    return -1;
  } else {
    printf("This is not an Ethernet interface. Link type: %d\n", link_type);
    return -1;
  }

  pcap_loop(handle, 0, packet_handler, NULL);
  pcap_close(handle);
  return 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet) {
  (void)args;

  // Define Ethernet header length
  int ethernet_header_length = 14;

  // Ensure the packet is large enough to contain Ethernet header
  if (header->caplen < (bpf_u_int32)ethernet_header_length) {
    return;
  }

  // Extract the Ethernet type field (bytes 12 and 13)
  uint16_t eth_type = ntohs(*(uint16_t *)(packet + 12));
  // printf("eth_type: %d\n", eth_type);

  // Initialize pointers
  const u_char *ip_packet = NULL;
  size_t ip_header_length = 0;

  // Check for IPv4
  if (eth_type == 0x0800) {
    ip_packet = packet + ethernet_header_length;

    // Ensure the packet is large enough to contain IPv4 header
    if (header->caplen <
        (bpf_u_int32)(ethernet_header_length + sizeof(struct ip))) {
      return;
    }

    struct ip *iph = (struct ip *)ip_packet;
    // default is 20 bytes
    ip_header_length = iph->ip_hl * 4; // mul by 4 to convert this to bytes

    // Validate IPv4 header length
    if (ip_header_length < 20) {
      return;
    }

    // Identify the protocol
    uint8_t protocol = iph->ip_p;

    if (protocol == IPPROTO_TCP) {
      // Process TCP packet
      struct tcphdr *tcph = (struct tcphdr *)(ip_packet + ip_header_length);
      int tcp_header_length = tcph->th_off * 4;

      // Calculate payload offset and length
      const u_char *tcp_payload =
          ip_packet + ip_header_length + tcp_header_length;
      int payload_len = header->caplen - (ethernet_header_length +
                                          ip_header_length + tcp_header_length);

      // Ensure payload is large enough for TLS handshake
      if (payload_len > 5 && tcp_payload[0] == TLS_HANDSHAKE &&
          tcp_payload[5] == CLIENT_HELLO) {
#if DEBUG
        printf("IPv4 TCP Client Hello detected.\n");
        printf(
            "payload len %d  header->caplen %d - ehternet_header_length %d - "
            "ipheader_len %ld - tcp_header_len %d\n",
            payload_len, header->caplen, ethernet_header_length,
            ip_header_length, tcp_header_length);
#endif

        char ja4_str[512] = "";
        if (parse_client_hello_for_ja4(tcp_payload, payload_len, ja4_str,
                                       sizeof(ja4_str), PROTOCOL_TCP) == 0) {
          printf("JA4 Fingerprint: %s\n", ja4_str);
        }
      }
    } else if (protocol == IPPROTO_UDP) {
#if DEBUG
      printf("UDP IPv4 Needs Proper Implementation\n");
#endif
      return;
      // Process UDP packet
    }
  } else if (eth_type == 0x86DD) { // Check for IPv6
    ip_packet = packet + ethernet_header_length;

    // Ensure the packet is large enough to contain IPv6 header
    if (header->caplen < ethernet_header_length + sizeof(struct ip6_hdr)) {
      return;
    }

    struct ip6_hdr *ip6h = (struct ip6_hdr *)ip_packet;
    ip_header_length = 40; // IPv6 header is fixed at 40bytes

    // Next header
    uint8_t next_header = ip6h->ip6_nxt;
    const u_char *payload_ptr = ip_packet + ip_header_length;
    size_t payload_len =
        header->caplen - (ethernet_header_length + ip_header_length);

    // Handle extension headers (needs further investigation)
    while (1) {
      if (next_header == IPPROTO_HOPOPTS || next_header == IPPROTO_ROUTING ||
          next_header == IPPROTO_DSTOPTS || next_header == IPPROTO_FRAGMENT ||
          next_header == IPPROTO_AH || next_header == IPPROTO_NONE) {
        if (payload_len < 2) {
          break; // Not enough data for extension header
        }
        uint8_t ext_len = payload_ptr[1];
        size_t ext_total_len = (ext_len + 1) * 8;
        if (payload_len < ext_total_len) {
          break; // Not enough data
        }
        next_header = payload_ptr[0];
        payload_ptr += ext_total_len;
        payload_len -= ext_total_len;
      } else {
        break;
      }
    }

    // Next_header should be the transport layer protocol
    if (next_header == IPPROTO_TCP) {
      // Process TCP packet
      struct tcphdr *tcph = (struct tcphdr *)payload_ptr;
      int tcp_header_length = tcph->th_off * 4;

      // Calculate payload offset and length
      const u_char *tcp_payload = payload_ptr + tcp_header_length;
      int tcp_payload_len = payload_len - tcp_header_length;

      // Ensure payload is large enough for TLS handshake
      if (tcp_payload_len > 5 && tcp_payload[0] == TLS_HANDSHAKE &&
          tcp_payload[5] == CLIENT_HELLO) {
#if DEBUG
        printf("IPv6 TCP Client Hello detected.\n");
#endif
        char ja4_str[512] = "";
        if (parse_client_hello_for_ja4(tcp_payload, tcp_payload_len, ja4_str,
                                       sizeof(ja4_str), PROTOCOL_TCP) == 0) {
          printf("JA4 Fingerprint: %s\n", ja4_str);
        }
        // printf("JA4 Fingerprint: %s\n", ja4_str);
      }
    } else if (next_header == IPPROTO_UDP) {
#if DEBUG
      printf("UDP IPv6 Needs Proper Implementation\n");
#endif
      return;
      // Process UDP packet
    }
  } else {
    // Unsupported Ethernet type
    return;
  }
}

// Compute truncated SHA256 and return as a hex string
char *compute_truncated_sha256(const char *data, size_t len) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256((const unsigned char *)data, len, hash);

  char *truncated_hash = malloc(13);
  if (truncated_hash == NULL) {
    fprintf(stderr, "Failed to allocate memory for truncated hash\n");
    return NULL;
  }
  for (int i = 0; i < 6; i++) {
    sprintf(&truncated_hash[i * 2], "%02x", hash[i]);
  }
  truncated_hash[12] = '\0';

  return truncated_hash;
}

// Same calculation as in the wireshark module
int is_grease_value(uint16_t val) {
  return ((val & 0x0f0f) == 0x0a0a) && ((val >> 8) == (val & 0xff));
}

int compare_uint16_t(const void *a, const void *b) {
  uint16_t val_a = *(const uint16_t *)a;
  uint16_t val_b = *(const uint16_t *)b;
  if (val_a < val_b)
    return -1;
  else if (val_a > val_b)
    return 1;
  else
    return 0;
}

int parse_client_hello_for_ja4(const u_char *payload, int payload_len,
                               char *ja4_str, size_t ja4_str_len,
                               char protocol) {
  if (payload_len < 0) {
    return -1;
  }

  int offset = 0;

  // Skip TLS record header
  offset += 5;

  if (offset + 4 > payload_len) {
    return -1;
  }

  uint8_t handshake_type = payload[offset];
  uint32_t handshake_length = (payload[offset + 1] << 16) |
                              (payload[offset + 2] << 8) | payload[offset + 3];
  offset += 4;

  if (handshake_type != CLIENT_HELLO) {
    return -1;
  }

#if DEBUG
  printf("offset %d + handshake len %d > payload_len %d\n", offset,
         handshake_length, payload_len);
#endif

  if (offset + handshake_length > (size_t)payload_len) {
    return -1;
  }

  // Protocol
  snprintf(ja4_str + strlen(ja4_str), ja4_str_len - strlen(ja4_str), "%c",
           protocol);

  // Client Version
  uint16_t client_version = (payload[offset] << 8) | payload[offset + 1];
  offset += 2;

  // Initialize TLS Version
  char tls_version[3] = "00";

  // Skip Random Field
  offset += 32;

  // Session ID
  if (offset + 1 > payload_len) {
    return -1;
  }

  uint8_t session_id_len = payload[offset];
  offset += 1 + session_id_len;

  // Cipher Suites
  if (offset + 2 > payload_len) {
    return -1;
  }

  uint16_t cipher_suites_len = (payload[offset] << 8) | payload[offset + 1];
  offset += 2;

  if (offset + cipher_suites_len > payload_len) {
    return -1;
  }

  size_t cipher_count = 0;
  uint16_t ciphers[256];

  for (size_t i = 0; i < cipher_suites_len && i < sizeof(ciphers) * 2; i += 2) {
    uint16_t cipher = (payload[offset + i] << 8) | payload[offset + i + 1];
    if (!is_grease_value(cipher)) {
      ciphers[cipher_count++] = cipher;
    }
  }
  offset += cipher_suites_len;

  // Compression Methods
  if (offset + 1 > payload_len) {
    return -1;
  }

  uint8_t compression_methods_len = payload[offset];
  offset += 1 + compression_methods_len;

  // Extensions
  if (offset + 2 > payload_len) {
    return -1;
  }

  uint16_t extensions_len = (payload[offset] << 8) | payload[offset + 1];
  offset += 2;

  int extension_count = 0;
  uint16_t extensions[256];
  int extension_count_with_sni_alpn = 0;
  int sni_found = 0;
  char alpn[5] = "00";

  int sig_algo_count = 0;
  uint16_t signature_algorithms[256];
  int supported_versions_found = 0;
  uint16_t highest_supported_version = 0;

  int extensions_end = offset + extensions_len;
  // printf("=====payload len: %d\n", payload_len);
  // printf("=====extensions_end len: %d\n", extensions_end);
  // printf("===== init ext len: %d\n", ext_len);

  while (offset + 4 <= extensions_end && offset + 4 <= payload_len) {
    uint16_t ext_type = (payload[offset] << 8) | payload[offset + 1];
    uint16_t ext_len = (payload[offset + 2] << 8) | payload[offset + 3];
    offset += 4;
    // printf("=====ext len: %d\n", ext_len);
    // printf("===== offset %d offset + ext_len %d > extensions_end %d\n",
    // offset,
    //        offset + ext_len, extensions_end);
    // printf("===== offset + ext_len %d > payload_len %d\n", offset + ext_len,
    //        payload_len);

    if (offset + ext_len > extensions_end || offset + ext_len > payload_len) {
      break;
    }

    uint32_t ext_data_end = offset + ext_len;
    uint32_t ext_data_offset = offset;

    // printf("sig_offset 0: %d\n", ext_data_offset);
    // printf("-------ext_type 0: %d\n", ext_type);
    if (is_grease_value(ext_type)) {
      // Skip GREASE extension
      offset = ext_data_end;
      continue;
    }
    // printf("sig_offset 1: %d\n", ext_data_offset);

    if (!is_grease_value(ext_type)) {
      extension_count_with_sni_alpn++;
      // printf("sig_offset 2: %d\n", ext_data_offset);

      if (ext_type != SNI_EXT && ext_type != ALPN_EXT) {
        extensions[extension_count++] = ext_type;
      }

      if (ext_type == SNI_EXT) {
        sni_found = 1;
      }

      if (ext_type == ALPN_EXT && ext_len > 0) {
        // printf("sig_offset 3: %d\n", ext_data_offset);
        uint32_t alpn_offset = ext_data_offset;
        if (alpn_offset + 2 > ext_data_end) {
          return -1;
        }
        uint16_t alpn_list_len =
            (payload[alpn_offset] << 8) | payload[alpn_offset + 1];
        alpn_offset += 2;
        if (alpn_offset + alpn_list_len > ext_data_end) {
          return -1;
        }

#if DEBUG
        printf("alpn_list_len %d\n", alpn_list_len);
#endif

        if (alpn_list_len > 0) {
          // printf("sig_offset 4: %d\n", ext_data_offset);
          while (alpn_offset < ext_data_end) {
            if (alpn_offset + 1 > ext_data_end) {
              return -1;
            }
            uint8_t alpn_str_len = payload[alpn_offset];
            alpn_offset += 1;
            if (alpn_offset + alpn_str_len > ext_data_end) {
              return -1;
            }
            // printf("sig_offset 5: %d\n", ext_data_offset);
            if (alpn_str_len > 0) {
              const u_char *alpn_value = payload + alpn_offset;
              int alpn_len = alpn_str_len;

              // Extract first and last characters of first ALPN value per spec
              if (alpn_len == 1) {
                if (isalnum(alpn_value[0])) {
                  alpn[0] = alpn_value[0];
                  alpn[1] = alpn_value[0];
                  alpn[2] = '\0';
                } else {
                  snprintf(alpn, sizeof(alpn), "%02x%02x", alpn_value[0] >> 4,
                           alpn_value[0] & 0x0F);
                }
              } else if (alpn_len > 1) {
                if (isalnum(alpn_value[0]) &&
                    isalnum(alpn_value[alpn_len - 1])) {
                  alpn[0] = alpn_value[0];
                  alpn[1] = alpn_value[alpn_len - 1];
                  alpn[2] = '\0';
                } else {
                  // Non-alphanumeric
                  snprintf(alpn, sizeof(alpn), "%x%x", alpn_value[0] >> 4,
                           alpn_value[alpn_len - 1] & 0x0F);
                }
              }
              // printf("sig_offset 6: %d\n", ext_data_offset);
              // At this point we found our first and last values
              break;
            }
            alpn_offset += alpn_str_len;
          }
        }
      }
      // printf("sig_offset: %d\n", ext_data_offset);

      if (ext_type == SIGNATURE_ALGORITHMS_EXT) {
        uint32_t sig_offset = ext_data_offset;
        // printf("sig_offset inside sig: %d\n", ext_data_offset);
        if (sig_offset + 2 > ext_data_end) {
          return -1;
        }
        uint16_t sig_algs_len =
            (payload[sig_offset] << 8) | payload[sig_offset + 1];
        sig_offset += 2;
        if (sig_offset + sig_algs_len > ext_data_end) {
          return -1;
        }
        // printf("alg len: %d\n", sig_algs_len);
        for (int j = 0; j < sig_algs_len; j += 2) {
          uint16_t sig_algo =
              (payload[sig_offset + j] << 8) | payload[sig_offset + j + 1];
          if (!is_grease_value(sig_algo)) {
            signature_algorithms[sig_algo_count++] = sig_algo;
          }
        }
      }

      if (ext_type == SUPPORTED_VERSIONS_EXT) {
        supported_versions_found = 1;
        uint32_t sv_offset = ext_data_offset;
        if (sv_offset + 1 > ext_data_end) {
          return -1;
        }
        uint8_t sv_len = payload[sv_offset];
        sv_offset += 1;
        if (sv_offset + sv_len > ext_data_end) {
          return -1;
        }
        for (int j = 0; j < sv_len; j += 2) {
          if (sv_offset + j + 1 >= ext_data_end) {
            break;
          }
          uint16_t version =
              (payload[sv_offset + j] << 8) | payload[sv_offset + j + 1];
          if (!is_grease_value(version) &&
              version > highest_supported_version) {
            highest_supported_version = version;
          }
        }
      }
    }

    // Next extension
    offset = ext_data_end;
    // printf("end offset: %d\n", offset);
  }

  // Find TLS Version
  if (supported_versions_found) {
    find_tls_version(highest_supported_version, tls_version);
  } else {
    find_tls_version(client_version, tls_version);
  }

  snprintf(ja4_str + strlen(ja4_str), ja4_str_len - strlen(ja4_str), "%s",
           tls_version);

  // SNI Indicator
  char sni_indicator = sni_found ? 'd' : 'i';
  snprintf(ja4_str + strlen(ja4_str), ja4_str_len - strlen(ja4_str), "%c",
           sni_indicator);

  // Number of Cipher Suites (don't include GREASE values in the count as per
  // Wireshark)
  int cipher_count_display = (cipher_count > 99) ? 99 : cipher_count;
  snprintf(ja4_str + strlen(ja4_str), ja4_str_len - strlen(ja4_str), "%02d",
           cipher_count_display);

  // Number of Extensions (include SNI and ALPN)
  int total_extension_count = extension_count_with_sni_alpn;
  if (total_extension_count > 99) {
    total_extension_count = 99;
  }

  snprintf(ja4_str + strlen(ja4_str), ja4_str_len - strlen(ja4_str), "%02d",
           total_extension_count);

  // ALPN
  snprintf(ja4_str + strlen(ja4_str), ja4_str_len - strlen(ja4_str), "%s_",
           alpn);

  // Compute JA4_b (Cipher Hash)
  qsort(ciphers, cipher_count, sizeof(uint16_t), compare_uint16_t);
  char cipher_str[4096] = "";
  for (size_t i = 0; i < cipher_count; i++) {
    char cipher_hex[5];
    snprintf(cipher_hex, sizeof(cipher_hex), "%04x", ciphers[i]);
    strcat(cipher_str, cipher_hex);
    if (i < cipher_count - 1) {
      strcat(cipher_str, ",");
    }
  }

  char *ja4_b;
  if (cipher_count == 0) {
    ja4_b = strdup("000000000000");
  } else {
    ja4_b = compute_truncated_sha256(cipher_str, strlen(cipher_str));
  }

  snprintf(ja4_str + strlen(ja4_str), ja4_str_len - strlen(ja4_str), "%s_",
           ja4_b);
  free(ja4_b);

  // Compute JA4_c (Extension Hash)
  // Signature algorithms are not included in the hash
  qsort(extensions, extension_count, sizeof(uint16_t), compare_uint16_t);
  char ext_str[4096] = "";
  for (int i = 0; i < extension_count; i++) {
    char ext_hex[5];
    snprintf(ext_hex, sizeof(ext_hex), "%04x", extensions[i]);
    strcat(ext_str, ext_hex);
    if (i < extension_count - 1) {
      strcat(ext_str, ",");
    }
  }

#if DEBUG
  printf("Extensions string to be hashed: %s\n", ext_str);
  printf("All extensions collected before exclusion: ");

  for (int i = 0; i < total_extension_count; i++) {
    printf("%04x", extensions[i]);
    if (i < total_extension_count - 1) {
      printf(",");
    }
  }
  printf("\n");

  printf("Signature algorithms: ");
  for (int i = 0; i < sig_algo_count; i++) {
    printf("%04x", signature_algorithms[i]);
    if (i < sig_algo_count - 1) {
      printf(",");
    }
  }
  printf("\n");
#endif

  // Print the extensions string
  if (sig_algo_count > 0) {
    strcat(ext_str, "_");
    for (int i = 0; i < sig_algo_count; i++) {
      char sig_hex[5];
      snprintf(sig_hex, sizeof(sig_hex), "%04x", signature_algorithms[i]);
      strcat(ext_str, sig_hex);
      if (i < sig_algo_count - 1) {
        strcat(ext_str, ",");
      }
    }
  }

  // Compute the extension hash
  char *ja4_c;
  if (extension_count == 0) {
    ja4_c = strdup("000000000000");
  } else {
    ja4_c = compute_truncated_sha256(ext_str, strlen(ext_str));
  }
  snprintf(ja4_str + strlen(ja4_str), ja4_str_len - strlen(ja4_str), "%s",
           ja4_c);
  free(ja4_c);

  return 0;
}

void find_tls_version(uint16_t version, char *tls_version) {
  switch (version) {
  case 0x0304:
    strncpy(tls_version, "13", 3);
    break;
  case 0x0303:
    strncpy(tls_version, "12", 3);
    break;
  case 0x0302:
    strncpy(tls_version, "11", 3);
    break;
  case 0x0301:
    strncpy(tls_version, "10", 3);
    break;
  case 0x0300:
    strncpy(tls_version, "s3", 3);
    break;
  case 0x0002:
    strncpy(tls_version, "s2", 3);
    break;
  case 0xfefd:
    strncpy(tls_version, "d2", 3); // DTLS 1.2
    break;
  case 0xfeff:
    strncpy(tls_version, "d1", 3); // DTLS 1.0
    break;
  case 0xfefc:
    strncpy(tls_version, "d3", 3); // DTLS 1.3
    break;
  default:
    strncpy(tls_version, "00", 3);
    break;
  }
}
