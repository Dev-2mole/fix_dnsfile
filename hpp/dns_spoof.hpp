#ifndef DNS_SPOOF_HPP
#define DNS_SPOOF_HPP

#include <pcap.h>
#include <cstdint>

// DNS 헤더 구조체 선언
struct dns_header {
    u_int16_t id;
    u_int16_t flags;
    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;
};

// DNS 스푸핑 응답 함수 선언
void send_dns_spoof_response(pcap_t* handle, u_int8_t* orig_packet, size_t orig_packet_len,
                             const u_int8_t* attacker_mac, const u_int8_t* gateway_ip);

#endif // DNS_SPOOF_HPP
