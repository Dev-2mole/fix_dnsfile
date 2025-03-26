#ifndef NETWORK_UTILS_HPP
#define NETWORK_UTILS_HPP

#include <string>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>

// 유틸리티 함수 선언
std::string mac_to_string(const u_int8_t* mac);
std::string ip_to_string(const u_int8_t* ip);
void string_to_ip(const char* ip_str, u_int8_t* ip);
bool string_to_mac(const char* mac_str, u_int8_t* mac);
bool mac_equals(const u_int8_t* mac1, const u_int8_t* mac2);
bool ip_equals(const u_int8_t* ip1, const u_int8_t* ip2);

// IP, UDP, ARP 헤더 구조체 선언
struct ip_header {
    u_int8_t  ip_vhl;   // 버전 및 헤더 길이
    u_int8_t  ip_tos;   // 서비스 타입
    u_int16_t ip_len;   // 전체 길이
    u_int16_t ip_id;    // 식별
    u_int16_t ip_off;   // 플래그 및 분할 오프셋
    u_int8_t  ip_ttl;   // 생존 시간
    u_int8_t  ip_p;     // 프로토콜
    u_int16_t ip_sum;   // 체크섬
    u_int32_t ip_src;   // 출발지 주소
    u_int32_t ip_dst;   // 목적지 주소
};

struct udp_header {
    u_int16_t uh_sport;
    u_int16_t uh_dport;
    u_int16_t uh_len;
    u_int16_t uh_sum;
};

struct arp_header {
    u_int16_t htype;
    u_int16_t ptype;
    u_int8_t hlen;
    u_int8_t plen;
    u_int16_t oper;
    u_int8_t sha[6];
    u_int8_t spa[4];
    u_int8_t tha[6];
    u_int8_t tpa[4];
};

// ARP 패킷 생성 함수 선언
void create_arp_packet(u_int8_t* packet, const u_int8_t* src_mac, const u_int8_t* dst_mac,
                         const u_int8_t* src_ip, const u_int8_t* dst_ip, u_int16_t oper);

// 인터페이스에서 MAC/IP 가져오기 함수 선언
bool get_interface_mac(const std::string& interface_name, u_int8_t* mac);
bool get_interface_ip(const std::string& interface_name, u_int8_t* ip);

// 상수 선언
extern const u_int8_t BROADCAST_MAC[6];
extern const u_int8_t ZERO_MAC[6];

#endif // NETWORK_UTILS_HPP
