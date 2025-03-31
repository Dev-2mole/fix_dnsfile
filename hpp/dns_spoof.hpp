#ifndef DNS_SPOOF_HPP
#define DNS_SPOOF_HPP

#include <pcap.h>
#include <cstdint>
#include <string>
#include <vector>
#include "arp_spoof.hpp"

// DNS 헤더 구조체 선언
struct dns_header {
    u_int16_t id;
    u_int16_t flags;
    u_int16_t qdcount;
    u_int16_t ancount;
    u_int16_t nscount;
    u_int16_t arcount;
};

// 전역 변수로 DNS 응답 템플릿 저장 (여러 응답을 저장하도록 수정)
extern std::vector<std::vector<uint8_t>> dns_template_naver;
extern std::vector<std::vector<uint8_t>> dns_template_google;
extern std::vector<std::vector<uint8_t>> dns_template_daum;

// DNS 응답 템플릿 로드 함수 (복수 응답 지원)
bool load_dns_response_template(const char* filename, std::vector<std::vector<uint8_t>>& templates);

// 모든 DNS 템플릿 로드
bool initialize_dns_templates();

// 도메인 이름 추출 함수
std::string extract_domain_name(const uint8_t* dns_data, size_t dns_len);

// DNS 스푸핑 응답 함수 선언
void send_dns_spoof_response(pcap_t* handle, u_int8_t* orig_packet, size_t orig_packet_len,
    const u_int8_t* attacker_mac, const u_int8_t* gateway_ip,
    const std::string& domain,
    const std::vector<std::unique_ptr<SpoofTarget>>& targets);

#endif // DNS_SPOOF_HPP
