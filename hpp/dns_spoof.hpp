#ifndef DNS_SPOOF_HPP
#define DNS_SPOOF_HPP

#include <pcap.h>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
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

// DNS 템플릿 캐시 구조체
struct DnsTemplateCache {
    std::vector<uint8_t> packet;
    uint16_t qtype;
    bool is_response;
};

// 글로벌 변수로 DNS 응답 템플릿 저장
extern std::vector<std::vector<uint8_t>> dns_template_naver;
extern std::vector<std::vector<uint8_t>> dns_template_google;
extern std::vector<std::vector<uint8_t>> dns_template_daum;

// 캐시 및 버퍼 전역 변수
extern std::unordered_map<std::string, std::vector<DnsTemplateCache>> template_cache;
extern std::vector<uint8_t> packet_buffer;

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
// DNS 스푸핑 복구 함수 선언 - 짧은 TTL로 정상 응답 전송
void send_dns_recovery_responses(pcap_t* handle, 
    const u_int8_t* attacker_mac, const u_int8_t* gateway_ip,
    const std::vector<std::unique_ptr<SpoofTarget>>& targets);

#endif // DNS_SPOOF_HPP