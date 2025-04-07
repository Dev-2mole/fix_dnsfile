#ifndef DNS_SPOOFER_HPP
#define DNS_SPOOFER_HPP

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <pcap.h>
#include <memory>

// DNS 헤더 구조체 정의
struct dns_hdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Forward declaration for SpoofTarget (defined in arp_spoof.hpp)
class SpoofTarget;

struct DnsTemplateCache {
    std::vector<uint8_t> packet;
    uint16_t qtype;
    bool is_response;
};

class DnsSpoofer {
public:
    DnsSpoofer();
    ~DnsSpoofer();
    
    // 템플릿 초기화 (각 파일 경로를 인자로 받음)
    bool initialize_templates(const std::string& naver_path,
                              const std::string& google_path,
                              const std::string& daum_path);
    
    // DNS 데이터에서 도메인 추출
    std::string extract_domain_name(const uint8_t* dns_data, size_t dns_len);
    
    // 스푸핑 응답 전송 (원본 패킷, 공격자/게이트웨이 MAC, 도메인, 타겟 목록 등)
    void send_spoof_response(pcap_t* handle, 
                             const uint8_t* orig_packet, 
                             size_t orig_packet_len,
                             const uint8_t* attacker_mac,
                             const uint8_t* gateway_ip,
                             const std::string& domain,
                             const std::vector<std::unique_ptr<SpoofTarget>>& targets);
    
    // DNS 스푸핑 복구 응답 전송
    void send_recovery_responses(pcap_t* handle,
                                 const uint8_t* attacker_mac,
                                 const uint8_t* gateway_ip,
                                 const std::vector<std::unique_ptr<SpoofTarget>>& targets);
    
private:
    std::unordered_map<std::string, std::vector<DnsTemplateCache>> template_cache;
    
    bool load_dns_response_template(const std::string& filename, std::vector<std::vector<uint8_t>>& templates);
    void cache_template_packet(const std::vector<uint8_t>& packet, const std::string& domain);
};

#endif // DNS_SPOOFER_HPP
