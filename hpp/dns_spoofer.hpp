#ifndef DNS_SPOOFER_HPP
#define DNS_SPOOFER_HPP

#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <pcap.h>
#include <memory>
#include <sstream> // 새로 추가: stringstream 사용

// DNS 헤더 구조체 정의
struct dns_hdr {
    uint16_t id;        // ID 트랜젝션
    uint16_t flags;     // 플래그 및 응답
    uint16_t qdcount;   // 질문 섹션 개수
    uint16_t ancount;   // 응답 섹션 개수
    uint16_t nscount;   // 권한 섹션 개수
    uint16_t arcount;   // 추가 정보 섹션 개수 
};

// ARP_Spoof 코드의 클래스 가져옴 (포인터 참조용)
class SpoofTarget;

struct DnsTemplateCache {
    std::vector<uint8_t> packet;    // PCAP파일에서 가져온 데이터
    uint16_t qtype;                 // PCAP파일에서의 레코드 타입
    bool is_response;               // DNS 응답 패킷인지 확인
};

// PCAP 템플릿 기반으로 DNS 패킷 제작 및 전송
class DnsSpoofer {
    public:
        DnsSpoofer();
        ~DnsSpoofer();
        // 템플릿 불러오는 함수
        bool initialize_templates(const std::string& naver_path,
                                  const std::string& google_path,
                                  const std::string& daum_path);
        // 도메인 정규화 진행 뒤에 . 이 있을 수 있어 제거용 함수
        std::string extract_domain_name(const uint8_t* dns_data, size_t dns_len);
        // DNS Spoofing 패킷 전송
        void send_spoof_response(pcap_t* handle, 
                                 const uint8_t* orig_packet, 
                                 size_t orig_packet_len,
                                 const uint8_t* attacker_mac,
                                 const uint8_t* gateway_ip,
                                 const std::string& domain,
                                 const std::vector<std::unique_ptr<class SpoofTarget>>& targets);
        // 복구용 DNS 패킷 전송 (템플릿 사용하지 않는 버전)
        void send_recovery_responses(pcap_t* handle,
                                     const uint8_t* attacker_mac,
                                     const uint8_t* gateway_ip,
                                     const std::vector<std::unique_ptr<class SpoofTarget>>& targets);
        
        // 새로운 함수: NXDOMAIN 패킷 직접 생성 및 전송
        void create_and_send_nxdomain_packet(pcap_t* handle,
                                           const uint8_t* src_mac,
                                           const uint8_t* dst_mac,
                                           const uint8_t* src_ip,
                                           const uint8_t* dst_ip,
                                           const std::string& domain);
    
        // 복구용 도메인 명 
        void setRecoveryDomains(const std::vector<std::string>& domains) {
            recovery_domains = domains;
        }
    
        // WEB 서버 spoof_ip 
        void setSpoofIP(const std::string& ip) {
            spoof_ip = ip;
        }
    
    private:
        std::unordered_map<std::string, std::vector<DnsTemplateCache>> template_cache;
        std::vector<std::string> recovery_domains; // 복구 도메인 리스트
        std::string spoof_ip = "192.168.127.132"; // 기본 스푸핑 IP
    
        bool load_dns_response_template(const std::string& filename, std::vector<std::vector<uint8_t>>& templates);
        void cache_template_packet(const std::vector<uint8_t>& packet, const std::string& domain);
    };
    
#endif // DNS_SPOOFER_HPP