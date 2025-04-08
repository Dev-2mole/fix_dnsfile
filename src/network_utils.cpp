#include "network_utils.hpp"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

using namespace std;

namespace NetworkUtils {

const uint8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t ZERO_MAC[6] = {0, 0, 0, 0, 0, 0};

string mac_to_string(const uint8_t* mac) 
{
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(mac_str);
}

string ip_to_string(const uint8_t* ip) 
{
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return string(ip_str);
}

void string_to_ip(const char* ip_str, uint8_t* ip) 
{
    memset(ip, 0, 4);
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) 
    {
        ip[0] = static_cast<uint8_t>(a);
        ip[1] = static_cast<uint8_t>(b);
        ip[2] = static_cast<uint8_t>(c);
        ip[3] = static_cast<uint8_t>(d);
    } 
    else 
    {
        cerr << "Invalid IP format: " << ip_str << endl;
    }
}

bool mac_equals(const uint8_t* mac1, const uint8_t* mac2) 
{
    return memcmp(mac1, mac2, 6) == 0;
}

bool ip_equals(const uint8_t* ip1, const uint8_t* ip2) 
{
    return memcmp(ip1, ip2, 4) == 0;
}

void create_arp_packet(uint8_t* packet, 
                       const uint8_t* src_mac, 
                       const uint8_t* dst_mac, 
                       const uint8_t* src_ip, 
                       const uint8_t* dst_ip, 
                       uint16_t oper) 
{
    // Ethernet header 설정
    struct ether_header* eth = reinterpret_cast<struct ether_header*>(packet);
    memcpy(eth->ether_dhost, dst_mac, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);
    
    // ARP header 설정 (struct ether_arp 사용)
    struct ether_arp* arp = reinterpret_cast<struct ether_arp*>(packet + sizeof(struct ether_header));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);  // 하드웨어 타입
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);    // 프로토콜 타입
    arp->ea_hdr.ar_hln = 6;                      // MAC 주소 길이
    arp->ea_hdr.ar_pln = 4;                      // IPv4 주소 길이
    arp->ea_hdr.ar_op = htons(oper);             // 오퍼레이션 코드 (1: request, 2: reply)
    
    memcpy(arp->arp_sha, src_mac, 6);            // 발신자 MAC
    memcpy(arp->arp_spa, src_ip, 4);             // 발신자 IP
    memcpy(arp->arp_tha, dst_mac, 6);            // 대상 MAC (ARP 요청에서는 브로드캐스트)
    memcpy(arp->arp_tpa, dst_ip, 4);             // 대상 IP
}

bool get_interface_mac(const string& interface_name, uint8_t* mac) 
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) 
    {
        cerr << "Socket creation failed" << endl;
        return false;
    }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) 
    {
        cerr << "Failed to get MAC address for " << interface_name << endl;
        close(sock);
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return true;
}

bool get_interface_ip(const string& interface_name, uint8_t* ip) 
{
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) 
    {
        cerr << "Failed to get interface addresses" << endl;
        return false;
    }
    bool found = false;
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == nullptr)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET && interface_name == ifa->ifa_name) 
        {
            struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            memcpy(ip, &addr->sin_addr, 4);
            found = true;
            break;
        }
    }
    freeifaddrs(ifaddr);
    if (!found)
        cerr << "Failed to get IPv4 address for " << interface_name << endl;
    return found;
}

} 
