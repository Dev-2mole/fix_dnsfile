#include "network_utils.hpp"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

using namespace std;

/*
*   짜잘한 중복 처리 로직 함수 모음집
*/

const u_int8_t BROADCAST_MAC[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
const u_int8_t ZERO_MAC[6] = {0,0,0,0,0,0};

string mac_to_string(const u_int8_t* mac) 
{
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(mac_str);
}

string ip_to_string(const u_int8_t* ip) 
{
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return string(ip_str);
}

void string_to_ip(const char* ip_str, u_int8_t* ip) 
{
    memset(ip, 0, 4);
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        ip[0] = (u_int8_t)a;
        ip[1] = (u_int8_t)b;
        ip[2] = (u_int8_t)c;
        ip[3] = (u_int8_t)d;
    } else {
        cerr << "Invalid IP format: " << ip_str << endl;
    }
}

bool string_to_mac(const char* mac_str, u_int8_t* mac) 
{
    return sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

bool mac_equals(const u_int8_t* mac1, const u_int8_t* mac2) 
{
    return memcmp(mac1, mac2, 6) == 0;
}

bool ip_equals(const u_int8_t* ip1, const u_int8_t* ip2) 
{
    return memcmp(ip1, ip2, 4) == 0;
}

void create_arp_packet(u_int8_t* packet, const u_int8_t* src_mac, const u_int8_t* dst_mac, const u_int8_t* src_ip, const u_int8_t* dst_ip, u_int16_t oper) 
{
    struct ether_header* eth = reinterpret_cast<struct ether_header*>(packet);
    memcpy(eth->ether_dhost, dst_mac, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);
    
    struct arp_header* arp = reinterpret_cast<struct arp_header*>(packet + sizeof(struct ether_header));
    arp->htype = htons(1);  // Ethernet Fild
    arp->ptype = htons(0x0800); // IPv4
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(oper);    
    
    memcpy(arp->sha, src_mac, 6);
    memcpy(arp->spa, src_ip, 4);
    memcpy(arp->tha, dst_mac, 6);
    memcpy(arp->tpa, dst_ip, 4);
}

bool get_interface_mac(const string& interface_name, u_int8_t* mac) 
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

bool get_interface_ip(const string& interface_name, u_int8_t* ip) 
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
        {
            continue;
        }
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
    {
        cerr << "Failed to get IPv4 address for " << interface_name << endl;
    }
    return found;
}
