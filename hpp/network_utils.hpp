#ifndef NETWORK_UTILS_HPP
#define NETWORK_UTILS_HPP

#include <string>
#include <cstdint>

namespace NetworkUtils {

    // C++17 inline 상수로 정의 (불가피한 경우)
    inline const uint8_t BROADCAST_MAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    inline const uint8_t ZERO_MAC[6] = {0, 0, 0, 0, 0, 0};

    std::string mac_to_string(const uint8_t* mac);
    std::string ip_to_string(const uint8_t* ip);
    void string_to_ip(const char* ip_str, uint8_t* ip);
    bool mac_equals(const uint8_t* mac1, const uint8_t* mac2);
    bool ip_equals(const uint8_t* ip1, const uint8_t* ip2);
    void create_arp_packet(uint8_t* packet, 
                           const uint8_t* src_mac, 
                           const uint8_t* dst_mac, 
                           const uint8_t* src_ip, 
                           const uint8_t* dst_ip, 
                           uint16_t oper);
    bool get_interface_mac(const std::string& interface_name, uint8_t* mac);
    bool get_interface_ip(const std::string& interface_name, uint8_t* ip);
}

#endif // NETWORK_UTILS_HPP
