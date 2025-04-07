#ifndef ARP_SPOOF_HPP
#define ARP_SPOOF_HPP

#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <pcap.h>
#include <thread>

class SpoofTarget {
public:
    explicit SpoofTarget(const std::string& ip_str);
    ~SpoofTarget();
    
    const uint8_t* get_ip() const;
    const uint8_t* get_mac() const;
    const std::string& get_ip_str() const;
    bool is_running() const;
    void set_mac(const uint8_t* mac);
    void start_thread(void (*threadFunc)(SpoofTarget*), SpoofTarget* target);
    void stop_thread();
    
private:
    std::string ip_str;
    uint8_t ip[4];
    uint8_t mac[6];
    bool running;
    std::unique_ptr<std::thread> thread_ptr;
};

class ArpSpoofer {
public:
    static ArpSpoofer* global_instance;
    pcap_t* get_handle() const;
    explicit ArpSpoofer(const std::string& iface);
    ~ArpSpoofer();
    
    bool initialize();
    bool set_gateway(const std::string& gateway_ip_str);
    bool add_target(const std::string& target_ip_str);
    bool update_filter();
    void start_spoofing_all();
    void stop_all();
    static bool enable_ip_forwarding();
    static bool disable_ip_forwarding();
    
    // Getter functions for use by 다른 모듈
    const uint8_t* get_attacker_mac() const { return attacker_mac; }
    const uint8_t* get_attacker_ip() const { return attacker_ip; }
    const uint8_t* get_gateway_mac() const { return gateway_mac; }
    const uint8_t* get_gateway_ip() const { return gateway_ip; }
    const std::vector<std::unique_ptr<SpoofTarget>>& get_targets() const { return targets; }
    
    void send_arp_spoofing_packet(const SpoofTarget* target);
    void send_recover_arp_packets();
    
private:
    
    std::string interface;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    uint8_t attacker_mac[6];
    uint8_t attacker_ip[4];
    uint8_t gateway_mac[6];
    uint8_t gateway_ip[4];
    std::string gateway_ip_str;
    
    std::vector<std::unique_ptr<SpoofTarget>> targets;
    mutable std::mutex mutex;
    
    void spoof_target_thread(SpoofTarget* target);

    bool get_mac_from_ip(const uint8_t* target_ip, uint8_t* target_mac);
};

#endif // ARP_SPOOF_HPP
