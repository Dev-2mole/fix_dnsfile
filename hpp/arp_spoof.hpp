#ifndef ARP_SPOOF_HPP
#define ARP_SPOOF_HPP

#include "network_utils.hpp"
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <pcap.h>

// ARP 스푸핑 대상 클래스
class SpoofTarget {
private:
    u_int8_t ip[4];
    u_int8_t mac[6];
    std::string ip_str;
    std::unique_ptr<std::thread> thread_ptr;
    std::atomic<bool> running;
public:
    explicit SpoofTarget(const std::string& ip_str_);
    ~SpoofTarget();
    void stop_thread();
    
    template<typename Func, typename... Args>
    void start_thread(Func&& func, Args&&... args) {
        stop_thread();
        running = true;
        thread_ptr = std::make_unique<std::thread>(std::forward<Func>(func), std::forward<Args>(args)...);
    }
    
    const u_int8_t* get_ip() const;
    const u_int8_t* get_mac() const;
    const std::string& get_ip_str() const;
    bool is_running() const;
    void set_mac(const u_int8_t* mac_);
    
    // 복사 생성자/대입 연산자 삭제
    SpoofTarget(const SpoofTarget&) = delete;
    SpoofTarget& operator=(const SpoofTarget&) = delete;
};

// ARP 스푸퍼 클래스 (ARP 스푸핑 및 관련 기능)
class ArpSpoofer {
private:
    // 멤버 선언 순서를 생성자 초기화 순서와 일치하도록
    std::string interface;
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int8_t attacker_mac[6];
    u_int8_t attacker_ip[4];
    u_int8_t gateway_mac[6];
    u_int8_t gateway_ip[4];
    std::string gateway_ip_str;
    
    std::vector<std::unique_ptr<SpoofTarget>> targets;
    std::mutex mutex;
    
    // ARP 스푸핑 패킷 전송 및 관련 내부 함수들
    void spoof_target_thread(SpoofTarget* target);
    void send_recover_arp_packets();
    
public:
    explicit ArpSpoofer(const std::string& iface);
    ~ArpSpoofer();
    
    bool initialize();
    bool set_gateway(const std::string& gateway_ip_str_);
    bool add_target(const std::string& target_ip_str);
    bool get_mac_from_ip(const u_int8_t* target_ip, u_int8_t* target_mac);
    bool update_filter();
    
    // 스푸핑 대상 및 인터페이스 정보 접근자
    pcap_t* get_handle() const { return handle; }
    const u_int8_t* get_attacker_mac() const { return attacker_mac; }
    const u_int8_t* get_gateway_ip() const { return gateway_ip; }
    const u_int8_t* get_gateway_mac() const { return gateway_mac; } // 추가된 accessor
    const std::vector<std::unique_ptr<SpoofTarget>>& get_targets() const { return targets; }
    
    void send_arp_spoofing_packet(const SpoofTarget* target);

    // 대상별 주기적 스푸핑 시작/정지
    void start_spoofing_all();
    void stop_all();
    
    static bool enable_ip_forwarding();
    static bool disable_ip_forwarding();
};

#endif // ARP_SPOOF_HPP