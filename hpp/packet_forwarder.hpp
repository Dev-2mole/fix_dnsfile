#ifndef PACKET_FORWARDER_HPP
#define PACKET_FORWARDER_HPP

#include "network_utils.hpp"
#include "arp_spoof.hpp"
#include "dns_spoof.hpp"
#include <pcap.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <memory>

// 패킷 포워딩을 담당하는 클래스
class PacketForwarder {
private:
    pcap_t* handle;
    ArpSpoofer* spoofer; // ArpSpoofer 인스턴스에 있는 정보 사용
    std::atomic<bool> running;
    std::unique_ptr<std::thread> forward_thread;
    std::mutex mutex;
    std::condition_variable cv;
    
    void forward_loop();
    void forward_packet(const u_int8_t* packet_data, size_t packet_len);
    bool is_spoofed_packet(const u_int8_t* packet_data, size_t packet_len);
    void handle_arp_packet(const u_int8_t* packet_data, size_t packet_len);
    
    // 새로운 함수 시그니처 (bool 반환값 추가)
    bool is_dns_packet(const u_int8_t* packet_data, size_t packet_len);
    bool handle_dns_packet(const u_int8_t* packet_data, size_t packet_len);
    
public:
    PacketForwarder(pcap_t* handle, ArpSpoofer* spoofer);
    ~PacketForwarder();
    
    void recover_dns();
    void start();
    void stop();
};

#endif // PACKET_FORWARDER_HPP