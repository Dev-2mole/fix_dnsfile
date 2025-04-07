#ifndef PACKET_FORWARDER_HPP
#define PACKET_FORWARDER_HPP

#include <pcap.h>
#include <memory>
#include <thread>
#include <atomic>
#include <condition_variable>
#include "arp_spoof.hpp"

// Forward declaration of DnsSpoofer
class DnsSpoofer;

class PacketForwarder {
public:
    PacketForwarder(pcap_t* handle, ArpSpoofer* spoofer, DnsSpoofer* dnsSpoofer);
    ~PacketForwarder();
    
    void start();
    void stop();
    
private:
    pcap_t* handle;
    ArpSpoofer* spoofer;
    DnsSpoofer* dnsSpoofer;
    std::atomic<bool> running;
    std::unique_ptr<std::thread> forward_thread;
    std::condition_variable cv;
    std::mutex cv_mutex;
    
    void forward_loop();
    bool handle_dns_packet(const uint8_t* packet, size_t packet_len);
    void handle_arp_packet(const uint8_t* packet, size_t packet_len);
    bool is_spoofed_packet(const uint8_t* packet, size_t packet_len);
    void forward_packet(const uint8_t* packet, size_t packet_len);
    void recover_dns();
    
};

#endif // PACKET_FORWARDER_HPP
