# 컴파일러 및 플래그 설정
CXX = g++
CXXFLAGS = -Wall -std=c++14 -pthread -Ihpp
LDFLAGS = -lpcap

# 대상 실행 파일 이름
TARGET = dns_hijacking

# 소스 파일 목록
SRCS = main.cpp \
       src/network_utils.cpp \
       src/arp_spoof.cpp \
       src/dns_spoof.cpp \
       src/packet_forwarder.cpp

# 객체 파일 목록 (main.cpp → main.o, src/foo.cpp → src/foo.o)
OBJS = main.o \
       src/network_utils.o \
       src/arp_spoof.o \
       src/dns_spoof.o \
       src/packet_forwarder.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

main.o: main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

src/%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
