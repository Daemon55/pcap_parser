#ifndef PCAP_H
#define PCAP_H

#include <iostream>
#include <filesystem>
#include <pcap/pcap.h>
#include <map>
#include <set>
#include <climits>
#include <cstring>
#include <sstream>
#include <algorithm>

namespace fs = std::filesystem;

enum class Protocols {IPv4, nonIPv4, TCP, UDP, ICMP, otherL4};

class CPcap {
public:
    struct Stast {
        int count {0};
        std::map<int, int> len_pack{{64, 0}, {255, 0}, {511, 0}, {1023, 0}, {1518, 0}, {INT_MAX, 0}};
        std::map<Protocols, u_int32_t> protocols{{ Protocols::IPv4 , 0}, { Protocols::nonIPv4 , 0}, { Protocols::TCP , 0}, { Protocols::UDP , 0}, { Protocols::ICMP , 0}, { Protocols::otherL4 , 0}};
        std::map<std::string, std::set<std::string>> sources{{"src_mac", {}}, {"dst_mac", {}}};
        std::map<std::string, std::set<unsigned short>> ports{{"src_port", {}}, {"dst_port", {}}};
        std::map<std::string, std::set<unsigned short>> ips{{"src_ip", {}}, {"dst_ip", {}}};
        std::map<std::string, std::set<std::string>> flags{{"SYN", {}}, {"SYN + ACK", {}}, {"ACK", {}}, {"FIN + ACK", {}}, {"RST", {}}, {"RST + ACK", {}}, {"other", {}}};

    } stats;
    CPcap(){
    };
    ~CPcap(){};
    bool ParseFile(const fs::path& filename);
private:
    std::map<Protocols, std::string> name_protocols{
            {Protocols::IPv4, "IPv4"}, 
            {Protocols::nonIPv4, "non-IPv4"}, 
            {Protocols::TCP, "TCP"}, 
            {Protocols::UDP, "UDP"}, 
            {Protocols::ICMP, "ICMP"}, 
            {Protocols::otherL4, "other L4"}
        };
};


#endif