 #include "pcap.h"

struct Header {
    u_int8_t dst_mac[6];
    u_int8_t src_mac[6];
    u_int16_t type;
    Header(const u_char *buff) {
        std::memcpy(dst_mac, buff, 6);
        std::memcpy(src_mac, buff + 6, 6);
        type = (((u_int16_t)buff[12]) << 8) + buff[13];
    };
};

#define ID_ARP  0x0806
#define ID_TCP  0x0800

#define ID_TYPE_UDP     0x11
#define ID_TYPE_TCP     0x06
#define ID_TYPE_ICMP     0x01
 
struct ARP {
    u_int16_t   hw_type;
    u_int16_t   protocol;
    u_int8_t    hw_size;
    u_int8_t    protocol_size;
    u_int16_t   opcode;
    u_int8_t    sender_mac[6];
    u_int32_t   sender_ip;
    u_int8_t    target_mac[6];
    u_int32_t   target_ip;
};

union port {
	u_int16_t port;
	u_char b[2];
} t;

struct IPv4 {
    u_char      ver : 4;
    u_char      header_len : 4;
    u_char      service;
    u_int16_t   len;
    u_int16_t   id;
    u_int16_t   flags : 3;
    u_int16_t   offset : 13;
    u_char      ttl;
    u_char      protocol;
    u_int16_t   crc;
    u_int32_t   source_address;
    u_int32_t   desination_address;
    port        source_port;
    port        desination_port; 
    IPv4(const u_char *buff) {
        memcpy(this, buff + sizeof(Header), sizeof(IPv4));
        std::swap(source_port.b[0], source_port.b[1]);
        std::swap(desination_port.b[0], desination_port.b[1]);
    }
};


std::string PrintMAC(const u_int8_t* mac) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex <<  (int)mac[0] << ":" << (int)mac[1] << ":" << (int)mac[2] << ":" << (int)mac[3] << ":" << (int)mac[4] << ":" << (int)mac[5];
    //std::cout << "MAC: " << ss.str() << std::endl;
    return ss.str();
}
std::string PrintIP(const u_int32_t ip) {
    std::stringstream ss;

    ss << (ip & 0xFF) << "." << (ip >> 8 & 0xFF) << "." << (ip >> 16 & 0xFF) << "." << (ip >> 24 & 0xFF);
    //std::cout << "IP: " << ss.str() << std::endl;
    return ss.str();
}
unsigned short GetPort(const u_char* port) {
    return ((unsigned short)(*port) << 8) + (unsigned short)*(port+1);
}

void ParseIPv4_ports(const IPv4 &ip4, CPcap::Stast *stats){
    stats->ports["src_port"].insert(ip4.source_port.port);
    stats->ports["dst_port"].insert(ip4.desination_port.port);
}

void ParseIPv4(const u_char* buff, CPcap::Stast *stats) {
    stats->protocols[Protocols::IPv4]++;
    IPv4 ip4(buff);
    stats->ips["src_ip"].insert(ip4.source_address);
    stats->ips["dst_ip"].insert(ip4.desination_address);
    switch(ip4.protocol){
        case ID_TYPE_ICMP:
            stats->protocols[Protocols::ICMP]++;
            break;
        case ID_TYPE_UDP:
            stats->protocols[Protocols::UDP]++;
            ParseIPv4_ports(ip4, stats);
            break;
        case ID_TYPE_TCP:
            stats->protocols[Protocols::TCP]++;
            ParseIPv4_ports(ip4, stats);
            break;
    }
    //std::cout << PrintIP(ip4.source_address) << ":" << ip4.source_port.port << " -> " << PrintIP(ip4.desination_address) << ":" << ip4.desination_port.port << std::endl;
}

void pcap_loop_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{   
    CPcap::Stast *stats = (CPcap::Stast *)useless;
    stats->count++;
    //std::cout << "packet " << stats->count << ", len = " << pkthdr->len << std::endl;
    for (auto& [len, cnt] : stats->len_pack) {
        if(pkthdr->len <= len) {
            cnt++;
            //std::cout << "len pack find: " << len << ", now cnt = " << cnt << std::endl;
            break;
        }
    }
    const Header h(packet);
    try {
        auto src_mac = PrintMAC(h.src_mac);
        stats->sources["src_mac"].insert(src_mac);
        auto dst_mac = PrintMAC(h.dst_mac);
        stats->sources["dst_mac"].insert(dst_mac);
        //auto src_ip = PrintIP(packet + 28);
        //std::cout << dst_mac << " " << src_mac;

        if(h.type == ID_ARP) {
            //std::cout << " *** ARP detected" << std::endl;
            stats->protocols[Protocols::nonIPv4]++;
        } else if(h.type == ID_TCP) {
            //std::cout << " *** IPv4 *** ";
            //stats->sources["src_ip"].insert(src_ip);
            //auto dst_ip = PrintIP(packet + 39);
            //stats->sources["dst_ip"].insert(dst_ip);
            ParseIPv4(packet, stats);
        } else {
            std::cout << " *** Unknown" << std::endl;
            stats->protocols[Protocols::nonIPv4]++;
        }
    } catch (...) {
        std::cout << "cannot parse mac" << std::endl;
    }
}



bool CPcap::ParseFile(const fs::path& filename) {
	std::cout << filename << std::endl;
    /* Open the dump file */
	char errbuf[PCAP_ERRBUF_SIZE];
    auto dumpfile = pcap_open_offline(filename.c_str(), errbuf);
    if(dumpfile==NULL)
    {
        fprintf(stderr,"\nError opening output file\n");
        return false;
    } else {
		int count = 0;
		pcap_loop(dumpfile, 0, pcap_loop_callback, (u_char *)&stats);
        std::cout << "Общее количество пакетов: " << stats.count << std::endl;
        std::cout << "Распределение длин пакетов в байтах " << std::endl;
        bool start = true;
        int prev_len = 0;
        for (auto& [len, cnt] : stats.len_pack) {
            if(!prev_len)
                std::cout << "<=" << len;
            else if(len == INT_MAX)
                std::cout << "=>" << prev_len + 1;
            else
                std::cout << prev_len + 1 << "-" << len;
            prev_len = len;
            std::cout << ": " <<  cnt << std::endl;
        }
        std::cout << "Распределение по протоколам: " << std::endl;
        for (auto& [key, value] : stats.protocols) {
            std::cout << name_protocols[key] << ": " << value << std::endl;
        }
        
        std::cout << "Количество уникальных значений по полям: " << std::endl;
        for (auto& [key, value] : stats.sources) {
            std::cout << key << ": " << value.size() << std::endl;
        }
        for (auto& [key, value] : stats.ips) {
            std::cout << key << ": " << value.size() << std::endl;
        }
        for (auto& [key, value] : stats.ports) {
            std::cout << key << ": " << value.size() << std::endl;
        }
	} 
//    std::cout << "size Header: " << sizeof(Header) << std::endl;
	return true;
}
