#ifndef STRUCT_H
#define STRUCT_H



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
};

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

#endif