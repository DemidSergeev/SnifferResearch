#include "packet_dumper.h"

#include <pcap.h>

#include <iostream>

PacketDumper::PacketDumper(const PacketSniffer& sniffer, const std::string& filename) {
    pcap_t* handle = sniffer.getHandle();
    if (!(dumper = pcap_dump_open(handle, filename.c_str()))) {
       throw std::runtime_error(pcap_geterr(handle)); 
    };
}

PacketDumper::~PacketDumper() {
    pcap_dump_close(dumper);
}