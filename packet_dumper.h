#pragma once

#include "packet_sniffer.h"

#include <pcap.h>

#include <fstream>
#include <string>

class PacketDumper {
    public:
        PacketDumper(const PacketSniffer& sniffer, const std::string& filename);
        ~PacketDumper();

    protected:
        pcap_dumper_t* dumper;
};