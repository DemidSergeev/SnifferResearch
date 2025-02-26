#pragma once

#include "packet_handler.h"
#include "packet_dumper.h"

// Обработчик для потока управления FTP
class FtpControlHandler : public PacketHandler, PacketDumper {
    public:
        FtpControlHandler(const PacketSniffer& sniffer);
        void process_packet(const pcap_pkthdr* packet_header, const u_char* packet) const override;

    private:
        static const std::string filename_out;
};
