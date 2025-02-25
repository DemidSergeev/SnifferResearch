#pragma once

#include "packet_handler.h"
#include "packet_dumper.h"

// Обработчик для потока данных FTP
class FtpDataHandler : public PacketHandler, PacketDumper {
    public:
        FtpDataHandler(const PacketSniffer& sniffer);
        void process_packet(const pcap_pkthdr* packet_header, const u_char* packet) const override;
    private:
        const std::string filename_out = "ftp_data.pcap";
};
