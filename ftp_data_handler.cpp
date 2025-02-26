#include "ftp_data_handler.h"

FtpDataHandler::FtpDataHandler(const PacketSniffer& sniffer)
                : PacketDumper(sniffer, filename_out) {}

void FtpDataHandler::process_packet(const pcap_pkthdr* packet_header, const u_char *packet) const {
    pcap_dump((u_char*) dumper, packet_header, packet);
}

const std::string FtpDataHandler::filename_out = "ftp_data.pcap";