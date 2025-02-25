#include "other_handler.h"

OtherHandler::OtherHandler(const PacketSniffer& sniffer)
    : PacketDumper(sniffer, filename_out) {}

void OtherHandler::process_packet(const pcap_pkthdr* packet_header, const u_char *packet) const {
    pcap_dump((u_char*) dumper, packet_header, packet);
}