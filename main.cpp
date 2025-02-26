#include "packet_sniffer.h"

#include <pcap.h>

#include <iostream>

int main(int argc, char *argv[]) {

	if (argc > 1) {
		PacketSniffer sniffer = PacketSniffer(argv[1]);
		sniffer.start_capture();
	} else {
		std::cout << "Usage: " << argv[0] << " <interface>\n";
	}

	return 0;
}
