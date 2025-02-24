#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include "packet_types.h"

#include <pcap.h>
#include <iostream>
#include <string>

class PacketSniffer {
public:
	static const int MAX_CAPTURE_BYTES = 2048, PROMISC = 1, TIMEOUT_MS = 1000;
	// Размер заголовка Ethernet - всегда 14 байт
	static const int SIZE_ETHERNET_HEADER = 14;
	static const int PORT_FTP_CONTROL = 21;
	static const int PORT_FTP_DATA = 20;

	// Конструктор с инициализацией handle и установкой фильтра на IPv4
	explicit PacketSniffer(const std::string& interface);
	// Деструктор с освобождением ресурсов
	~PacketSniffer();

	// Метод для захвата пакетов
	void start_capture();

private:
	pcap_t *handle = nullptr; // handle сессии захвата

	// Функция обработки для отдельного пакета
	static void distribute_packets(u_char* user, const struct pcap_pkthdr* packetHeader, const u_char* packet);
	static PacketType analyze_packet(const struct pcap_pkthdr* packet_header, const u_char* packet);
};

#endif
