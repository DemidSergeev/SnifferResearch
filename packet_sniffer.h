#pragma once

#include "packet_types.h"
#include "packet_handler.h"

#include <pcap.h>
#include <iostream>
#include <string>
#include <vector>

// Класс, отвечающий за захват пакетов и распределение на нужный обработчик.
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

		pcap_t* getHandle() const;

	private:
		pcap_t *handle = nullptr; // handle сессии захвата
		std::vector<std::unique_ptr<PacketHandler>> handlers;
		// Функция обработки для отдельного пакета
		static void distribute_packets(u_char* user, const struct pcap_pkthdr* packetHeader, const u_char* packet);
		static PacketType analyze_packet(const struct pcap_pkthdr* packet_header, const u_char* packet);
		static volatile bool stop_capture;
		static void handle_signal(int signal);
};