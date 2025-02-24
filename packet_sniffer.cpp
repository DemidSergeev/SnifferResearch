#include "packet_sniffer.h"

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <sys/stat.h> // Для chmod
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>


// Конструктор, инициализирующий handle
PacketSniffer::PacketSniffer(const std::string& interface) {
	char errbuf[PCAP_ERRBUF_SIZE];

	std::cout << "Имя интерфейса: " << interface << std::endl;
	handle = pcap_open_live(interface.c_str(), MAX_CAPTURE_BYTES, PROMISC, TIMEOUT_MS, errbuf);
	if (!handle) {
		throw std::runtime_error("Ошибка при открытии объекта:\n'" + std::string(errbuf) + "'");
	}	
}

// Деструктор - закрытие handle
PacketSniffer::~PacketSniffer() {
	if (handle) {
		pcap_close(handle);
	}
}

// Метод для захвата указанного числа пакетов 
void PacketSniffer::start_capture() {
	std::cout << "Начат захват пакетов." << std::endl;
	if (pcap_loop(handle, -1, distribute_packets, nullptr)) {
		throw std::runtime_error("Ошибка при захвате пакетов: " + std::string(pcap_geterr(handle)));
	}
}	

// Callback-обработчик для пакета
void PacketSniffer::distribute_packets(u_char* user, const struct pcap_pkthdr* packetHeader, const u_char* packet) {
	PacketType packet_type = analyze_packet(packetHeader, packet);
}

/* В текущей версии нет проверки на то, что packetHeader->caplen (длина захваченной части пакета) достаточна,
   чтобы пакет вмещал хотя бы заголовки Ethernet и IP/TCP минимальной длины. Из-за этого есть риск считывать
   данные за пределами пакета.
   Кроме того, проверка на протокол FTP примитивна и всего лишь проверяет порты источника и назначения, то есть не сработает в пассивном режиме FTP или при нестандартной настройке.
*/
PacketType PacketSniffer::analyze_packet(const struct pcap_pkthdr* packetHeader, const u_char* packet) {
	// Отступаем 14 байт от начала пакета, чтобы пропустить заголовок Ethernet
	const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packet + SIZE_ETHERNET_HEADER);

	// Проверка на версию протокола IP
	if (ipHeader->ip_v != 4) return TYPE_OTHER;

	int size_ip = ipHeader->ip_hl * 4;
	if (size_ip < 20) {
		throw std::runtime_error("Длина заголовка IP меньше 20 байт: " + size_ip);
	}

	uint16_t port_src = 0, port_dest = 0;
	
	// Определим протокол в заголовке IP
	if (ipHeader->ip_p == IPPROTO_TCP) {
		// Протокол TCP - попробуем опознать FTP по номеру порта
		const struct tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(packet + SIZE_ETHERNET_HEADER + size_ip);
		port_src = tcpHeader->th_sport;
		port_dest = tcpHeader->th_dport;
	} else { 
		// UDP или иной протокол
		return TYPE_OTHER;
	}

	if (port_src == PORT_FTP_CONTROL || port_dest == PORT_FTP_CONTROL) {
		// Порт 21 - поток управления
		return TYPE_FTP_CONTROL;
	} else if (port_src == PORT_FTP_DATA || port_dest == PORT_FTP_DATA) {
		// Порт 20 - поток данных
		return TYPE_FTP_DATA;
	} else {
		// Не FTP
		return TYPE_OTHER;
	}
}