#include "packet_sniffer.h"
#include "packet_handler_factory.h"

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/stat.h> // Для chmod

#include <csignal>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>


// Конструктор, инициализирующий `handle`
PacketSniffer::PacketSniffer(const std::string& interface) {
	char errbuf[PCAP_ERRBUF_SIZE];

	// Поднимаем обработчик останова по SIGINT
	std::signal(SIGINT, handle_signal);

	std::cout << "Имя интерфейса: " << interface << std::endl;
	handle = pcap_open_live(interface.c_str(), MAX_CAPTURE_BYTES, PROMISC, TIMEOUT_MS, errbuf);
	if (!handle) {
		throw std::runtime_error("Ошибка при открытии объекта:\n'" + std::string(errbuf) + "'");
	}	
	for (int i = 0; i < NUMBER_OF_TYPES; i++) {
		handlers.push_back(PacketHandlerFactory::from_packet_type(*this, (PacketType) i));
	}
}

// Деструктор -- закрытие `handle`.
PacketSniffer::~PacketSniffer() {
	if (handle) {
		pcap_close(handle);
	}
}

// Запускает потоки обработчиков пакетов, захватывает пакеты с интерфейса и вызывает распределитель.
void PacketSniffer::start_capture() {
	for (auto& handler: handlers) {
		handler.get()->start();
	}
	std::cout << "Начат захват пакетов." << std::endl;
	if (pcap_loop(handle, -1, distribute_packets, reinterpret_cast<u_char*>(this))) {
		throw std::runtime_error("Ошибка при захвате пакетов: " + std::string(pcap_geterr(handle)));
	}
}	

// Callback-обработчик для пакета
void PacketSniffer::distribute_packets(u_char* user, const struct pcap_pkthdr* packet_header, const u_char* packet) {
	PacketSniffer* sniffer = reinterpret_cast<PacketSniffer*>(user);
	PacketType packet_type = analyze_packet(packet_header, packet);
	// Добавляем пакет в очередь соответствующего обработчика
	sniffer->handlers[packet_type].get()->add_packet(packet_header, packet);

	if (stop_capture) {
		pcap_breakloop(sniffer->handle);
	}
}

/* Анализ пакета на протокол. Проверка на протокол FTP примитивна и всего лишь проверяет порты источника и назначения, то есть не сработает в пассивном режиме FTP или при нестандартной настройке.
*/
PacketType PacketSniffer::analyze_packet(const struct pcap_pkthdr* packet_header, const u_char* packet) {
	if (packet_header->caplen < SIZE_ETHERNET_HEADER + 20) {
		throw std::runtime_error("Размер захваченного пакета меньше суммы минимальных размеров заголовков Ethernet и IP: " + packet_header->caplen);
	}

	// Отступаем 14 байт от начала пакета, чтобы пропустить заголовок Ethernet
	const struct ip* ip_header = reinterpret_cast<const struct ip*>(packet + SIZE_ETHERNET_HEADER);

	// Проверка на версию протокола IP
	if (ip_header->ip_v != 4) return TYPE_OTHER;

	int size_ip = ip_header->ip_hl * 4;
	if (size_ip < 20) {
		throw std::runtime_error("Длина заголовка IP меньше 20 байт: " + size_ip);
	}

	uint16_t port_src = 0, port_dest = 0;
	
	// Определим протокол в заголовке IP
	if (ip_header->ip_p == IPPROTO_TCP) {
		// Протокол TCP - попробуем опознать FTP по номеру порта
		const struct tcphdr* tcp_header = reinterpret_cast<const struct tcphdr*>(packet + SIZE_ETHERNET_HEADER + size_ip);
		port_src = tcp_header->th_sport;
		port_dest = tcp_header->th_dport;
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

// Обработчик останова по SIGINT
void PacketSniffer::handle_signal(int signal) {
	if (signal == SIGINT) {
		stop_capture = true;
	}
}

// Геттер pcap хендла
pcap_t* PacketSniffer::getHandle() const {
	return handle;
}