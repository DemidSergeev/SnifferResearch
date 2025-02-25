#pragma once

#include <pcap.h>

#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

// Родительский класс для обработчиков.
class PacketHandler {
    public:
        void start();
        void stop();
        void add_packet(const pcap_pkthdr* packet_header, const u_char* packet);
        void process_loop();
        virtual void process_packet(const pcap_pkthdr* packet_header, const u_char* packet) const = 0;
        virtual ~PacketHandler() = default;

    private:
        std::queue<std::pair<const pcap_pkthdr*, const u_char*>> packet_queue;
        std::thread worker_thread;
        bool is_running;
        std::mutex mutex;
        std::condition_variable cv;
};
