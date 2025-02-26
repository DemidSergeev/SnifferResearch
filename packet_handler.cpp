#include "packet_handler.h"

#include <iostream>

// Запускает поток обработчика.
void PacketHandler::start() {
    is_running = true;
    worker_thread = std::thread(&PacketHandler::process_loop, this);
    std::cout << "PacketHandler запущен.\n";
}

// Останавливает поток обработчика.
void PacketHandler::stop() {
    is_running = false;
    cv.notify_all();
    if (worker_thread.joinable()) worker_thread.join();
    std::cout << "PacketHandler остановлен.\n";
}

// Добавляет `packet` в конец `packet_queue`.
void PacketHandler::add_packet(const pcap_pkthdr* packet_header, const u_char* packet) {
    {
        std::unique_lock<std::mutex> lock(mutex);
        packet_queue.push(std::pair<const pcap_pkthdr*, const u_char*>(packet_header, packet));
    }
    cv.notify_one();
}

// Цикл потока обработчика
void PacketHandler::process_loop() {
    while (is_running) {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] {
            return !packet_queue.empty() || !is_running;
        });
        
        // Break if capturing has stopped while the thread was waiting.
        if (!is_running) break;

        auto pair = std::move(packet_queue.front());
        packet_queue.pop();

        lock.unlock();

        auto packet_header = pair.first;
        auto packet = pair.second;
        process_packet(packet_header, packet);
    }
}