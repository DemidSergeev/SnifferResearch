#pragma once

#include "packet_types.h"
#include "packet_handler.h"
#include "packet_sniffer.h"

// Фабричный класс для создания обработчика нужного класса по enum типа пакета
class PacketHandlerFactory {
    public:
        static std::unique_ptr<PacketHandler> from_packet_type(const PacketSniffer& sniffer, PacketType packet_type);
};