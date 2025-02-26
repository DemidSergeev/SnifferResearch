#include "packet_handler_factory.h"
#include "ftp_control_handler.h"
#include "ftp_data_handler.h"
#include "other_handler.h"

std::unique_ptr<PacketHandler> PacketHandlerFactory::from_packet_type(const PacketSniffer& sniffer, PacketType packet_type) {
    std::cout << "Создание PacketHandler через фабрику...\n";
    switch (packet_type) {
        case TYPE_FTP_CONTROL:
            return std::make_unique<FtpControlHandler>(sniffer);
        case TYPE_FTP_DATA:
            return std::make_unique<FtpDataHandler>(sniffer);
        case TYPE_OTHER:
            return std::make_unique<OtherHandler>(sniffer);
    }
}