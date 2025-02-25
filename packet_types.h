#pragma once

// Перечисление типов пакетов
enum PacketType {
    TYPE_FTP_CONTROL, TYPE_FTP_DATA, TYPE_OTHER,
    NUMBER_OF_TYPES // Последний член равен числу типов при нумерации с 0
};