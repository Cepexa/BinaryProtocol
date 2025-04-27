#ifndef BINARY_PROTOCOL_HPP
#define BINARY_PROTOCOL_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <cstring>

// Шаблонная функция для конвертации простых типов в байтовую строку
template <typename T>
std::string to_bytes(T value) {
    // Проверяем, что тип T является тривиально копируемым (например, int, float, double)
    static_assert(std::is_trivially_copyable<T>::value, "T must be a trivially copyable type");

    // Создаём строку из sizeof(T) байт
    std::string bytes(sizeof(T), '\0');

    // Копируем байты значения в строку
    memcpy(&bytes[0], &value, sizeof(T));

    return bytes;
}

// Шаблонная функция для обратного преобразования байтовой строки в значение
template <typename T>
T from_bytes(const std::string& bytes) {
    // Проверяем, что тип T является тривиально копируемым
    static_assert(std::is_trivially_copyable<T>::value, "T must be a trivially copyable type");

    // Проверяем, что размер байтовой строки соответствует размеру типа T
    if (bytes.size() != sizeof(T)) {
        throw std::invalid_argument("Invalid byte string size for type T");
    }

    T value;
    memcpy(&value, bytes.data(), sizeof(T)); // Копируем байты в значение
    return value;
}

namespace BinaryProtocol {

// 📌 Код команд
enum CommandType : uint8_t {
    ERROR = 0x00,
    OK = 0x01,
    SQL = 0x02,
    EMPTY = 0x03,
    PING = 0xFF,
};

// 📌 SQL Тэги 
enum SQL_Tags : uint8_t {
    SELECT = 0x01,
    INSERT = 0x02,
    UPDATE = 0x03,
    DELETE,
    FROM,
    SET,
    WHERE,
    VALUES,
    JOIN,
    ON,
    ORDER_BY,
    DESC,
    AS,
    GROUP_BY
};

// 📌 Заголовок пакета
#pragma pack(push, 1)
struct PacketHeader {
    uint16_t magic = 0xABCD;   // Сигнатура пакета
    uint8_t version = 1;       // Версия протокола
    uint8_t command;           // Код команды
    uint32_t request_id;       // ID записи
    uint32_t payload_size;     // Размер полезных данных
};
#pragma pack(pop)

struct PacketBase {
    PacketHeader header;
    std::string payload;
    PacketBase(CommandType cmd, uint32_t req_id,const std::string& payload = {});
    std::vector<uint8_t> toBinary() const;
    static PacketBase fromBinary(const std::vector<uint8_t>& raw);
};

// 📌 Бинарный пакет
struct PacketRequest : PacketBase{
    PacketRequest(CommandType cmd, uint32_t req_id,const std::string& payload = {});
    static PacketRequest fromBinary(const std::vector<uint8_t>& raw);
    void addData(SQL_Tags tag, const std::string& data);
    void addData(const std::string& data_bytes);
    std::string getQuery();
};

struct PacketResponse : PacketBase{
    PacketResponse(CommandType cmd, uint32_t req_id,const std::string& payload = {});
    std::vector<uint8_t> toBinary();
    static PacketResponse fromBinary(const std::vector<uint8_t>& raw);
    void addNameValue(const std::string& name, const std::string& value);
    void addNameValue(const std::string& name, const char* value);
};

// 📌 Утилиты сериализации
namespace Serializer {
    std::vector<uint8_t> encodeString(const std::string& str);
    std::string decodeString(const std::vector<uint8_t>& data);
    std::vector<uint8_t> encodeInt(int32_t value);
    int32_t decodeInt(const std::vector<uint8_t>& data);
}

} // namespace BinaryProtocol

#endif // BINARY_PROTOCOL_HPP
