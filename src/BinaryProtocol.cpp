#include "BinaryProtocol.hpp"
#include <stdexcept>
#include <unordered_map>

namespace BinaryProtocol {

// 📌 Конструктор пакета
PacketBase::PacketBase(CommandType cmd, uint32_t req_id, const std::string& payload)
    : header{0xABCD, 1, static_cast<uint8_t>(cmd), req_id}, payload(payload) {}

// 📌 Сериализация пакета в бинарный формат
std::vector<uint8_t> PacketBase::toBinary() const {
    std::vector<uint8_t> binary(sizeof(PacketHeader) + payload.size());
    std::memcpy(binary.data(), &header, sizeof(PacketHeader));
    std::memcpy(binary.data() + sizeof(PacketHeader), payload.data(), payload.size());
    return binary;
}

// 📌 Десериализация пакета из бинарного формата
PacketBase PacketBase::fromBinary(const std::vector<uint8_t>& raw) {
    if (raw.size() < sizeof(PacketHeader)) {
        throw std::runtime_error("Invalid packet size");
    }
    
    PacketHeader header;
    std::memcpy(&header, raw.data(), sizeof(PacketHeader));
    
    if (header.magic != 0xABCD) {
        throw std::runtime_error("Invalid packet signature");
    }

    std::string payload(raw.begin() + sizeof(PacketHeader), raw.end());

    return PacketBase(static_cast<CommandType>(header.command), header.request_id, payload);
}

PacketResponse::PacketResponse(CommandType cmd, uint32_t req_id, const std::string& payload)
    : PacketBase::PacketBase(cmd, req_id, payload) {}

PacketResponse PacketResponse::fromBinary(const std::vector<uint8_t>& raw) {
    PacketBase base = PacketBase::fromBinary(raw);
    return PacketResponse(static_cast<CommandType>(base.header.command), base.header.request_id, base.payload);
}


PacketRequest::PacketRequest(CommandType cmd, uint32_t req_id, const std::string& payload)
    : PacketBase::PacketBase(cmd, req_id, payload) {}
    

void PacketRequest::addData(SQL_Tags tag, const std::string& data)
{
    payload += tag;
    addData(data);
}

void PacketRequest::addData(const std::string& data_bytes)
{
    size_t sz = data_bytes.size();
    if (sz < 0xFF)
    {
        payload += static_cast<uint8_t>(sz);              // Записываем 1 байт
    }
    else
    {
        payload += static_cast<uint8_t>(0xFF);             // Маркер расширенного размера
        payload += static_cast<uint8_t>(sz >> 8);          // Старший байт
        payload += static_cast<uint8_t>(sz & 0xFF);        // Младший байт
    }
    payload += data_bytes;
}

std::string PacketRequest::getQuery()
{
    static const std::unordered_map<uint8_t, std::string> tagNames = {
        {SELECT, "SELECT"     }, {INSERT,   "INSERT INTO"}, {UPDATE, "UPDATE"}, 
        {DELETE, "DELETE FROM"}, {FROM,     "FROM"       }, {SET,    "SET"   }, 
        {WHERE,  "WHERE"      }, {VALUES,   "VALUES"     }, {JOIN,   "JOIN"  }, 
        {ON,     "ON"         }, {ORDER_BY, "ORDER BY"   }, {DESC,   "DESC"  },
        {AS,     "AS"         }, {GROUP_BY, "GROUP BY"   }
    };

    std::string result;
    size_t pos = 0;

    while (pos < payload.size())
    {
        // Извлекаем тег
        uint8_t tagValue = static_cast<uint8_t>(payload[pos++]);
        auto tagIt = tagNames.find(tagValue);
        std::string tagStr = (tagIt != tagNames.end()) ? tagIt->second : "UNKNOWN_TAG";

        result += tagStr + " ";

        // Извлекаем размер данных
        size_t sz = static_cast<uint8_t>(payload[pos++]);

        if (sz == 0xFF) // Расширенный размер (2 байта)
        {
            if (pos + 2 > payload.size()) break; // Проверка границ
            sz = (static_cast<uint8_t>(payload[pos]) << 8) |
                 (static_cast<uint8_t>(payload[pos + 1]));
            pos += 2;
        }

        // Извлекаем строку данных
        if (pos + sz > payload.size()) break; // Проверка границ
        std::string data = payload.substr(pos, sz);
        pos += sz;

        result += data + " ";
    }
    result += ";";

    return result;
}



// 📌 Кодирование строки в бинарный формат
std::vector<uint8_t> Serializer::encodeString(const std::string& str) {
    std::vector<uint8_t> result(str.begin(), str.end());
    return result;
}

// 📌 Декодирование строки из бинарного формата
std::string Serializer::decodeString(const std::vector<uint8_t>& data) {
    return std::string(data.begin(), data.end());
}

// 📌 Кодирование числа
std::vector<uint8_t> Serializer::encodeInt(int32_t value) {
    std::vector<uint8_t> result(sizeof(int32_t));
    std::memcpy(result.data(), &value, sizeof(int32_t));
    return result;
}

// 📌 Декодирование числа
int32_t Serializer::decodeInt(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(int32_t)) {
        throw std::runtime_error("Invalid int32 size");
    }
    int32_t value;
    std::memcpy(&value, data.data(), sizeof(int32_t));
    return value;
}

} // namespace BinaryProtocol
