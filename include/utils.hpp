#ifndef UTILS_HPP
#define UTILS_HPP

#include <span>
#include <cstdint>

namespace ntk {

    uint16_t read_uint16_be( const unsigned char* buffer, size_t offset );

    uint16_t read_uint16_be( const std::span<const uint8_t> buffer, size_t offset );

    uint32_t read_uint32_be( const unsigned char* buffer, size_t offset );

    uint32_t read_uint32_be( const std::span<const uint8_t> buffer, size_t offset );

} // namespace ntk

#endif // UTILS_HPP