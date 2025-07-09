#ifndef UTILS_HPP
#define UTILS_HPP

#include <vector>
#include <cstdint>

namespace ntk {

	uint16_t read_uint16_be( const unsigned char* buffer, size_t offset );

    uint16_t read_uint16_be( const std::vector<uint8_t>& buffer, size_t offset );

    uint32_t read_uint32_be( const unsigned char* buffer, size_t offset );

    uint32_t read_uint32_be( const std::vector<uint8_t>& buffer, size_t offset );

} // namespace ntk

#endif // UTILS_HPP