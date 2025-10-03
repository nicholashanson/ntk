#include <cstdint>

#include <expected>
#include <span>
#include <string>

namespace ntk {

	std::expected<std::size_t,std::string> parse_ans1_length( std::span<const uint8_t> certificate_bytes );

} // namespace ntk