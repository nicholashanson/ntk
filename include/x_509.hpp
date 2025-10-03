#include <cstdint>

#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace ntk {

	// =====================
    //  Parse Length Result
    // =====================

	struct parse_length_result {
		std::size_t header_len;
		std::size_t node_len;
	};

	// ==========
    //  Tag Type
    // ==========

	enum class tag_type : uint8_t {
		bit_string = 0x03,
		sequence   = 0x30
	};

	struct asn1_node {
		tag_type tag;
		std::span<const uint8_t> raw_bytes;
		std::vector<std::unique_ptr<asn1_node>> children;
	};

	struct certificate {
		std::unique_ptr<asn1_node> head;
	};

	std::expected<parse_length_result,std::string> parse_ans1_length( std::span<const uint8_t> certificate_bytes );

	std::expected<certificate,std::string> get_parsed_certificate( std::span<const uint8_t> certificate_bytes );

} // namespace ntk