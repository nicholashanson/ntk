#include <cstdint>

#include <expected>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <utils.hpp>

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
		boolean           = 0x01,
		integer           = 0x02,
		bit_string        = 0x03,
		octet_string      = 0x04,
		object_identifier = 0x06,
		printable_string  = 0x13,
		utc_time		  = 0x17,
		sequence   		  = 0x30,
		set        	      = 0x31,
		context_0  		  = 0xa0,
		context_3  		  = 0xa3
	};

	namespace look_up {

        constexpr std::array<tag_type,11/* entries in enum tag_type */> tag_types = {
            tag_type::boolean,
			tag_type::integer,        
			tag_type::bit_string,        
			tag_type::octet_string,    
			tag_type::object_identifier,
			tag_type::printable_string, 
			tag_type::utc_time,		  
			tag_type::sequence,   		 
			tag_type::set,        	      
			tag_type::context_0,  		  
			tag_type::context_3  		
        };

    } // namespace look_up

    inline auto get_tag_type = make_lookup( look_up::tag_types );

	struct asn1_node {
		tag_type tag;
		std::span<const uint8_t> raw_bytes;
		std::vector<std::unique_ptr<asn1_node>> children;
		bool leaf = false;
	};

	struct certificate {
		std::unique_ptr<asn1_node> head;
	};

	// =================
    //  Tbs Certificate
    // =================

    struct tbs_certificate {
    	std::optional<uint8_t> version;
    	std::vector<uint8_t> serial_number;
    	std::vector<uint8_t> algorithm_identifier;
    	std::vector<uint8_t> issuer_rnd;
    	std::vector<uint8_t> validity;
    	std::vector<uint8_t> subject_rnd;
    	std::vector<uint8_t> subject_public_key_info;
    	std::optional<std::vector<uint8_t>> extensions;
    };

    // =================
    //  ECDSA Signature
    // =================

    struct ecdsa_signature {
    	std::vector<uint8_t> r;
    	std::vector<uint8_t> s;
    };

	std::expected<parse_length_result,std::string> parse_ans1_length( std::span<const uint8_t> certificate_bytes );

	std::expected<certificate,std::string> get_parsed_certificate( std::span<const uint8_t> certificate_bytes, int target_depth = -1 );

	std::expected<tbs_certificate,std::string> get_tbs_certificate( std::span<const uint8_t> certificate_bytes );

	std::expected<ecdsa_signature,std::string> get_ecdsa_signature( std::span<const uint8_t> certificate_bytes );

	std::expected<std::vector<std::vector<uint8_t>>,std::string> get_children( std::span<const uint8_t> certificate_bytes );

	std::expected<std::vector<std::vector<uint8_t>>,std::string> get_children_from_raw_bytes( std::span<const uint8_t> certificate_bytes );

	std::expected<std::vector<uint8_t>,std::string> get_signature_algorithm( std::span<const uint8_t> certificate_bytes );

	std::expected<std::vector<std::vector<uint8_t>>,std::string> get_extensions( std::span<const uint8_t> certificate_bytes );

} // namespace ntk