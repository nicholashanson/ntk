#ifndef X_509_HPP
#define X_509_HPP

#include <cstdint>

#include <chrono>
#include <expected>
#include <map>
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
    	std::vector<uint8_t> issuer_rdn;
    	std::vector<uint8_t> validity;
    	std::vector<uint8_t> subject_rdn;
    	std::vector<uint8_t> subject_public_key_info;
    	std::optional<std::vector<uint8_t>> extensions;
    };

    inline std::map<std::string,std::string> algorithm_identifier_names = {
    	{ "1.2.840.10045.4.3.2", "ECDSA with SHA256" }
    };

	// =========
    //  Tbs Rdn
    // =========

    struct tbs_rdn {
    	std::vector<uint8_t> oid;
    	std::string value;
    }; 

    // ==============
    //  Tbs Validity
    // ==============

    struct tbs_validity {
    	std::chrono::system_clock::time_point not_before;
    	std::chrono::system_clock::time_point not_after;
    };

    // =========================
    //  Subject Public Key Info
    // =========================

    struct subject_public_key_info {
    	std::vector<uint8_t> algorithm;
    	std::vector<uint8_t> parameters;
    	std::vector<uint8_t> key;
    };

    // ===========
    //  Extension
    // ===========

    struct extension {
    	std::vector<uint8_t> id;
    	std::vector<uint8_t> value;
    	std::optional<bool> critical;
    };

    inline std::map<std::string,std::string> object_identifier_names = {
    	{ "1.2.840.10045.2.1",                             "EC Public Key" },
    	{ "1.2.840.10045.3.1.7",                  "prime256v1 (secp256r1)" },
    	{ "2.5.4.6", 								        "Country Name" },
    	{ "2.5.4.10", 								   "Organization Name" },
    	{ "2.5.4.3", 								         "Common Name" },
    	{ "2.5.29.15",                                         "Key Usage" },
		{ "2.5.29.37",							           "Ext Key Usage" },
		{ "2.5.29.19", 							       "Basic Constraints" },
		{ "2.5.29.14",							  "Subject Key Identifier" },
		{ "2.5.29.35",				            "Authority Key Identifier" },
		{ "1.3.6.1.5.5.7.1.1", 				   	   "Authority Info Access" },
		{ "2.5.29.17",						            "Subject Alt Name" },
		{ "2.5.29.32", 							    "Certificate Policies" },
		{ "2.5.29.31",						     "CRL Distribution Points" },
		{ "1.3.6.1.4.1.11129.2.4.2", "Google Signed Certificate Timestamp" }
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

	std::expected<std::vector<extension>,std::string> get_extensions( std::span<const uint8_t> certificate_bytes );

	std::expected<std::vector<extension>,std::string> get_extensions( const tbs_certificate& cert );

	std::expected<std::vector<extension>,std::string> get_extensions( const std::vector<std::vector<uint8_t>>& extensions_bytes );
	
	std::expected<extension,std::string> get_extension( std::span<const uint8_t> extension_bytes );

	std::expected<std::string,std::string> convert_oid_to_dotted_string( std::span<const uint8_t> oid_bytes );

	std::expected<std::vector<std::vector<uint8_t>>,std::string> get_nodes( std::span<const uint8_t> certificate_bytes );

    std::expected<std::vector<std::vector<uint8_t>>,std::string> get_nodes_from_raw_bytes( std::span<const uint8_t> certificate_bytes );

    std::expected<std::chrono::system_clock::time_point,std::string> parse_utc_time( std::span<const uint8_t> utc_time_bytes );

    std::expected<tbs_validity,std::string> get_tbs_validity( std::span<const uint8_t> validity_bytes );

    std::expected<std::vector<tbs_rdn>,std::string> get_tbs_rdns( std::span<const uint8_t> rdn_bytes );

    std::expected<subject_public_key_info,std::string> get_subject_public_key_info( std::span<const uint8_t> public_key_bytes );

    std::expected<std::string,std::string> get_algorithm_identifier( std::span<const uint8_t> algorithm_bytes );

} // namespace ntk

#endif // X_509_HPP