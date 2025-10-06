#include <x_509.hpp>
#include <iostream>

namespace ntk {

	// =========================
    //  Is Constructed Type Tag
    // =========================

	bool is_constructed_type_tag( const uint8_t tag_byte ) {
    	return ( tag_byte & 0x20 ) != 0;
	}

	// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
	bool is_constructed_type_tag( const tag_type tag ) {
    	return is_constructed_type_tag( static_cast<uint8_t>( tag ) );
    }

	// ===================
    //  Parse Ans1 Length 
    // ===================

	std::expected<parse_length_result,std::string> parse_ans1_length( std::span<const uint8_t> certificate_bytes ) {
		constexpr std::size_t minimum_len = 2 /* ans1 byte + single-byte length field */; 
		constexpr std::size_t sb = 1 /* single-byte length field offset */;
		if ( certificate_bytes.size() < minimum_len ) {
			return std::unexpected( "Certificate is too short for Single-Byte Length Field" );
		}
		std::size_t header_len{};
		std::size_t node_len{};
		if ( certificate_bytes[ sb ] < 0x80 /* length is <= 127 */ ) {
			header_len = minimum_len;
			node_len = certificate_bytes[ sb ];
		} else {
			std::size_t num_len_bytes = certificate_bytes[ sb ] & 0x7f /* clear the highest bit */;
			if ( certificate_bytes.size() < minimum_len + num_len_bytes ) {
				return std::unexpected( "Certificate is too short for Multi-Byte Length Field" );
			}
			for ( std::size_t i = 0; i < num_len_bytes; ++i ) {
				node_len = ( node_len << 8 ) | certificate_bytes[ minimum_len + i ];
			}
			header_len = minimum_len + num_len_bytes;
		}
		if ( certificate_bytes.front() == 0x03 ) {
			if ( certificate_bytes.size() < header_len + 1 ) {
           		return std::unexpected( "Truncated BIT STRING (missing unused-bits byte)" );
        	}
        	header_len += 1;
        	node_len -= 1;
		}
		return parse_length_result{ header_len, node_len };
	}

    // ===============
    //  Get Raw Bytes 
    // ===============

   	std::expected<void,std::string> get_raw_bytes( asn1_node& node, std::span<const uint8_t> certificate_bytes, 
   											       const parse_length_result& length_result ) {
   		if ( certificate_bytes.size() < length_result.header_len + length_result.node_len ) {
   			return std::unexpected( "Certificate Node is truncated" );
   		}
   	   	node.raw_bytes = std::span<const uint8_t>( certificate_bytes.data() + length_result.header_len, length_result.node_len ); 
   	   	return {};
   	}

   	// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
   	std::vector<uint8_t> get_raw_bytes( auto& it ) {
    	auto bytes = std::vector<uint8_t>{ ( *it )->raw_bytes.begin(), ( *it )->raw_bytes.end() };
    	++it;
    	return bytes;
    } 

   	// ================
    //  Parse Children 
    // ================

    std::expected<void,std::string> parse_children( asn1_node& parent, int target_depth, int current_depth ) {
    	if ( target_depth >= 0 && current_depth >= target_depth ) {
    		return {};
    	}
   		if ( parent.leaf ) {
    		return {};
    	}
    	auto bytes = parent.raw_bytes;
    	while ( !bytes.empty() ) {
    		auto child = std::make_unique<asn1_node>();
    		auto length_result = parse_ans1_length( bytes );
    		if ( !length_result ) {
    			return std::unexpected( length_result.error() );
    		}
    		auto result = get_raw_bytes( *child, bytes, length_result.value() );
    		if ( !result ) {
    			return std::unexpected( result.error() );
    		}
    		auto tag_opt = get_tag_type( bytes.front() );
    		if ( !tag_opt ) {
    			return std::unexpected( "Unrecognized Tag Type" );
    		}
    		child->tag = tag_opt.value();
    		if ( !is_constructed_type_tag( child->tag ) ) {
    			child->leaf = true;
    		}
    		parent.children.push_back( std::move( child ) );
    		bytes = bytes.subspan( length_result.value().header_len + length_result.value().node_len );
    	}
    	for ( auto& child : parent.children ) {
    		auto parse_result = parse_children( *child, target_depth, current_depth + 1 );
    		if ( !parse_result ) {
    			return std::unexpected( parse_result.error() ); 
    		}
    	}
    	return {};
    }

	// ========================
    //  Get Parsed Certificate
    // ========================

    std::expected<certificate,std::string> get_parsed_certificate( std::span<const uint8_t> certificate_bytes, int target_depth ) {
    	int current_depth{};
    	certificate cert;
    	auto head = std::make_unique<asn1_node>();
    	auto tag_opt = get_tag_type( certificate_bytes.front() );
    	if ( !tag_opt ) {
    		return std::unexpected( "Unrecognized Tag Type" );
    	}
    	head->tag = tag_opt.value();
    	if ( !is_constructed_type_tag( head->tag ) ) {
    		head->leaf = true;
    	}
  		auto length_result = parse_ans1_length( certificate_bytes );
  		if ( !length_result ) {
  			return std::unexpected( length_result.error() );
  		}
    	auto result = get_raw_bytes( *head, certificate_bytes, length_result.value() );
    	if ( !result ) {
    		return std::unexpected( result.error() );
    	}
    	if ( !head->leaf ) {
	    	auto parse_result = parse_children( *head, target_depth, current_depth );
	    	if ( !parse_result ) {
	    		return std::unexpected( parse_result.error() );
	    	}
	    }
    	cert.head = std::move( head );
    	return cert;
    }

    // =====================
    //  Get Tbs Certificate
    // =====================

    std::expected<tbs_certificate,std::string> get_tbs_certificate( std::span<const uint8_t> certificate_bytes ) {
    	tbs_certificate certificate;
    	auto parse_result = get_parsed_certificate( certificate_bytes, 2 /* parse to tbs certificate children */ );
    	if ( !parse_result ) {
    		return std::unexpected( parse_result.error() );
    	}
    	auto& parsed_tbs_certificate = parse_result.value().head->children.front();
    	if ( parsed_tbs_certificate->children.empty() ) {
    		return std::unexpected( "Tbs Certificate has no fields" );
    	}
    	if ( parsed_tbs_certificate->children.front()->tag == tag_type::context_0 ) {
    		certificate.version = parsed_tbs_certificate->children.front()->raw_bytes.front();
    	} else {
    		certificate.version = std::nullopt;
    	}
    	std::size_t fields_required = certificate.version ? 7 : 6;
    	if ( parsed_tbs_certificate->children.size() < fields_required ) {
    		return std::unexpected( "Tbs Certificate does not have enough fields" ); 
    	}
    	auto it = parsed_tbs_certificate->children.begin();
    	if ( certificate.version ) {
    		it = std::next( it );
    	}
    	certificate.serial_number = std::move( get_raw_bytes( it ) );    	
    	certificate.algorithm_identifier = std::move( get_raw_bytes( it ) );
    	certificate.issuer_rnd = std::move( get_raw_bytes( it ) );
    	certificate.validity = std::move( get_raw_bytes( it ) );
    	certificate.subject_rnd = std::move( get_raw_bytes( it ) );
    	certificate.subject_public_key_info = std::move( get_raw_bytes( it ) );
    	if ( it != parsed_tbs_certificate->children.end() ) {
    		certificate.extensions = std::move( get_raw_bytes( it ) );
    	} else {
    		certificate.extensions = std::nullopt;
    	}
    	return certificate;
    }

    // ==============
    //  Get Children
    // ==============

    std::expected<std::vector<std::vector<uint8_t>>,std::string> get_children( std::span<const uint8_t> certificate_bytes ) {
    	auto length_result = parse_ans1_length( certificate_bytes );
	    if ( !length_result ) {
	    	return std::unexpected( length_result.error() );
	    }
    	auto [ header_len, node_len ] = length_result.value();
    	certificate_bytes = certificate_bytes.subspan( header_len );
    	return get_children_from_raw_bytes( certificate_bytes );
    }

    // ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    std::expected<std::vector<std::vector<uint8_t>>,std::string> get_children_from_raw_bytes( std::span<const uint8_t> certificate_bytes ) {
    	std::vector<std::vector<uint8_t>> children;
    	while ( !certificate_bytes.empty() ) {
	    	auto length_result = parse_ans1_length( certificate_bytes );
	    	if ( !length_result ) {
	    		return std::unexpected( length_result.error() ); 
	    	}
	    	auto [ header_len, node_len ] = length_result.value();
	    	certificate_bytes = certificate_bytes.subspan( header_len );
	    	children.emplace_back( certificate_bytes.begin(), 
	    						   certificate_bytes.begin() + node_len );
	    	certificate_bytes = certificate_bytes.subspan( node_len );
    	}
    	return children;
    }

    // ===============
    //  Get Signature
    // ===============

    std::expected<ecdsa_signature,std::string> get_ecdsa_signature( std::span<const uint8_t> certificate_bytes ) {
    	ecdsa_signature signature;
    	auto certificate_parse_result = get_parsed_certificate( certificate_bytes, 1 /* parse to signature */ );
    	if ( !certificate_parse_result ) {
    		return std::unexpected( certificate_parse_result.error() );
    	}
    	auto& parsed_ecdsa_signature = certificate_parse_result.value().head->children.back();
    	auto sequence_bytes = parsed_ecdsa_signature->raw_bytes;
    	auto children_result = get_children( sequence_bytes );
    	if ( !children_result ) {
    		return std::unexpected( children_result.error() );
    	}
    	auto& children = children_result.value();
    	signature.r = std::move( children.front() );
    	signature.s = std::move( children.back() );
    	return signature;
    }

    // =========================
    //  Get Signature Algorithm
    // =========================

    std::expected<std::vector<uint8_t>,std::string> get_signature_algorithm( std::span<const uint8_t> certificate_bytes ) {
    	auto certificate_parse_result = get_parsed_certificate( certificate_bytes, 1 /* parse to signature */ );
    	if ( !certificate_parse_result ) {
    		return std::unexpected( certificate_parse_result.error() );
    	}
    	if ( certificate_parse_result.value().head->children.size() < 2 ) {
    		return std::unexpected( "Certificate does not contain a Signature Algorithm" );
    	}
    	auto& sequence = certificate_parse_result.value().head->children[ 1 ];
   		auto children_result = get_children_from_raw_bytes( sequence->raw_bytes );
   		if ( !children_result ) {
   			return std::unexpected( children_result.error() );   		
   		}
   		auto& children = children_result.value();
   		return children.front(); 
    }

} // namespace ntk
