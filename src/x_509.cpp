#include <x_509.hpp>
#include <iostream>

namespace ntk {

	bool is_constructed_type_tag( const uint8_t tag_byte ) {
    	return ( tag_byte & 0x20 ) != 0;
	}

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

   	// ================
    //  Parse Children 
    // ================

    std::expected<void,std::string> parse_children( asn1_node& parent ) {
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
    		auto parse_result = parse_children( *child );
    		if ( !parse_result ) {
    			return std::unexpected( parse_result.error() ); 
    		}
    	}
    	return {};
    }

	// ========================
    //  Get Parsed Certificate
    // ========================

    std::expected<certificate,std::string> get_parsed_certificate( std::span<const uint8_t> certificate_bytes ) {
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
    	get_raw_bytes( *head, certificate_bytes, length_result.value() );
    	if ( !head->leaf ) {
	    	auto parse_result = parse_children( *head );
	    	if ( !parse_result ) {
	    		return std::unexpected( parse_result.error() );
	    	}
	    }
    	cert.head = std::move( head );
    	return cert;
    }

} // namespace ntk
