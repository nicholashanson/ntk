#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, ParseSniList ) {
	std::vector<uint8_t> sni_list = {
    	0x00,                   
    	0x00, 0x0a,      
    	'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm'
	};
	std::span<const uint8_t> sni_list_span( sni_list ); 
	auto sni_result = ntk::parse_sni_list( sni_list_span );
	ASSERT_TRUE( sni_result ) << sni_result.error() << std::endl;
	ASSERT_EQ( sni_result.value(), "google.com" );
} 