#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetAlgorithimIdentifier ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 33, 10 );
	auto parse_result = ntk::get_algorithm_identifier( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& algorithm_id = parse_result.value();
	EXPECT_EQ( algorithm_id, "1.2.840.10045.4.3.2" ); 
} 