#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetExtension ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 260, 16 ); 
	auto parse_result = ntk::get_extension( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& extension = parse_result.value();
	std::vector<uint8_t> expected_id{ 0x55, 0x1d, 0x0f };
	std::vector<uint8_t> expected_value{ 0x03, 0x02, 0x07, 0x80 };
	EXPECT_EQ( extension.id, expected_id );
	EXPECT_EQ( extension.value, expected_value );
	EXPECT_TRUE( extension.critical );
}