#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ParseAns1Length ) {
	auto parse_result = ntk::parse_ans1_length( test::tls_certificate );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto [ header_len, node_len ] = parse_result.value();
	EXPECT_EQ( header_len, 4 );
	EXPECT_EQ( node_len, 935 );
}

TEST( UnitTest, ParseAns1Length_TbsCertificate ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 4 );
	auto parse_result = ntk::parse_ans1_length( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto [ header_len, node_len ] = parse_result.value();
	EXPECT_EQ( header_len, 4 );
	EXPECT_EQ( node_len, 845 ); 
}

TEST( UnitTest, ParseAns1Length_SignatureAlgorithm ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 4 + 4 + 845 );
	auto parse_result = ntk::parse_ans1_length( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto [ header_len, node_len ] = parse_result.value();
	EXPECT_EQ( header_len, 2 );
	EXPECT_EQ( node_len, 10 ); 
}

TEST( UnitTest, ParseAns1Length_Signatue ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 4 + 4 + 845 + 2 + 10 );
	auto parse_result = ntk::parse_ans1_length( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto [ header_len, node_len ] = parse_result.value();
	EXPECT_EQ( header_len, 3 );
	EXPECT_EQ( node_len, 71 );
}

TEST( UnitTest, ParseAns1Length_Integer ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 4 + 4 + 2, 3 );
	auto parse_result = ntk::parse_ans1_length( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto [ header_len, node_len ] = parse_result.value();
	EXPECT_EQ( header_len, 2 );
	EXPECT_EQ( node_len, 1 );
}

TEST( UnitTest, ParseAns1Length_Signatue_Sequence ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 868, 71 );
	auto parse_result = ntk::parse_ans1_length( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto [ header_len, node_len ] = parse_result.value();
	EXPECT_EQ( header_len, 2 );
	EXPECT_EQ( node_len, 69 );
}

