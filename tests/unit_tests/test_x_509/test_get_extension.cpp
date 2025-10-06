#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetExtension_KeyUsage ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 260, 16 ); 
	auto parse_result = ntk::get_extension( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& extension = parse_result.value();
	std::vector<uint8_t> expected_id{ 0x55, 0x1d, 0x0f };
	std::vector<uint8_t> expected_value{ 0x03, 0x02, 0x07, 0x80 };
	EXPECT_EQ( extension.id, expected_id );
	EXPECT_EQ( extension.value, expected_value );
	ASSERT_TRUE( extension.critical );
	EXPECT_TRUE( extension.critical.value() );
}

TEST( UnitTest, GetExtension_ExtKeyUsage ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 276, 21 ); 
	auto parse_result = ntk::get_extension( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& extension = parse_result.value();
	std::vector<uint8_t> expected_id{ 0x55, 0x1d, 0x25 };
	std::vector<uint8_t> expected_value{ 
		0x30, 0x0a, 0x06,
		0x08, 0x2b, 0x06, 
		0x01, 0x05, 0x05, 
		0x07, 0x03, 0x01 };
	EXPECT_EQ( extension.id, expected_id );
	EXPECT_EQ( extension.value, expected_value );
}

TEST( UnitTest, GetExtension_BasicConstraints ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 297, 14 ); 
	auto parse_result = ntk::get_extension( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& extension = parse_result.value();
	std::vector<uint8_t> expected_id{ 0x55, 0x1d, 0x13 };
	std::vector<uint8_t> expected_value{ 0x30, 0x00 };
	EXPECT_EQ( extension.id, expected_id );
	EXPECT_EQ( extension.value, expected_value );
	ASSERT_TRUE( extension.critical );
	EXPECT_TRUE( extension.critical.value() );
}

TEST( UnitTest, GetExtension_SubjectKeyIdentifier ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 311, 31 ); 
	auto parse_result = ntk::get_extension( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& extension = parse_result.value();
	std::vector<uint8_t> expected_id{ 0x55, 0x1d, 0x0e };
	std::vector<uint8_t> expected_value{ 
		0x04, 0x14, 0xb1, 0x2e, 0xc8, 0x72, 
		0xc0, 0x37, 0x58, 0xec, 0xd9, 0xd1, 
		0x9a, 0x7b, 0x45, 0xcc, 0xb7, 0x6f, 
		0xf5, 0xc1, 0xaf, 0xfb };
	EXPECT_EQ( extension.id, expected_id );
	EXPECT_EQ( extension.value, expected_value );
}

TEST( UnitTest, GetExtension_AuthorityKeyIdentifier ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 342, 33 ); 
	auto parse_result = ntk::get_extension( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& extension = parse_result.value();
	std::vector<uint8_t> expected_id{ 0x55, 0x1d, 0x23 };
	std::vector<uint8_t> expected_value{ 
		0x30, 0x16, 0x80, 0x14, 0x90, 0x77, 0x92, 0x35, 0x67,  
		0xc4, 0xff, 0xa8, 0xcc, 0xa9, 0xe6, 0x7b, 0xd9, 0x80, 
		0x79, 0x7b, 0xcc, 0x93, 0xf9, 0x38, };
	EXPECT_EQ( extension.id, expected_id );
	EXPECT_EQ( extension.value, expected_value );
}

TEST( UnitTest, GetExtension_AuthorityInfoAccess ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 375, 96 ); 
	auto parse_result = ntk::get_extension( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& extension = parse_result.value();
	std::vector<uint8_t> expected_id{ 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
	std::vector<uint8_t> expected_value{ 
		0x30, 0x50, 0x30, 0x27, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
		0x05, 0x07, 0x30, 0x01, 0x86, 0x1B, 0x68, 0x74, 0x74, 0x70,
		0x3a, 0x2f, 0x2f, 0x6f, 0x2e, 0x70, 0x6B, 0x69, 0x2e, 0x67,
		0x6f, 0x6f, 0x67, 0x2f, 0x73, 0x2f, 0x77, 0x65, 0x31, 0x2f,
		0x66, 0x45, 0x49, 0x30, 0x25, 0x06, 0x08, 0x2B, 0x06, 0x01,
		0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x19, 0x68, 0x74, 0x74,
		0x70, 0x3a, 0x2f, 0x2f, 0x69, 0x2e, 0x70, 0x6B, 0x69, 0x2e,
		0x67, 0x6f, 0x6f, 0x67, 0x2f, 0x77, 0x65, 0x31, 0x2e, 0x63,
		0x72, 0x74
	};
	EXPECT_EQ( extension.id, expected_id );
	EXPECT_EQ( extension.value, expected_value );
}

TEST( UnitTest, GetExtension_CertificatePolicies ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 512, 21 ); 
	auto parse_result = ntk::get_extension( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& extension = parse_result.value();
	std::vector<uint8_t> expected_id{ 0x55, 0x1d, 0x20 };
	std::vector<uint8_t> expected_value{ 
		0x30, 0x0a, 0x30, 0x08, 0x06, 0x06, 0x67,
		0x81, 0x0c, 0x01, 0x02, 0x01
	};
	EXPECT_EQ( extension.id, expected_id );
	EXPECT_EQ( extension.value, expected_value );
}

TEST( UnitTest, GetExtension_CrlDistributionPoints ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 533, 56 ); 
	auto parse_result = ntk::get_extension( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& extension = parse_result.value();
	std::vector<uint8_t> expected_id{ 0x55, 0x1d, 0x1f };
	std::vector<uint8_t> expected_value{ 
		0x30, 0x2d, 0x30, 0x2b, 0xa0, 0x29, 0xa0, 0x27, 0x86, 0x25,
    	0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x63, 0x2e, 0x70, 
    	0x6b, 0x69, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x2f, 0x77, 0x65, 
    	0x31, 0x2f, 0x74, 0x58, 0x32, 0x48, 0x35, 0x68, 0x53, 0x46, 
    	0x77, 0x71, 0x45, 0x2e, 0x63, 0x72, 0x6c
	};
	EXPECT_EQ( extension.id, expected_id );
	EXPECT_EQ( extension.value, expected_value );
}

TEST( UnitTest, GetExtension_GoogleSignedCertificateTimestamp ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	auto x = s.subspan( 589, 264 ); 
	auto parse_result = ntk::get_extension( x );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& extension = parse_result.value();
	std::vector<uint8_t> expected_id{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02 };
	std::vector<uint8_t> expected_value( s.begin() + 608, s.begin() + 608 + 245 );
	EXPECT_EQ( extension.id, expected_id );
	EXPECT_EQ( extension.value, expected_value );
}