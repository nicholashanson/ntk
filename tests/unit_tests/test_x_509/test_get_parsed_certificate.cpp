#include <gtest/gtest.h>

#include <x_509.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetParsedCertificate ) {
	auto parse_result = ntk::get_parsed_certificate( test::tls_certificate );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& parsed_certificate = parse_result.value();
	EXPECT_EQ( parsed_certificate.head->tag, ntk::tag_type::sequence );
	EXPECT_EQ( parsed_certificate.head->children.size(), 3 );
	EXPECT_EQ( parsed_certificate.head->children.front()->tag, ntk::tag_type::sequence );
	EXPECT_EQ( parsed_certificate.head->children[ 1 ]->tag, ntk::tag_type::sequence );
	EXPECT_EQ( parsed_certificate.head->children.back()-> tag, ntk::tag_type::bit_string );
}

TEST( UnitTest, GetParsedCertificate_TbsCertificate ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 4, 4 + 845 ); 
	auto parse_result = ntk::get_parsed_certificate( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& parsed_certificate = parse_result.value();
	EXPECT_EQ( parsed_certificate.head->tag, ntk::tag_type::sequence );
	EXPECT_EQ( parsed_certificate.head->children.size(), 8 );
	EXPECT_EQ( parsed_certificate.head->children[ 1 ]->tag, ntk::tag_type::integer );
}

TEST( UnitTest, GetParsedCertificate_TbsCertificate_Version ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 4 + 4, 5 );
	auto parse_result = ntk::get_parsed_certificate( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& parsed_certificate = parse_result.value();
	EXPECT_EQ( parsed_certificate.head->children.size(), 1 );
	EXPECT_EQ( parsed_certificate.head->children.front()->tag, ntk::tag_type::integer ); 
}

TEST( UnitTest, GetParsedCertificate_TbsCertificate_Version_Integer ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 4 + 4 + 2, 3 );
	auto parse_result = ntk::get_parsed_certificate( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& parsed_certificate = parse_result.value();
	EXPECT_EQ( parsed_certificate.head->children.size(), 0 );
	EXPECT_EQ( parsed_certificate.head->tag, ntk::tag_type::integer );
	EXPECT_EQ( parsed_certificate.head->raw_bytes.size(), 1 );
}

TEST( UnitTest, GetParsedCertificate_IssuerRdnSequence ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 43, 61 ); 
	auto parse_result = ntk::get_parsed_certificate( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& issuer_rdn_sequence = parse_result.value();
	EXPECT_EQ( issuer_rdn_sequence.head->tag, ntk::tag_type::sequence );
	EXPECT_EQ( issuer_rdn_sequence.head->children.size(), 3 );
	EXPECT_EQ( issuer_rdn_sequence.head->children.front()->tag, ntk::tag_type::set );
	EXPECT_EQ( issuer_rdn_sequence.head->children[ 1 ]->tag, ntk::tag_type::set );
	EXPECT_EQ( issuer_rdn_sequence.head->children.back()->tag, ntk::tag_type::set );
} 

TEST( UnitTest, GetParsedCertificate_RelativeDistinguishedName ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 45, 13 ); 
	auto parse_result = ntk::get_parsed_certificate( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& rdn = parse_result.value();
	EXPECT_EQ( rdn.head->tag, ntk::tag_type::set );
	EXPECT_EQ( rdn.head->children.size(), 1 );
} 

TEST( UnitTest, GetParsedCertificate_Signature_Sequence ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 868, 71 ); 
	auto parse_result = ntk::get_parsed_certificate( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& sequence = parse_result.value();
	EXPECT_EQ( sequence.head->children.size(), 2 );
} 
