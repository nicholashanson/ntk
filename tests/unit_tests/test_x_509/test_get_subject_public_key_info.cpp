#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetSubjectPublicKeyInfo ) {
	auto s = std::span<const uint8_t>( test::tls_certificate );
	s = s.subspan( 163, 89 );
	auto parse_result = ntk::get_subject_public_key_info( s );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& public_key_info = parse_result.value();
	auto alogorithm_result = ntk::convert_oid_to_dotted_string( public_key_info.algorithm );
	ASSERT_TRUE( alogorithm_result ) << alogorithm_result.error() << std::endl;
	auto& algorithm = alogorithm_result.value();
	EXPECT_EQ( algorithm, "1.2.840.10045.2.1" );
	auto parameters_result = ntk::convert_oid_to_dotted_string( public_key_info.parameters );
	ASSERT_TRUE( parameters_result ) << parameters_result.error() << std::endl;
	auto& parameters = parameters_result.value();
	EXPECT_EQ( parameters, "1.2.840.10045.3.1.7" );
}


TEST( UnitTest, GetSubjectPublicKeyInfoFromCert ) {
	auto parse_result = ntk::get_subject_public_key_info_from_cert( test::tls_certificate );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& public_key_info = parse_result.value();
	auto alogorithm_result = ntk::convert_oid_to_dotted_string( public_key_info.algorithm );
	ASSERT_TRUE( alogorithm_result ) << alogorithm_result.error() << std::endl;
	auto& algorithm = alogorithm_result.value();
	EXPECT_EQ( algorithm, "1.2.840.10045.2.1" );
	auto parameters_result = ntk::convert_oid_to_dotted_string( public_key_info.parameters );
	ASSERT_TRUE( parameters_result ) << parameters_result.error() << std::endl;
	auto& parameters = parameters_result.value();
	EXPECT_EQ( parameters, "1.2.840.10045.3.1.7" );
}