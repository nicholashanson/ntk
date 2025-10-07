#include <gtest/gtest.h> 

#include <x_509.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetTbsCertificate ) {
	auto parse_result = ntk::get_tbs_certificate( test::tls_certificate );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& certificate = parse_result.value();
	ASSERT_TRUE( certificate.version );
	EXPECT_EQ( certificate.serial_number.size(), 16 );
	EXPECT_EQ( certificate.algorithm_identifier.size(), 10 );
	EXPECT_EQ( certificate.validity.size(), 30 );
	EXPECT_EQ( certificate.subject_rdn.size(), 23 );
	EXPECT_EQ( certificate.subject_public_key_info.size(), 89 );
	ASSERT_TRUE( certificate.extensions );
	EXPECT_EQ( certificate.extensions.value().size(), 597 );
}