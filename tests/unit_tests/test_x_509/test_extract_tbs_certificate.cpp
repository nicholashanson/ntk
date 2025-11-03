#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_certificates.hpp>

TEST( UnitTest, ExtractTbsCertificate ) {
	auto result = ntk::extract_tbs_certificate( test_constants::tls_certificate_0 );
	ASSERT_TRUE( result ) << result.error();
	EXPECT_EQ( result.value().size(), 849 );
}