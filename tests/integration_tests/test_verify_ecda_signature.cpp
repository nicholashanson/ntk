#include <gtest/gtest.h>

#include <io.hpp>
#include <x_509.hpp>

#include <test_certificates.hpp>

TEST( IntegrationTest, VerifyEcdaSignature ) {
	auto tbs_result = ntk::extract_tbs_certificate( test_constants::tls_certificate_0 );
	ASSERT_TRUE( tbs_result ) << tbs_result.error();
	auto sig_result = ntk::get_ecdsa_signature( test_constants::tls_certificate_0 );
	ASSERT_TRUE( sig_result ) << sig_result.error();
	auto pubkey_result = ntk::get_subject_public_key_info_from_cert( test_constants::tls_certificate_1 );
	ASSERT_TRUE( pubkey_result ) << pubkey_result.error();
	EXPECT_TRUE( ntk::verify_ecdsa_signature( tbs_result.value(), sig_result.value(), pubkey_result.value().key ) );
}