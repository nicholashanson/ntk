#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, ExtrashHashSuffix ) {
	auto hash_256_cipher = ntk::cipher_suite::TLS_RSA_WITH_AES_128_GCM_SHA256;
	auto hash_384_cipher = ntk::cipher_suite::TLS_RSA_WITH_AES_256_GCM_SHA384;
	auto hash_256_result = ntk::extract_hash_suffix( hash_256_cipher );
	ASSERT_TRUE( hash_256_result ) << hash_256_result.error() << std::endl;
	EXPECT_EQ( hash_256_result.value(), "SHA256" );
	auto hash_384_result = ntk::extract_hash_suffix( hash_384_cipher );
	ASSERT_TRUE( hash_384_result ) << hash_384_result.error() << std::endl;
	EXPECT_EQ( hash_384_result.value(), "SHA384" );
}