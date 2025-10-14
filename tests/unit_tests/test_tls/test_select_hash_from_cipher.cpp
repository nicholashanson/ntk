#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, SelectHashFromCipher ) {
	auto result = ntk::select_hash_from_cipher( ntk::cipher_suite::TLS_AES_256_GCM_SHA384 );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	EXPECT_EQ( result.value(), EVP_sha384() );
}