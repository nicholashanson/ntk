#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, ExtractArray_CipherSuites ) {
	auto config = ntk::load_client_config();
	auto result = ntk::extract_array( config, "cipher_suites" );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	auto& cipher_suites = result.value();
	EXPECT_EQ( cipher_suites.size(), 17 );
}