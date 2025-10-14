#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, ExtractArray_CipherSuites ) {
	auto config_result = ntk::load_client_config();
	ASSERT_TRUE( config_result) << config_result.error() << std::endl;
	auto result = ntk::extract_array( config_result.value(), "cipher_suites" );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	auto& cipher_suites = result.value();
	EXPECT_EQ( cipher_suites.size(), 17 );
}