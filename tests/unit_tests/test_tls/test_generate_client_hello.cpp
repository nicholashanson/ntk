#include <gtest/gtest.h>

#include <io.hpp>
#include <tls.hpp>

TEST( UnitTest, GenerateClientHello ) {
	ntk::generate_default_client_config();
	auto config_result = ntk::load_client_config();
	ASSERT_TRUE( config_result ) << config_result.error() << std::endl;
	auto result = ntk::generate_client_hello( config_result.value() );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	auto& client_hello_result = result.value();
	EXPECT_EQ( client_hello_result.client_hello.size(), 282 ); 
}