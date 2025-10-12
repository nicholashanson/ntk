#include <gtest/gtest.h>

#include <io.hpp>
#include <tls.hpp>

TEST( UnitTest, GenerateClientHello ) {
	ntk::generate_default_client_config();
	auto config = ntk::load_client_config();
	auto result = ntk::generate_client_hello( config );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	auto& client_hello_result = result.value();
	EXPECT_EQ( client_hello_result.client_hello.size(), 282 ); 
}