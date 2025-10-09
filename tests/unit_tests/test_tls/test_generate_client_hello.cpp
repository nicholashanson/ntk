#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, GenerateClientHello ) {
	auto config = ntk::load_client_config();
	auto result = ntk::generate_client_hello( config );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	auto& client_hello = result.value();
	std::vector<uint8_t> expected{ 0x00, 0x22 };
	EXPECT_EQ( client_hello.size(), 148 ); 
}