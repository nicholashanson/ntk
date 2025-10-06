#include <gtest/gtest.h>

#include <io.hpp>
#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetExtensions ) {
	auto extensions_result = ntk::get_extensions( test::tls_certificate );
	ASSERT_TRUE( extensions_result ) << extensions_result.error() << std::endl;
	auto& extensions = extensions_result.value();
	EXPECT_EQ( extensions.size(), 10 );
}