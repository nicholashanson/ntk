#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsHttpResponse_Ethernet ) {
	ASSERT_TRUE( ntk::is_http_response( std::span( test::http_response_packet ) ) );
}