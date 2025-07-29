#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsHttpRequest_Ethernet ) {
	ASSERT_TRUE( ntk::is_http_request( std::span( test::http_get_packet ) ) );
}