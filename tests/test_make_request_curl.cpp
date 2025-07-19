#include <gtest/gtest.h>

#include <requests.hpp>

TEST( UnitTest, MakeRequestCurl ) {
    ASSERT_TRUE( ntk::make_request_curl( "https://www.google.com" ) );
}