#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetHttpType ) {
    auto http_request_payload = ntk::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_response_payload = ntk::extract_http_payload_from_ethernet( test::http_response_packet );
    ntk::http_type request_type = ntk::get_http_type( http_request_payload );
    ntk::http_type response_type = ntk::get_http_type( http_response_payload );

    ASSERT_EQ( request_type, ntk::http_type::REQUEST );
    ASSERT_EQ( response_type, ntk::http_type::RESPONSE );
}