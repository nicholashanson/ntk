#include <gtest/gtest.h>

#include <cstdlib>
#include <vector>

#include <http.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ContainsHttpHeader ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "color" ] );
    auto http_response = ntk::get_first_http_respone( packet_data );
    auto http_headers = *ntk::get_http_headers_from_payload( http_response );
    ASSERT_TRUE( ntk::contains_http_header( http_headers, "Content-Length" ) );
}