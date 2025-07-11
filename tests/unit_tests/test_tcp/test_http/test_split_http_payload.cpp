#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( PacketParsingTests, HttpPayloadSectionLengths ) {

    std::vector<uint8_t> http_payload = ntk::extract_http_payload_from_ethernet( test::http_get_packet );
    auto http_sections = ntk::split_http_payload( http_payload );

    ASSERT_EQ( std::get<0>( http_sections ).size(), 14 );
    ASSERT_EQ( std::get<1>( http_sections ).size(), 334 );
    ASSERT_EQ( std::get<2>( http_sections ).size(), 0 );
}
