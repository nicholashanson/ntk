#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ExtractHttpPayloadFromEthernet ) {
    std::vector<uint8_t> http_payload = ntk::extract_http_payload_from_ethernet( test::http_get_packet );
    ASSERT_EQ( http_payload.size(), 354 );
}

