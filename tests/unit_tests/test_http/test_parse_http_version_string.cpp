#include <gtest/gtest.h>

#include <http.hpp>

struct http_version_string_test_case {
    std::string http_version_string;   
    std::variant<uint8_t,ntk::http_parse_error> expected;
};

class HttpVersionStringUnitTest : public ::testing::TestWithParam<http_version_string_test_case> {};

TEST_P( HttpVersionStringUnitTest, ParseHttpVersionString ) {
    const auto& param = GetParam();
    auto result = ntk::parse_http_version_string( param.http_version_string );
    if ( result ) {
        ASSERT_TRUE( std::holds_alternative<uint8_t>( param.expected ) );
        EXPECT_EQ( result.value(), std::get<uint8_t>( param.expected ) );
    } else {
        ASSERT_TRUE( std::holds_alternative<ntk::http_parse_error>(param.expected ) );
        EXPECT_EQ( result.error(), std::get<ntk::http_parse_error>(param.expected ) );
    }

}

INSTANTIATE_TEST_SUITE_P(
    HttpVersionStringTest,
    HttpVersionStringUnitTest,
    ::testing::Values(
        http_version_string_test_case{ "HTTP/0.9", uint8_t( 0x09 ) },
        http_version_string_test_case{ "HTTP/1.0", uint8_t( 0x10 ) },
        http_version_string_test_case{ "HTTP/1.1", uint8_t( 0x11 ) },
        http_version_string_test_case{ "HTTP/2",   uint8_t( 0x20 ) },
        http_version_string_test_case{ "HTTP/3",   uint8_t( 0x30 ) },
        http_version_string_test_case{ "HTTP3",    ntk::http_parse_error::malformed_http_version }
    )
);