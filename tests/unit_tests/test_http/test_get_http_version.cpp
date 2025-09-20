#include <gtest/gtest.h>

#include <http.hpp>

struct http_version_test_case {
    std::string http_version_string;   
    std::variant<ntk::http_version,ntk::http_parse_error> expected;
};

class HttpVersionUnitTest : public ::testing::TestWithParam<http_version_test_case> {};

TEST_P( HttpVersionUnitTest, GetHttpVersion ) {
    const auto& param = GetParam();
    auto result = ntk::get_http_version( param.http_version_string );
    if ( result ) {
        ASSERT_TRUE( std::holds_alternative<ntk::http_version>( param.expected ) );
        EXPECT_EQ( result.value(), std::get<ntk::http_version>( param.expected ) );
    } else {
        ASSERT_TRUE( std::holds_alternative<ntk::http_parse_error>( param.expected ) );
        EXPECT_EQ( result.error(), std::get<ntk::http_parse_error>( param.expected ) );
    }

}

INSTANTIATE_TEST_SUITE_P(
    HttpVersionTest,
    HttpVersionUnitTest,
    ::testing::Values(
        http_version_test_case{ "HTTP/0.9", ntk::http_version::http_0_9 },
        http_version_test_case{ "HTTP/1.0", ntk::http_version::http_1_0 },
        http_version_test_case{ "HTTP/1.1", ntk::http_version::http_1_1 },
        http_version_test_case{ "HTTP/2",   ntk::http_version::http_2 },
        http_version_test_case{ "HTTP/3",   ntk::http_version::http_3 },
        http_version_test_case{ "HTTP3",    ntk::http_parse_error::malformed_http_version },
        http_version_test_case{ "HTTP/4",   ntk::http_parse_error::invalid_http_version }
    )
);