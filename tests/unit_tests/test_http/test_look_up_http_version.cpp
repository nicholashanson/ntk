#include <gtest/gtest.h>

#include <http.hpp>

struct look_up_http_version_test_case {
    uint16_t version_bytes;   
    std::optional<ntk::http_version> expected;
};

class LookUpHttpVersionUnitTest : public ::testing::TestWithParam<look_up_http_version_test_case> {};

TEST_P( LookUpHttpVersionUnitTest, LookUpHttpVersion ) {
    const auto& param = GetParam();
    auto value = param.version_bytes;
    auto result = ntk::look_up_http_version( param.version_bytes );
    EXPECT_EQ( result, param.expected );
}

INSTANTIATE_TEST_SUITE_P(
    LookUpHttpVersionTest,
    LookUpHttpVersionUnitTest,
    ::testing::Values(
        look_up_http_version_test_case{ 0x09, ntk::http_version::http_0_9 },
        look_up_http_version_test_case{ 0x10, ntk::http_version::http_1_0 },
        look_up_http_version_test_case{ 0x11, ntk::http_version::http_1_1 },
        look_up_http_version_test_case{ 0x20, ntk::http_version::http_2 },
        look_up_http_version_test_case{ 0x30, ntk::http_version::http_3 },
        look_up_http_version_test_case{ 0x00, std::nullopt }
    )
);