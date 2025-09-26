#include <gtest/gtest.h>
#include <tls.hpp>

struct tls_version_test_case {
    uint16_t version_bytes;   
    std::optional<ntk::tls_version> expected;
};

class TlsVersionUnitTest : public ::testing::TestWithParam<tls_version_test_case> {};

TEST_P( TlsVersionUnitTest, GetTlsVersion) {
    const auto& param = GetParam();
    auto value = param.version_bytes;
    auto result = ntk::get_tls_version(param.version_bytes);
    EXPECT_EQ( result, param.expected );
}

INSTANTIATE_TEST_SUITE_P(
    TlsVersionTest,
    TlsVersionUnitTest,
    ::testing::Values(
        tls_version_test_case{ 0x0301, ntk::tls_version::tls_1_0 },
        tls_version_test_case{ 0x0303, ntk::tls_version::tls_1_2 },
        tls_version_test_case{ 0x0304, ntk::tls_version::tls_1_3 },
        tls_version_test_case{ 0x0000, std::nullopt }
    )
);