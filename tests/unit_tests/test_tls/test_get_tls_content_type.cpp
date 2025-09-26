#include <gtest/gtest.h>
#include <tls.hpp>

struct tls_content_type_test_case {
    uint8_t type_byte;                        
    std::optional<ntk::tls_content_type> expected;
};

class TlsContentTypeUnitTest : public ::testing::TestWithParam<tls_content_type_test_case> {};

TEST_P( TlsContentTypeUnitTest, GetTlsContentType ) {
    const auto& param = GetParam();
    auto result = ntk::get_tls_content_type( param.type_byte );
    EXPECT_EQ( result, param.expected );
}

INSTANTIATE_TEST_SUITE_P(
    TlsContentTypeTest,
    TlsContentTypeUnitTest,
    ::testing::Values(
        tls_content_type_test_case{ 0x14, ntk::tls_content_type::change_cipher_spec },
        tls_content_type_test_case{ 0x15, ntk::tls_content_type::alert },
        tls_content_type_test_case{ 0x16, ntk::tls_content_type::handshake },
        tls_content_type_test_case{ 0x17, ntk::tls_content_type::application_data },
        tls_content_type_test_case{ 0x00, std::nullopt }
    )
);
