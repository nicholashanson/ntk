#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, BuildTls13Nonce ) {
    std::vector<uint8_t> base_iv = { 0x00 ,0x01 ,0x02 ,0x03, 
                                     0x04, 0x05, 0x06, 0x07, 
                                     0x08, 0x09, 0x0a, 0x0b };
    uint64_t seq_num = 0x0102030405060708;
    auto actual_nonce = ntk::build_tls13_nonce( base_iv, seq_num );
    std::vector<uint8_t> expected_nonce = {
        0x00, 0x01, 0x02, 0x03,
        0x05, 0x07, 0x05, 0x03,
        0x0d, 0x0f, 0x0d, 0x03
    };
    ASSERT_EQ( actual_nonce, expected_nonce );
}