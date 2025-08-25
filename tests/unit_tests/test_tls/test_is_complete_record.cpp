#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, IsCompleteRecord ) {
    std::vector<uint8_t> complete_record = { 0x16, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc };
    ASSERT_TRUE( ntk::is_complete_record( complete_record ) );
}

TEST( UnitTest, IsCompleteRecord_CounterCase ) {
    std::vector<uint8_t> incomplete_record = { 0x16, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb };
    ASSERT_FALSE( ntk::is_complete_record( incomplete_record ) );
}
