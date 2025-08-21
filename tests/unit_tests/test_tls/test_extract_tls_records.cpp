#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ExtractTlsRecords ) {
    std::vector<uint8_t> first_payload = {
        // record 1
        0x16, 0x03, 0x03, 0x00, 0x01, 0xaa,       // 6 bytes
        // record 2
        0x17, 0x03, 0x03, 0x00, 0x01, 0xbb,       // 6 bytes
        // partial record 3 ( incomplete, only 2 of 4 payload bytes )
        0x16, 0x03, 0x03, 0x00, 0x04, 0xcc, 0xdd  // 7 bytes ( only first 2 payload bytes )
    };
    std::vector<uint8_t> second_payload = {
        // remaining 2 payload bytes for record 3
        0xee, 0xff
    };
    std::vector<std::vector<uint8_t>> tls_payloads = { first_payload, second_payload };
    auto result = ntk::extract_tls_records( tls_payloads );
    ASSERT_EQ( result.records.size(), 3 );
    ASSERT_FALSE( result.has_remainder );
}