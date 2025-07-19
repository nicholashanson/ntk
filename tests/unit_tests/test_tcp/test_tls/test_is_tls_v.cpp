#include <gtest/gtest.h>

#include <algorithm>
#include <span>
#include <cstdint>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsTlsV ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto tls_records_filter = std::views::all( packet_data ) | std::views::filter( ntk::is_tls_v );
    auto tls_records = std::vector<std::vector<uint8_t>>( tls_records_filter.begin(), tls_records_filter.end() );
    ASSERT_EQ( tls_records.size(), 5 );
}

TEST( UnitTest, IsTlsV_GetLineNumbers ) {
    auto tls_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], ntk::is_tls_v );
    std::vector<int> expected_line_numbers = { 4, 6, 10, 12, 16 };
    ASSERT_EQ( tls_line_numbers.size(), 5 );
    ASSERT_EQ( tls_line_numbers, expected_line_numbers );
}
