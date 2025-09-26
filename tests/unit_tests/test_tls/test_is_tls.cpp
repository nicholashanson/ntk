#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsTls ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto tls_records_filter = std::views::all( packet_data ) | std::views::filter( [] ( const auto& packet) {
                                                                                       auto result = ntk::is_tls( packet ); 
                                                                                       return result && result.value();
                                                                                   } );
    auto tls_records = std::vector<std::vector<uint8_t>>( tls_records_filter.begin(), tls_records_filter.end() );
    ASSERT_EQ( tls_records.size(), 5 );
}

TEST( UnitTest, IsTls_GetLineNumbers ) {
    auto tls_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], [] ( const auto& packet) {
                                                                                                   auto result = ntk::is_tls( packet ); 
                                                                                                   return result && result.value();
                                                                                               } );
    std::vector<int> expected_line_numbers = { 4, 6, 10, 12, 16 };
    EXPECT_EQ( tls_line_numbers.size(), 5 );
    EXPECT_EQ( tls_line_numbers, expected_line_numbers );
}

TEST( UnitTest, IsTls_LongStream ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    auto packet = packet_data[ 18 ];
    auto result = ntk::is_tls( packet );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    ASSERT_TRUE( result.value() );
}

