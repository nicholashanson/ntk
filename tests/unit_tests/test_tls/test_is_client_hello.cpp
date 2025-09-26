#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, IsClientHello ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto client_hello_filter = std::views::all( packet_data ) | std::views::filter( ntk::client_hello_filter );
    auto client_hellos = std::vector<std::vector<uint8_t>>( client_hello_filter.begin(), client_hello_filter.end() );
    ASSERT_EQ( client_hellos.size(), 1 );
}

TEST( UnitTest, IsClientHello_GetPacketsByLineNumbers ) {
    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], ntk::client_hello_filter );
    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "tls_handshake" ], client_hello_line_numbers );
    ASSERT_EQ( client_hello_packets.size(), 1 );
}

TEST( UnitTest, IsClientHello_LongStream ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto& client_hello_packet = packet_data[ 3 ];
    auto is_client_hello_result = ntk::is_client_hello( client_hello_packet );
    ASSERT_TRUE( is_client_hello_result ) << is_client_hello_result.error() << std::endl;
    ASSERT_TRUE( is_client_hello_result.value() );
}