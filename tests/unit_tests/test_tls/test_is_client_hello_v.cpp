#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, IsClientHelloV ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto client_hello_filter = std::views::all( packet_data ) | std::views::filter( ntk::is_client_hello_v );
    auto client_hellos = std::vector<std::vector<uint8_t>>( client_hello_filter.begin(), client_hello_filter.end() );
    ASSERT_EQ( client_hellos.size(), 1 );
}

TEST( UnitTest, IsClientHelloV_GetPacketsByLineNumbers ) {
    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], ntk::is_client_hello_v );
    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "tls_handshake" ], client_hello_line_numbers );
    ASSERT_EQ( client_hello_packets.size(), 1 );
}