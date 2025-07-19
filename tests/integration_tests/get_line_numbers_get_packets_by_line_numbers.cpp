#include <gtest/gtest.h>

#include <algorithm>
#include <span>
#include <cstdint>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetLineNumbers_GetPacketsByLineNumbers ) {
    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], ntk::is_client_hello_v );
    ASSERT_TRUE( !client_hello_line_numbers.empty() );

    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], client_hello_line_numbers );
    ASSERT_TRUE( !client_hello_packets.empty() );
    ASSERT_EQ( client_hello_line_numbers.size(), client_hello_packets.size() );

    auto secrets = ntk::get_tls_secrets( "sslkeys.log" );
    std::vector<ntk::client_hello> client_hellos;
    for ( auto& client_hello_packet : client_hello_packets ) {
        auto tcp_payload = ntk::get_tcp_payload( client_hello_packet.data() );
        auto client_hello = ntk::get_client_hello( tcp_payload );
        client_hellos.push_back( client_hello );
    }
}