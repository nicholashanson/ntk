#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, GetLineNumbersGetPacketsByLineNumbers ) {
    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], 
                                                            ntk::client_hello_filter );
    ASSERT_FALSE( client_hello_line_numbers.empty() );
    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], client_hello_line_numbers );
    ASSERT_FALSE( client_hello_packets.empty() );
    ASSERT_EQ( client_hello_line_numbers.size(), client_hello_packets.size() );
    auto secrets = ntk::get_tls_secrets( "sslkeys.log" );
    std::vector<ntk::client_hello> client_hellos;
    for ( auto& client_hello_packet : client_hello_packets ) {
        auto payload_result = ntk::get_tcp_payload( client_hello_packet );
        ASSERT_TRUE( payload_result ) << payload_result.error() << std::endl;
        auto payload = *payload_result.value();
        auto client_hello_result = ntk::get_client_hello( payload );
        ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
        client_hellos.push_back( client_hello_result.value() );
    }
}