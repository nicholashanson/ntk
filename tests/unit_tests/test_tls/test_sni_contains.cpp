#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, SniContains ) {
    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], ntk::client_hello_filter );
    ASSERT_FALSE( client_hello_line_numbers.empty() );
    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], client_hello_line_numbers );
    ASSERT_FALSE( client_hello_packets.empty() );
    std::vector<ntk::client_hello> client_hellos;
    for ( auto& client_hello_packet : client_hello_packets ) {
        auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
        ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
        client_hellos.push_back( client_hello_result.value() );
    }
    EXPECT_FALSE( client_hellos.empty() );
    bool found = false;
    for ( const auto& client_hello : client_hellos ) {
        auto sni_result = ntk::sni_contains( client_hello, "earthcam" );
        if ( !sni_result ) { 
            std::cout << sni_result.error() << std::endl;
            continue;
        }
        if ( sni_result.value() ) {
            found = true;
        }
    }   
    EXPECT_TRUE( found );
}

TEST( UnitTest, SniContains_LongStream ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto& packet = packet_data[ 3 ];
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( packet );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto result = ntk::sni_contains( client_hello_result.value(), "earthcam" );
    ASSERT_TRUE( result ) << result.error() << std::endl;
    EXPECT_TRUE( result.value() );
}