#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, HasSni ) {
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( test_constants::tls_client_hello_packet );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto& client_hello = client_hello_result.value();
    auto has_sni_result = ntk::has_sni( client_hello, "earthcam.com" );
    ASSERT_TRUE( has_sni_result ) << has_sni_result.error() << std::endl;
    EXPECT_TRUE( has_sni_result.value() );
}

TEST( UnitTest, HasSni_TlsHandshake ) {
    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], ntk::client_hello_filter );    
    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "tls_handshake" ], client_hello_line_numbers );
    ASSERT_FALSE( client_hello_packets.empty() );
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( client_hello_packets.front() );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto& client_hello = client_hello_result.value();
    auto has_sni_result = ntk::has_sni( client_hello, "earthcam.com" );
    ASSERT_TRUE( has_sni_result ) << has_sni_result.error() << std::endl;
    EXPECT_TRUE( has_sni_result.value() );
}