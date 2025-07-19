#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, HasSni ) {
    auto client_hello = ntk::get_client_hello_from_ethernet_frame( test_constants::tls_client_hello_packet );
    ASSERT_TRUE( *ntk::has_sni( client_hello, "earthcam.com" ) );
}

TEST( UnitTest, HasSni_TlsHandshake ) {
    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "tls_handshake" ], ntk::is_client_hello_v );
    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "tls_handshake" ], client_hello_line_numbers );

    auto client_hello = ntk::get_client_hello_from_ethernet_frame( client_hello_packets.front() );
    auto sni_result = ntk::has_sni( client_hello, "earthcam.com" );

    if ( !sni_result ) {
        std::cerr << sni_result.error() << std::endl; 
    }

    ASSERT_TRUE( sni_result.value() );
}