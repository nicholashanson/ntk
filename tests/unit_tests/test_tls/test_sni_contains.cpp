#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, SniContains ) {
    auto client_hello_line_numbers = ntk::get_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], ntk::is_client_hello_v );
    auto client_hello_packets = ntk::get_packets_by_line_numbers( test::packet_data_files[ "earth_cam_live_stream" ], client_hello_line_numbers );

    std::vector<ntk::client_hello> client_hellos;
    for ( auto& client_hello_packet : client_hello_packets ) {
        auto client_hello = *ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
        client_hellos.push_back( client_hello );
    }
    ASSERT_TRUE( !client_hellos.empty() );

    bool found = false;
    for ( const auto& client_hello : client_hellos ) {
        auto result = ntk::sni_contains( client_hello, "earthcam" );
        if ( result.has_value() ) {
            std::cout << "SNI match result: " << *result << std::endl;
            if ( *result ) {
                found = true;
            }
        } else {
            std::cerr << "SNI parsing failed: " << result.error() << std::endl;
        }
    }   
    ASSERT_TRUE( found );
}