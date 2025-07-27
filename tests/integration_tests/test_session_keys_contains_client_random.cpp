#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, SessionKeysContainsClientRandom ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello_packet = packet_data[ 3 ];
    auto tls_client_hello_bytes = ntk::get_tcp_payload( tls_client_hello_packet.data() );
    auto tls_record_span = std::span<const unsigned char>( tls_client_hello_bytes );
    auto client_hello_span = tls_record_span.subspan( 9 );
    auto client_hello = *ntk::parse_client_hello( client_hello_span );
    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    auto client_random_hex = ntk::client_random_to_hex( client_hello.random );
    ASSERT_TRUE( session_keys.contains( client_random_hex ) );
}


