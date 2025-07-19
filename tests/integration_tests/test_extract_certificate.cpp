#include <gtest/gtest.h>

#include <algorithm>
#include <span>
#include <cstdint>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, ExtractCertificate ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto merged_stream = ntk::get_merged_tcp_stream( packet_data );
    auto first_packet_pos = merged_stream.begin();
    auto first_packet = first_packet_pos->second;
    auto second_packet_pos = std::next( first_packet_pos );
    auto second_packet = second_packet_pos->second;

    auto [ first_records, first_offset ] = *ntk::split_tls_records( 
        std::span( first_packet.data(), first_packet.size() ) );

    std::vector<uint8_t> remainder( first_packet.data() + first_offset, first_packet.data() + first_packet.size() );
    remainder.insert( remainder.end(), second_packet.data(), second_packet.data() + second_packet.size() );

    auto [ second_records, second_offset ] = *ntk::split_tls_records( remainder );

    auto& tls_client_hello_packet = packet_data[ 3 ];
    auto tls_client_hello_bytes = ntk::get_tcp_payload( tls_client_hello_packet.data() );
    auto tls_record_span = std::span<const unsigned char>( tls_client_hello_bytes );
    auto client_hello_span = tls_record_span.subspan( 9 );
    auto client_hello = ntk::parse_client_hello( client_hello_span );

    tls_record_span = std::span<const unsigned char>( first_records[ 0 ].payload ).subspan( 4 );
    auto server_hello = ntk::parse_server_hello( tls_record_span );

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    auto decrypted_records = ntk::decrypt_tls_data( client_hello.random, server_hello.random, server_hello.server_version, 
        server_hello.cipher_suite, second_records, session_keys );

    std::vector<uint8_t> certificate_payload( decrypted_records[ 0 ].payload.begin() + 10, decrypted_records[ 0 ].payload.end() );
    auto certificate_bytes = ntk::extract_certificate( certificate_payload );
}