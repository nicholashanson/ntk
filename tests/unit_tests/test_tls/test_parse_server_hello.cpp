#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, ParseServerHello ) {
    auto tls_record_span = std::span<const unsigned char>( test_constants::tls_server_hello_record );;
    auto server_hello_span = tls_record_span.subspan( 9 );
    auto server_hello = *ntk::parse_server_hello( server_hello_span );
    ntk::cipher_suite expected_cipher_suite = ntk::cipher_suite::TLS_AES_256_GCM_SHA384;
    std::size_t expected_session_id_size = 32;
    ntk::cipher_suite actual_cipher_suite = static_cast<ntk::cipher_suite>( server_hello.cipher_suite );
    std::size_t actual_session_id_size = server_hello.session_id.size();
    ASSERT_EQ( actual_cipher_suite, expected_cipher_suite );
    ASSERT_EQ( actual_session_id_size, expected_session_id_size );
}

TEST( UnitTest, ParseServerHello_TlsHandshake ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto merged_stream = ntk::get_merged_tcp_stream( packet_data );
    auto first_packet_pos = merged_stream.begin();
    auto first_packet = first_packet_pos->second;
    auto [ first_records, first_offset ] = *ntk::split_tls_records( 
        std::span( first_packet.data(), first_packet.size() ) );
    auto tls_record_span = std::span<const unsigned char>( first_records[ 0 ].payload ).subspan( 4 );
    auto server_hello = *ntk::parse_server_hello( tls_record_span );
    ntk::cipher_suite expected_cipher_suite = ntk::cipher_suite::TLS_AES_256_GCM_SHA384;
    ntk::cipher_suite actual_cipher_suite = static_cast<ntk::cipher_suite>( server_hello.cipher_suite );
    ASSERT_EQ( actual_cipher_suite, expected_cipher_suite );
}
