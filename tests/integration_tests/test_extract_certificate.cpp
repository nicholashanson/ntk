#include <gtest/gtest.h>

#include <cstdint>
#include <span>

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
    auto [ first_records, first_offset ] = *ntk::split_tls_records( std::span( first_packet.data(), 
                                                                               first_packet.size() ) );
    std::vector<uint8_t> remainder( first_packet.data() + first_offset, first_packet.data() + first_packet.size() );
    remainder.insert( remainder.end(), second_packet.data(), second_packet.data() + second_packet.size() );
    auto split_result = ntk::split_tls_records( remainder );
    ASSERT_TRUE( split_result ) << split_result.error() << std::endl;
    auto [ second_records, second_offset ] = split_result.value();
    auto& client_hello_packet = packet_data[ 3 ];
    auto client_hello = *ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    auto server_hello = *ntk::get_server_hello( first_records.front() );
    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );
    auto decrypted_records = ntk::decrypt_tls_data( client_hello.random, 
                                                    server_hello.random, 
                                                    server_hello.server_version, 
                                                    server_hello.cipher_suite, 
                                                    second_records, 
                                                    session_keys );
    std::vector<uint8_t> certificate_payload( decrypted_records[ 0 ].payload.begin() + 10, decrypted_records[ 0 ].payload.end() );
    auto certificate_bytes = ntk::extract_certificate( certificate_payload );
}