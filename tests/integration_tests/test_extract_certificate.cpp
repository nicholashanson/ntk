#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( IntegrationTest, ExtractCertificate ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto merged_stream = ntk::get_merged_tcp_stream( packet_data );
    auto first_packet_pos = merged_stream.begin();
    auto first_packet = first_packet_pos->second;
    auto second_packet_pos = std::next( first_packet_pos );
    auto second_packet = second_packet_pos->second;
    auto split_result_1 = ntk::split_tls_records( std::span( first_packet.data(), first_packet.size() ) );
    ASSERT_TRUE( split_result_1 ) << split_result_1.error() << std::endl;
    auto [ first_records, first_offset ] = split_result_1.value();
    std::vector<uint8_t> remainder( first_packet.data() + first_offset, first_packet.data() + first_packet.size() );
    remainder.insert( remainder.end(), second_packet.data(), second_packet.data() + second_packet.size() );
    auto split_result_2 = ntk::split_tls_records( remainder );
    ASSERT_TRUE( split_result_2 ) << split_result_2.error() << std::endl;
    auto [ second_records, second_offset ] = split_result_2.value();
    auto& client_hello_packet = packet_data[ 3 ];
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto& client_hello = client_hello_result.value();
    auto server_hello_result = ntk::get_server_hello( first_records.front() );
    ASSERT_TRUE( server_hello_result ) << server_hello_result.error() << std::endl;
    auto server_hello = server_hello_result.value();
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

TEST( IntegrationTest, ExtractCertificate_Segment ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto& certificate_packet = packet_data[ 12 ];
    auto split_result = ntk::get_tls_records_from_ethernet( certificate_packet );
    ASSERT_TRUE( split_result ) << split_result.error() << std::endl;
    auto [ records, offset ] = split_result.value();
    EXPECT_EQ( records.size(), 4 );
    auto& certificate_record = records[ 3 ];
    EXPECT_TRUE( ntk::is_server_hello( records.front() ) );
    auto server_hello_result = ntk::get_server_hello( records.front() );
    ASSERT_TRUE( server_hello_result ) << server_hello_result.error() << std::endl;
    auto& server_hello = server_hello_result.value();
    auto& client_hello_packet = packet_data[ 10 ];
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    ASSERT_TRUE( client_hello_result ) << client_hello_result.error() << std::endl;
    auto& client_hello = client_hello_result.value();
    auto session_keys = ntk::get_tls_secrets( "../server/session_keys.log" );
    auto decrypted_record = ntk::decrypt_record( client_hello.random, 
                                                 server_hello.random, 
                                                 server_hello.server_version, 
                                                 server_hello.cipher_suite, 
                                                 certificate_record, 
                                                 session_keys,
                                                 "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                                                 1 );
}