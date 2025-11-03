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
    ntk::print_vector( certificate_payload );
    auto certificate_bytes = ntk::extract_certificate( certificate_payload );
    std::cout << "certificate_bytes size: " << certificate_bytes.size() << std::endl;
    std::cout << "certificate_payload size: " << certificate_payload.size() << std::endl;
    ntk::print_vector( certificate_bytes );
    std::span<uint8_t> second_certificate{ certificate_payload.begin() + 11 + certificate_bytes.size() + 2, certificate_payload.size() - 11 - certificate_bytes.size() - 2 };
    ntk::print_vector( second_certificate );
    auto second_certificate_result = ntk::extract_certificate_( second_certificate );
    ASSERT_TRUE( second_certificate_result ) << second_certificate_result.error();
    ntk::print_vector( second_certificate_result.value() );
    std::span<const uint8_t> third_certificate{ second_certificate.begin() + 3 + second_certificate_result.value().size() + 2, 
                                                second_certificate.size() - 3 - second_certificate_result.value().size() - 2 };
    auto third_certificate_result = ntk::extract_certificate_( third_certificate );
    ntk::print_vector( third_certificate_result.value() );
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
    ntk::print_server_hello( server_hello );
}