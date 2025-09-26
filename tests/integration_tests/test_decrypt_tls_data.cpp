#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( IntegrationTest, DecryptTlsData ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto merged_stream = ntk::get_merged_tcp_stream( packet_data );
    auto first_packet_pos = merged_stream.begin();
    auto first_packet = first_packet_pos->second;
    auto second_packet_pos = std::next( first_packet_pos );
    auto second_packet = second_packet_pos->second;
    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    auto [ first_records, first_offset ] = *ntk::split_tls_records( 
        std::span( first_packet.data(), first_packet.size() ) );

    std::vector<uint8_t> remainder( first_packet.data() + first_offset, first_packet.data() + first_packet.size() );
    remainder.insert( remainder.end(), second_packet.data(), second_packet.data() + second_packet.size() );

    auto [ second_records, second_offset ] = *ntk::split_tls_records( remainder );

    auto& client_hello_packet = packet_data[ 3 ];
    auto client_hello = *ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    auto server_hello = *ntk::get_server_hello( first_records.front() );

    auto decrypted_records = ntk::decrypt_tls_data( client_hello.random, 
                                                    server_hello.random, 
                                                    server_hello.server_version, 
                                                    server_hello.cipher_suite, 
                                                    second_records, 
                                                    session_keys );
    ASSERT_EQ( decrypted_records.size(), 1 );
}

TEST( IntegrationTest, DecryptTlsData_TlsCombinedRecords ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& client_hello_packet = packet_data[ 3 ];
    auto client_hello = *ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    auto& server_hello_packet = packet_data[ 5 ];
    auto server_hello = *ntk::get_server_hello_from_ethernet( server_hello_packet );
    
    auto [ records, offset_reached ] = *ntk::split_tls_records( test_constants::tls_combined_records ); 
    ASSERT_EQ( offset_reached, sizeof( test_constants::tls_combined_records ) );
    ASSERT_EQ( records.size(), 2 );

    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );
    ASSERT_TRUE( !session_keys.empty() );

    std::vector<ntk::tls_record> encrypted_records( records.begin() + 1, records.end() );
    ASSERT_EQ( encrypted_records[ 0 ].payload.size(), 69 );

    auto decrypted_records = ntk::decrypt_tls_data( client_hello.random,
                                                    server_hello.random,
                                                    server_hello.server_version,
                                                    server_hello.cipher_suite,
                                                    encrypted_records,
                                                    session_keys,
                                                    "CLIENT_HANDSHAKE_TRAFFIC_SECRET" );
    ASSERT_EQ( decrypted_records.size(), 1 );
    ASSERT_EQ( decrypted_records[ 0 ].payload.size(), encrypted_records[ 0 ].payload.size() - 16 /* tag size */ );
}

TEST( IntegrationTest, DecryptTlsData_ShortStream ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "short_stream" ] );
    auto four = *ntk::get_four_tuples( packet_data ).begin();
    auto client_payloads = ntk::extract_payloads( four, packet_data );
    auto server_payloads = ntk::extract_payloads( ntk::flip_four( four ), packet_data );
    auto client_records = ntk::extract_tls_records( client_payloads ).records;
    auto server_records = ntk::extract_tls_records( server_payloads ).records;
    auto client_hello = *ntk::get_client_hello( client_records.front() );
    auto server_hello = *ntk::get_server_hello( server_records.front() );
    auto secrets = ntk::get_tls_secrets( "sslkeys.log", client_hello.random );
    
    auto decrypted_record_1 = ntk::decrypt_record( client_hello.random,
                                                   server_hello.random,
                                                   server_hello.server_version,
                                                   server_hello.cipher_suite,
                                                   server_records[ 2 ],
                                                   secrets,
                                                   "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                                                   0 );
    auto decrypted_record_2 = ntk::decrypt_record( client_hello.random,
                                                   server_hello.random,
                                                   server_hello.server_version,
                                                   server_hello.cipher_suite,
                                                   server_records[ 3 ],
                                                   secrets,
                                                   "SERVER_TRAFFIC_SECRET_0",
                                                   0 );
}

TEST( IntegrationTest, DecryptTlsData_LongStream ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    auto four = *ntk::get_four_tuples( packet_data ).begin();
    auto client_payloads = ntk::extract_payloads( four, packet_data );
    auto server_payloads = ntk::extract_payloads( ntk::flip_four( four ), packet_data );
    auto client_records = ntk::extract_tls_records( client_payloads ).records;
    auto server_records = ntk::extract_tls_records( server_payloads ).records;
    auto client_hello = *ntk::get_client_hello( client_records.front() );
    auto server_hello = *ntk::get_server_hello( server_records.front() );

    std::vector<ntk::tls_record> client_records_to_decrypt( client_records.begin() + 3, client_records.end() );
    std::vector<ntk::tls_record> server_records_to_decrypt( server_records.begin() + 3, server_records.end() );
    auto secrets = ntk::get_tls_secrets( "sslkeys.log", client_hello.random );
    
    auto decrypted_client_records = ntk::decrypt_tls_data( client_hello.random,
                                                           server_hello.random,
                                                           server_hello.server_version,
                                                           server_hello.cipher_suite,
                                                           client_records_to_decrypt,
                                                           secrets,
                                                           "CLIENT_TRAFFIC_SECRET_0" );
    auto decrypted_server_records = ntk::decrypt_tls_data( client_hello.random,
                                                           server_hello.random,
                                                           server_hello.server_version,
                                                           server_hello.cipher_suite,
                                                           server_records_to_decrypt,
                                                           secrets,
                                                           "SERVER_TRAFFIC_SECRET_0" );
    for ( auto& record : decrypted_server_records ) {
        record.payload.pop_back();
    }
    ntk::http_response response = *ntk::get_http_response(  decrypted_server_records[ 2 ].payload  );
    for ( std::size_t i = 3; i < decrypted_server_records.size(); ++i ) {
        response.body.insert( response.body.end(), decrypted_server_records[ i ].payload.begin(), decrypted_server_records[ i ].payload.end() );
    }
    ntk::write_payload_to_file( response.body, "segment.ts" );
}

TEST( IntegrationTest, DecryptTlsData_IsHttpRequest ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    auto four = *ntk::get_four_tuples( packet_data ).begin();
    auto client_payloads = ntk::extract_payloads( four, packet_data );
    auto client_records = ntk::extract_tls_records( client_payloads ).records;
    auto server_payloads = ntk::extract_payloads( ntk::flip_four( four ), packet_data );
    auto server_records = ntk::extract_tls_records( server_payloads ).records;
    auto client_hello = *ntk::get_client_hello( client_records.front() );
    auto server_hello = *ntk::get_server_hello( server_records.front() );

    std::vector<ntk::tls_record> client_records_to_decrypt( client_records.begin() + 3, client_records.end() );
    auto secrets = ntk::get_tls_secrets( "sslkeys.log", client_hello.random );
    
    auto decrypted_client_records = ntk::decrypt_tls_data( client_hello.random,
                                                           server_hello.random,
                                                           server_hello.server_version,
                                                           server_hello.cipher_suite,
                                                           client_records_to_decrypt,
                                                           secrets,
                                                           "CLIENT_TRAFFIC_SECRET_0" );
    decrypted_client_records.erase( decrypted_client_records.begin() );
    decrypted_client_records.erase( decrypted_client_records.begin() );
    ASSERT_TRUE( ntk::is_http_request( decrypted_client_records.front().payload )  );
}

TEST( IntegrationTest, DecryptTlsData_IsHttpResponse ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    auto four = *ntk::get_four_tuples( packet_data ).begin();
    auto client_payloads = ntk::extract_payloads( four, packet_data );
    auto client_records = ntk::extract_tls_records( client_payloads ).records;
    auto server_payloads = ntk::extract_payloads( ntk::flip_four( four ), packet_data );
    auto server_records = ntk::extract_tls_records( server_payloads ).records;
    auto client_hello = *ntk::get_client_hello( client_records.front() );
    auto server_hello = *ntk::get_server_hello( server_records.front() );

    std::vector<ntk::tls_record> server_records_to_decrypt( server_records.begin() + 3, server_records.end() );
    auto secrets = ntk::get_tls_secrets( "sslkeys.log", client_hello.random );
    
    auto decrypted_server_records = ntk::decrypt_tls_data( client_hello.random,
                                                           server_hello.random,
                                                           server_hello.server_version,
                                                           server_hello.cipher_suite,
                                                           server_records_to_decrypt,
                                                           secrets,
                                                           "SERVER_TRAFFIC_SECRET_0" );
    decrypted_server_records.erase( decrypted_server_records.begin() );
    decrypted_server_records.erase( decrypted_server_records.begin() );
    decrypted_server_records.front().payload.pop_back();
    ASSERT_TRUE( ntk::is_http_response( decrypted_server_records.front().payload )  );
}

