#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_tls_handshake_packets.hpp>
#include <test_constants.hpp>

TEST( IntegrationTest, DecryptRecord_TlsApplicationData_Client ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto& client_hello_packet = packet_data[ 3 ];
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    ASSERT_TRUE( client_hello_result );
    auto& client_hello = client_hello_result.value();
    auto& server_hello_packet = packet_data[ 5 ];
    auto server_hello_result = ntk::get_server_hello_from_ethernet( server_hello_packet );
    auto& server_hello = server_hello_result.value();
    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    auto& record_packet = packet_data[ 15 ];
    auto payload_result = ntk::get_tcp_payload( record_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error();
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty";
    auto& payload = *payload_result.value();
    auto split_result = ntk::split_tls_records( payload );
    ASSERT_TRUE( split_result ) << split_result.error() << std::endl;
    auto [ encrypted_records, offset_reached ] = split_result.value();
    ASSERT_EQ( encrypted_records.size(), 1 );

    auto decrypted_record = ntk::decrypt_record( client_hello.random,
                                                 server_hello.random,
                                                 server_hello.server_version,
                                                 server_hello.cipher_suite,
                                                 encrypted_records[ 0 ],
                                                 session_keys,
                                                 "CLIENT_TRAFFIC_SECRET_0",
                                                 0 );
}

TEST( IntegrationTest, DecrytRecod_TlsApplicationData_Server ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    ASSERT_FALSE( packet_data.empty() );
    auto& client_hello_packet = packet_data[ 3 ];
    auto client_hello_result = ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
    ASSERT_TRUE( client_hello_result );
    auto& client_hello = client_hello_result.value();
    auto& server_hello_packet = packet_data[ 5 ];
    auto server_hello_result = ntk::get_server_hello_from_ethernet( server_hello_packet );
    auto& server_hello = server_hello_result.value();
    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    auto& record_packet = packet_data[ 11 ];
    auto payload_result = ntk::get_tcp_payload( record_packet );
    ASSERT_TRUE( payload_result ) << payload_result.error();
    ASSERT_TRUE( payload_result.value() ) << "TCP Payload is empty";
    auto& payload = *payload_result.value();
    auto split_result = ntk::split_tls_records( payload );
    ASSERT_TRUE( split_result ) << split_result.error() << std::endl;
    auto [ encrypted_records, offset_reached ] = split_result.value();
    ASSERT_EQ( encrypted_records.size(), 2 );
    
    auto first_decrypted_record = ntk::decrypt_record( client_hello.random,
                                                       server_hello.random,
                                                       server_hello.server_version,
                                                       server_hello.cipher_suite,
                                                       encrypted_records[ 0 ],
                                                       session_keys,
                                                       "SERVER_TRAFFIC_SECRET_0",
                                                       0 );
    auto second_decrypted_record = ntk::decrypt_record( client_hello.random,
                                                        server_hello.random,
                                                        server_hello.server_version,
                                                        server_hello.cipher_suite,
                                                        encrypted_records[ 1 ],
                                                        session_keys,
                                                        "SERVER_TRAFFIC_SECRET_0",
                                                        1 );
}

