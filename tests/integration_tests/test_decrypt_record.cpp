#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tls.hpp>
#include <io.hpp>

#include <test_tls_handshake_packets.hpp>
#include <test_constants.hpp>

TEST( IntegrationTest, DecryptRecord_TlsApplicationData_Client ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
    auto& tls_client_hello = packet_data[ 3 ];
    auto client_hello = *ntk::get_client_hello_from_ethernet_frame( tls_client_hello );
    auto& tls_server_hello = packet_data[ 5 ];
    auto server_hello = *ntk::get_server_hello_from_ethernet_frame( tls_server_hello );
    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );

    auto& tls_record = packet_data[ 15 ];
    auto tls_application_data = ntk::get_tcp_payload( tls_record.data() );
    auto [ encrypted_records, offset_reached ] = *ntk::split_tls_records( 
        std::span( tls_application_data.data(), tls_application_data.size() ) );
    ASSERT_EQ( encrypted_records.size(), 1 );

    auto decrypted_record = ntk::decrypt_record(
        client_hello.random,
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
    auto& tls_client_hello = packet_data[ 3 ];
    auto client_hello = *ntk::get_client_hello_from_ethernet_frame( tls_client_hello );
    auto& tls_server_hello = packet_data[ 5 ];
    auto server_hello = *ntk::get_server_hello_from_ethernet_frame( tls_server_hello );
    auto session_keys = ntk::get_tls_secrets( "tls_session_keys.log" );
    auto& tls_record = packet_data[ 11 ];

    auto tls_application_data = ntk::get_tcp_payload( tls_record.data() );
    auto [ encrypted_records, offset_reached ] = *ntk::split_tls_records( 
        std::span( tls_application_data.data(), tls_application_data.size() ) );
    ASSERT_EQ( encrypted_records.size(), 2 );

    auto first_decrypted_record = ntk::decrypt_record(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        encrypted_records[ 0 ],
        session_keys,
        "SERVER_TRAFFIC_SECRET_0",
        0 );
    auto second_decrypted_record = ntk::decrypt_record(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        encrypted_records[ 1 ],
        session_keys,
        "SERVER_TRAFFIC_SECRET_0",
        1 );
}
