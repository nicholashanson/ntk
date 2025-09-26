/*

#include <gtest/gtest.h>

TEST( IntegrationTest, GetMimeTypeFromEthernet_ApplicationVndAppleMpegurl_LongSteam ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    auto four = *ntk::get_four_tuples( packet_data ).begin();
    auto client_payloads = ntk::extract_payloads( four, packet_data );
    auto client_tls_records = ntk::extract_tls_records( client_payloads ).records;
    auto server_payloads = ntk::extract_payloads( ntk::flip_four( four ), packet_data );
    auto server_tls_records = ntk::extract_tls_records( server_payloads ).records;
    auto client_hello = *ntk::get_client_hello( client_tls_records[ 0 ] );
    auto server_hello = *ntk::get_server_hello( server_tls_records[ 0 ] );

    std::vector<ntk::tls_record> server_records_to_decrypt( server_tls_records.begin() + 3, server_tls_records.end() );
    auto secrets = ntk::get_tls_secrets( "sslkeys.log", client_hello.random );
    
    auto decrypted_server_tls_records = ntk::decrypt_tls_data(
        client_hello.random,
        server_hello.random,
        server_hello.server_version,
        server_hello.cipher_suite,
        server_records_to_decrypt,
        secrets,
        "SERVER_TRAFFIC_SECRET_0" );
    decrypted_server_tls_records.erase( decrypted_server_tls_records.begin() );
    decrypted_server_tls_records.erase( decrypted_server_tls_records.begin() );
    decrypted_server_tls_records.front().payload.pop_back();
    ntk::print_vector( decrypted_server_tls_records.front().payload );
    auto response = *ntk::get_http_response( decrypted_server_tls_records.front().payload );
    ntk::print_http_response( response );
    ASSERT_EQ( ntk::get_   );
}

*/