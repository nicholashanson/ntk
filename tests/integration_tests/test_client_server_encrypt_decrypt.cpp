#include <gtest/gtest.h>

#include <tls_client.hpp>
#include <tls_server.hpp>

TEST( IntegrationTest, BaseTlsClient_Ts ) {

    ntk::generate_default_client_config();
    auto client_config_result = ntk::load_client_config();
    ASSERT_TRUE( client_config_result ) << client_config_result.error();
    auto client_hello_result = ntk::generate_client_hello( client_config_result.value() );

    ntk::base_tls_client client( [& ]( std::vector<uint8_t>& payload ) {
        std::cout << "Payload received, payload size: " << payload.size() << std::endl;
    } );
    ntk::base_tls_client_friend_helper::set_server_state( client, ntk::base_tls_client::tls_state::client_hello_sent );
    ntk::base_tls_client_friend_helper::set_client_hello_result( client, client_hello_result.value() );

    auto server_hello_result = ntk::generate_server_hello( client_hello_result.value().client_hello );
    auto construct_result = ntk::construct_server_hello_record( server_hello_result.value().server_hello );
    ntk::base_tls_client_friend_helper::set_internal_buffer( client, construct_result.value() );
    ntk::base_tls_client_friend_helper::process_tls_data( client );

    auto server_context_result = ntk::get_server_tls_context( server_hello_result.value(), client_hello_result.value().client_hello );
    ASSERT_TRUE( server_context_result ) << server_context_result.error();
    auto& server_context = server_context_result.value();
    uint64_t seq_num{};

    auto read_result = ntk::read_from_file( "http_response.txt" );
    ASSERT_TRUE( read_result ) << read_result.error();
    auto& http_message = read_result.value();
    auto ts_read_result = ntk::read_from_file( "../assets/segment.ts" );
    ASSERT_TRUE( ts_read_result ) << ts_read_result.error();    
    auto& ts = ts_read_result.value();
    http_message.insert( http_message.end(), ts.begin(), ts.end() );

    std::visit( [&]( auto&& secrets ) {
        auto records_result = ntk::convert_to_tls_application_data_records(
        ntk::cipher_suite::TLS_AES_128_GCM_SHA256,
            http_message,
            secrets.server_traffic_secret_0,
            seq_num,
            16385
        );
        ASSERT_TRUE( records_result ) << records_result.error();
        auto& records = records_result.value();
        

        ntk::base_tls_client_friend_helper::set_server_state( client, ntk::base_tls_client::tls_state::request_sent );
        for ( const auto& record : records ) {
            std::size_t offset = 0;
            while ( offset < record.size() ) {
                std::size_t chunk_size = std::min<std::size_t>( 500, record.size() - offset );
                std::span<const uint8_t> chunk(record.data() + offset, chunk_size);
                ntk::base_tls_client_friend_helper::set_internal_buffer( client, chunk );
                ntk::base_tls_client_friend_helper::process_tls_data( client );
                offset += chunk_size;
            }
        }
    }, server_context.secrets );
}