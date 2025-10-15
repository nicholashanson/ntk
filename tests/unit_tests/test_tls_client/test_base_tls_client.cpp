#include <gtest/gtest.h>

#include <tls_client.hpp>
#include <tls_server.hpp>

TEST( UnitTest, BaseTlsClient_HandleBuffer_SingleCompleteRecord ) {
	std::vector<uint8_t> record = { 0x17, 0x03, 0x03, 0x00, 0x01, 0xff };
	ntk::base_tls_client client;
	ntk::base_tls_client_friend_helper::set_internal_buffer( client, record );
	auto internal_buffer_before = ntk::base_tls_client_friend_helper::get_internal_buffer( client );
	EXPECT_EQ( internal_buffer_before.size(), 6 );
	ntk::base_tls_client_friend_helper::set_server_state( client, ntk::base_tls_client::tls_state::handshake_complete );
	ntk::base_tls_client_friend_helper::process_tls_data( client );
	auto internal_buffer_after = ntk::base_tls_client_friend_helper::get_internal_buffer( client );
	EXPECT_EQ( internal_buffer_after.size(), 0 );
}

TEST( UnitTest, BaseTlsClient_HandleBuffer_SingleIncompleteRecord ) {
	std::vector<uint8_t> record = { 0x17, 0x03, 0x03, 0x00, 0x03, 0xff };
	ntk::base_tls_client client;
	ntk::base_tls_client_friend_helper::set_internal_buffer( client, record );
	auto internal_buffer_before = ntk::base_tls_client_friend_helper::get_internal_buffer( client );
	EXPECT_EQ( internal_buffer_before.size(), 6 );
	ntk::base_tls_client_friend_helper::set_server_state( client, ntk::base_tls_client::tls_state::handshake_complete );
	ntk::base_tls_client_friend_helper::process_tls_data( client );
	auto internal_buffer_after = ntk::base_tls_client_friend_helper::get_internal_buffer( client );
	EXPECT_EQ( internal_buffer_after.size(), 0 );
	auto incomplete_record = ntk::base_tls_client_friend_helper::get_incomplete_record( client );
	ASSERT_TRUE( incomplete_record );
	EXPECT_EQ( incomplete_record->record.payload.size(), 1 );
}

TEST( UnitTest, BaseTlsClient_HandleServerHello ) {
	ntk::generate_default_client_config();
	ntk::generate_default_server_config();
	auto client_config_result = ntk::load_client_config();
	ASSERT_TRUE( client_config_result ) << client_config_result.error();
	auto client_hello_result = ntk::generate_client_hello( client_config_result.value() );
	ASSERT_TRUE( client_hello_result ) << client_hello_result.error();
	auto& client_hello_bytes = client_hello_result->client_hello;
	auto server_hello_result = ntk::generate_server_hello( client_hello_bytes );
	auto& server_hello_bytes = server_hello_result.value();
	ntk::base_tls_client client;
	ntk::base_tls_client_friend_helper::set_client_hello_result( client, client_hello_result.value() );
	ntk::base_tls_client_friend_helper::set_server_state( client, ntk::base_tls_client::tls_state::client_hello_sent );
	ntk::base_tls_client_friend_helper::set_internal_buffer( client, server_hello_bytes.server_hello );
	ntk::base_tls_client_friend_helper::process_tls_data( client );
	auto tls_context = ntk::base_tls_client_friend_helper::get_tls_context( client );
	ASSERT_TRUE( tls_context );
}