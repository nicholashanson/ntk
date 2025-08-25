#include <gtest/gtest.h>

#include <tls.hpp>

#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, GetServerHelloSessionId ) {
	const std::size_t session_id_pos = 35;
	const std::size_t session_id_len = 32;
	ntk::server_hello s_hello;
	ntk::get_server_hello_session_id( test_constants::tls_server_hello_body, s_hello );
	std::vector<uint8_t> expected_session_id( 
		std::begin( test_constants::tls_server_hello_body ) + session_id_pos, 
		std::begin( test_constants::tls_server_hello_body ) + session_id_pos + session_id_len );
	ASSERT_EQ( s_hello.session_id, expected_session_id );
} 