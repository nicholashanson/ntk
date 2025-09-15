#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tcp_handshake_packets.hpp>

TEST( UnitTest, TlsLiveStream_Initialization_ClientHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& client_hello_packet = packet_data[ 3 ];
	auto four_result = ntk::get_four_from_ethernet( client_hello_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::tls_live_stream live_stream( four );
	auto client_hello_populated = ntk::tls_live_stream_friend_helper::client_hello_populated( live_stream );
	ASSERT_FALSE( client_hello_populated );
}

TEST( UnitTest, TlsLiveStream_Initialization_LinesConsumed ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "tls_session_keys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );read_packets_to
	auto lines_consumed = ntk::tls_live_stream_friend_helper::lines_consumed( live_stream );
	ASSERT_EQ( lines_consumed, 0 );
}

TEST( UnitTest, TlsLiveStream_Initialization_ClientTrafficSeqNumber ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "tls_session_keys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	auto client_traffic_seq_number = ntk::tls_live_stream_friend_helper::client_traffic_seq_number( live_stream );
	ASSERT_EQ( client_traffic_seq_number, 0 );
}

TEST( UnitTest, TlsLiveStream_Initialization_IncompleteRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "tls_session_keys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	auto incomplete_record = ntk::tls_live_stream_friend_helper::get_incomplete_record( live_stream );
	ASSERT_FALSE( incomplete_record );
}
read_packets_to
TEST( UnitTest, TlsLiveStream_Initialization_ServerTrafficSeqNumber ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "tls_session_keys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	auto server_traffic_seq_number = ntk::tls_live_stream_friend_helper::server_traffic_seq_number( live_stream );
	ASSERT_EQ( server_traffic_seq_number, 0 );
}

TEST( UnitTest, TlsLiveStream_HandshakeFeed_Complete ) {
	std::vector<uint8_t> tcp_syn_packet( std::begin( test_constants::tcp_syn_packet), std::end( test_constants::tcp_syn_packet ) );
	std::vector<uint8_t> tcp_synack_packet( std::begin( test_constants::tcp_synack_packet), std::end( test_constants::tcp_synack_packet ) );  
	std::vector<uint8_t> tcp_ack_packet( std::begin( test_constants::tcp_ack_packet), std::end( test_constants::tcp_ack_packet ) ); 
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::tls_live_stream live_stream( four );
	live_stream.feed( tcp_syn_packet );
	live_stream.feed( tcp_synack_packet );
	live_stream.feed( tcp_ack_packet );
	auto handshake_complete = ntk::tcp_live_stream_friend_helper::handshake_feed( live_stream ).m_complete;
	ASSERT_TRUE( handshake_complete );
}

TEST( UnitTest, TlsLiveStream_ClientHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	auto& syn = packet_data[ 0 ];
	auto& synack = packet_data[ 1 ];
	auto& ack = packet_data[ 2 ];
	auto& client_hello_packet = packet_data[ 3 ];
	auto four_result = ntk::get_four_from_ethernet( client_hello_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::tls_live_stream live_stream( four );
	live_stream.feed( syn );
	live_stream.feed( synack );
	live_stream.feed( ack ); 
	live_stream.feed( client_hello_packet );
	auto client_hello_populated = ntk::tls_live_stream_friend_helper::client_hello_populated( live_stream );
	ASSERT_TRUE( client_hello_populated );
	auto client_hello_from_ethernet = ntk::get_client_hello_from_ethernet_frame( client_hello_packet );
	auto client_hello_from_tls_live_stream = *ntk::tls_live_stream_friend_helper::get_client_hello( live_stream );
	ASSERT_EQ( client_hello_from_ethernet, client_hello_from_tls_live_stream );
}

TEST( UnitTest, TlsLiveStream_ClientHelloPopulated_LongStream ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::tls_live_stream live_stream( four );
	const std::size_t read_up_to = 4;
	for ( std::size_t i = 0; i < 4; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto client_hello_populated = ntk::tls_live_stream_friend_helper::client_hello_populated( live_stream );
	ASSERT_TRUE( client_hello_populated );
}

TEST( UnitTest, TlsLiveStream_ClientHelloPopulated_CounterCase ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& client_hello_packet = packet_data[ 3 ];
	auto four_result = ntk::get_four_from_ethernet( client_hello_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::tls_live_stream live_stream( four );
	live_stream.feed( client_hello_packet );
	auto client_hello_populated = ntk::tls_live_stream_friend_helper::client_hello_populated( live_stream );
	ASSERT_FALSE( client_hello_populated );
}

TEST( UnitTest, TlsLiveStream_ServerHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& syn = packet_data[ 0 ];
	auto& synack = packet_data[ 1 ];
	auto& ack = packet_data[ 2 ];
	auto& client_hello_packet = packet_data[ 3 ];
	auto& server_hello_packet = packet_data[ 5 ];
	auto four_result = ntk::get_four_from_ethernet( client_hello_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::tls_live_stream live_stream( four );
	live_stream.feed( syn );
	live_stream.feed( synack );
	live_stream.feed( ack ); 
	live_stream.feed( client_hello_packet );
	live_stream.feed( server_hello_packet );
	auto server_hello_populated = ntk::tls_live_stream_friend_helper::server_hello_populated( live_stream );
	ASSERT_TRUE( server_hello_populated );
}

TEST( UnitTest, TlsLiveStream_ServerHelloPopulated_CounterCase ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& server_hello_packet = packet_data[ 4 ];
	auto four_result = ntk::get_four_from_ethernet( server_hello_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::tls_live_stream live_stream( four );
	live_stream.feed( server_hello_packet );
	auto server_hello_populated = ntk::tls_live_stream_friend_helper::server_hello_populated( live_stream );
	ASSERT_FALSE( server_hello_populated );
}

TEST( UnitTest, TlsLiveStream_GetTlsSecretsDynamically ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	ASSERT_FALSE( packet_data.empty() );
	std::string ssl_keys_log = "tls_session_keys.log";
	auto& syn = packet_data[ 0 ];
	auto& synack = packet_data[ 1 ];
	auto& ack = packet_data[ 2 ];
	auto& client_hello_packet = packet_data[ 3 ];
	auto& server_hello_packet = packet_data[ 5 ];
	auto four_result = ntk::get_four_from_ethernet( client_hello_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	live_stream.feed( syn );
	live_stream.feed( synack );
	live_stream.feed( ack ); 
	live_stream.feed( client_hello_packet );
	live_stream.feed( server_hello_packet );
	auto lines_consumed = ntk::tls_live_stream_friend_helper::lines_consumed( live_stream );
	ASSERT_EQ( lines_consumed, 10 );
}

TEST( UnitTest, TlsLiveStream_ClientTrafficSeqNumber ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 12 /* first http request */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto client_traffic_seq_number = ntk::tls_live_stream_friend_helper::client_traffic_seq_number( live_stream );
	auto client_hello_from_tls_live_stream = *ntk::tls_live_stream_friend_helper::get_client_hello( live_stream );
	ASSERT_EQ( client_traffic_seq_number, 1 );
}

TEST( UnitTest, TlsLiveStream_ServerTrafficSeqNumber ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 14 /* first http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto server_traffic_seq_number = ntk::tls_live_stream_friend_helper::server_traffic_seq_number( live_stream );
	auto partial_record_buffer = ntk::tls_live_stream_friend_helper::partial_record_buffer( live_stream );
	ASSERT_TRUE( partial_record_buffer.empty() );
	ASSERT_EQ( server_traffic_seq_number, 1 );
}

TEST( UnitTest, TlsLiveStream_Initialization_DecryptedRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake"] );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "tls_session_keys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	auto decrypted_records = ntk::tls_live_stream_friend_helper::decrypted_records( live_stream );
	ASSERT_FALSE( decrypted_records );
}

TEST( UnitTest, TlsLiveStream_DecryptedRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 12 /* first http request */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto decrypted_records = ntk::tls_live_stream_friend_helper::decrypted_records( live_stream );
	ASSERT_TRUE( decrypted_records );
	ASSERT_EQ( decrypted_records.value().size(), 1 );
}

TEST( UnitTest, TlsLiveStream_DecryptedRecord_Reset ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 13 /* one packet after first http request */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto decrypted_records = ntk::tls_live_stream_friend_helper::decrypted_records( live_stream );
	ASSERT_FALSE( decrypted_records );
}

TEST( UnitTest, TlsLiveStream_Initialization_PartialRecordBuffer ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tls_handshake" ] );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "tls_session_keys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	auto partial_record_buffer = ntk::tls_live_stream_friend_helper::partial_record_buffer( live_stream );
	ASSERT_TRUE( partial_record_buffer.empty() );
}

TEST( UnitTest, TlsLiveStream_IncompleteRecord_NotNullOpt ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 19 /* first part of first record of http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
		auto incomplete_record = ntk::tls_live_stream_friend_helper::get_incomplete_record( live_stream );
		if ( i < read_packets_to - 1 ) ASSERT_FALSE( incomplete_record );
	}
	auto incomplete_record = ntk::tls_live_stream_friend_helper::get_incomplete_record( live_stream );
	ASSERT_TRUE( incomplete_record );
}

TEST( UnitTest, TlsLiveStream_IncompleteRecord_PayloadGrows ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 21 /* second part of first record of http response */;
	std::size_t payload_size_before;
	std::size_t payload_size_after;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
        live_stream.feed( packet_data[ i ] );
        if ( i == read_packets_to - 3 ) {
        	auto incomplete_record = ntk::tls_live_stream_friend_helper::get_incomplete_record( live_stream );
        	payload_size_before = incomplete_record.value().record.payload.size();	
        }
        if ( i == read_packets_to - 1 ) {
        	auto incomplete_record = ntk::tls_live_stream_friend_helper::get_incomplete_record( live_stream );
        	payload_size_after = incomplete_record.value().record.payload.size();	
        }
    }
	ASSERT_GT( payload_size_after, payload_size_before );
}

TEST( UnitTest, TlsLiveStream_IncompleteRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 19 /* first part of first record http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto incomplete_record = ntk::tls_live_stream_friend_helper::get_incomplete_record( live_stream );
	ASSERT_TRUE( incomplete_record );
}

TEST( UnitTest, TlsLiveStream_IncompleteRecord_IsStartOfNextRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 27 /* last part of first record of http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto incomplete_record = ntk::tls_live_stream_friend_helper::get_incomplete_record( live_stream );
	auto decrypted_records = ntk::tls_live_stream_friend_helper::decrypted_records( live_stream );
	ASSERT_TRUE( incomplete_record );
	ASSERT_EQ( incomplete_record.value().record.payload.size(), 797 );
	ASSERT_TRUE( decrypted_records );
	ASSERT_EQ( decrypted_records.value().size(), 1 );
}

TEST( UnitTest, TlsLiveStream_LinesConsumed ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 7 /* server hello */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto lines_consumed = ntk::tls_live_stream_friend_helper::lines_consumed( live_stream );
	ASSERT_EQ( lines_consumed, 160 );
}

TEST( UnitTest, TlsLiveStream_HasSecrets ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::tls_live_stream live_stream( four, ssl_keys_log );
	ASSERT_FALSE( live_stream.has_secrets() );
	const std::size_t read_packets_to = 7 /* server hello */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	ASSERT_TRUE( live_stream.has_secrets() );
}
