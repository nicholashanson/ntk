#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include <https.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, HttpsLiveStream_ServerHelloPopulated_HasClientTrafficSecret ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 7 /* client hello */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto server_hello_populated = ntk::tls_live_stream_friend_helper::server_hello_populated( live_stream );
	ASSERT_TRUE( server_hello_populated );
	ASSERT_TRUE( live_stream.has_secrets() );
	ASSERT_TRUE( live_stream.has_client_traffic_secret() );
}

TEST( UnitTest, HttpsLiveStream_TlsSecrets ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 7 /* client hello */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto tls_secrets = ntk::tls_live_stream_friend_helper::tls_secrets( live_stream );
	auto client_hello_opt = ntk::tls_live_stream_friend_helper::get_client_hello( live_stream );
	ASSERT_TRUE( client_hello_opt.has_value() ) << "No ClientHello found after feeding packets";
	auto client_random_hex = ntk::client_random_to_hex( client_hello_opt->get().random );
	ASSERT_TRUE( ntk::is_complete_secrets( tls_secrets[ client_random_hex ] ) );
}

TEST( UnitTest, HttpsLiveStream_IncompleteRequestResponse_HttpRequest ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 12 /* first http request */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto incomplete_request_response = ntk::https_live_stream_friend_helper::get_incomplete_request_response( live_stream );
	ASSERT_TRUE( incomplete_request_response.request );
}

TEST( UnitTest, HttpsLiveStream_Initialization_ExpectedData ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	auto expected_data = ntk::https_live_stream_friend_helper::expected_data( live_stream );	
	ASSERT_FALSE( expected_data );
}

TEST( UnitTest, HttpsLiveStream_Initialization_NameOfWrittenFile ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	auto name_of_written_file = ntk::https_live_stream_friend_helper::name_of_written_file( live_stream );	
	ASSERT_FALSE( name_of_written_file );
}

TEST( UnitTest, HttpsLiveStream_ExpectedData ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 12 /* first http request */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto expected_data = ntk::https_live_stream_friend_helper::expected_data( live_stream );	
	ASSERT_TRUE( expected_data );
}

TEST( UnitTest, HttpsLiveStream_ExpectedData_MimeType ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 12 /* first http request */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto expected_data = ntk::https_live_stream_friend_helper::expected_data( live_stream );	
	ASSERT_EQ( expected_data, ntk::mime_type::VIDEO_MP2T );
}

TEST( UnitTest, HttpsLiveStream_IncompleteRequestResponse_IncompleteHttpResponse ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 27 /* last part of first record of third http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto incomplete_request_response = ntk::https_live_stream_friend_helper::get_incomplete_request_response( live_stream );
	auto decrypted_records = ntk::tls_live_stream_friend_helper::decrypted_records( live_stream ); 
	ASSERT_TRUE( decrypted_records );
	ASSERT_TRUE( decrypted_records.value().size() );
	ASSERT_TRUE( incomplete_request_response.response );
	ASSERT_EQ( ( *incomplete_request_response.response ).body.size(), 15848 );
	ASSERT_EQ( ( *incomplete_request_response.response ).content_length, 384836 );
	ASSERT_FALSE( ( *incomplete_request_response.response ).http_response_complete() );
}

TEST( UnitTest, HttpsLiveStream_IsComplete_BecomesTrue ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	std::size_t read_packets_to = 97 /* last part of last record of third http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto is_complete = ntk::https_live_stream_friend_helper::is_complete( live_stream );
	( is_complete );
}

TEST( UnitTest, HttpsLiveStream_IsComplete_BecomesFalse ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	for ( auto& packet : packet_data ) {
		live_stream.feed( packet );
	}
	auto is_complete = ntk::https_live_stream_friend_helper::is_complete( live_stream );
	ASSERT_FALSE( is_complete );
}

TEST( UnitTest, HttpsLiveStream_IncompleteRequestResponse_IncompleteHttpResponse_ContentLength ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_packets_to = 27 /* last part of first record of third http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto incomplete_request_response = ntk::https_live_stream_friend_helper::get_incomplete_request_response( live_stream );
	ASSERT_EQ( ( *incomplete_request_response.response ).content_length, 384836 );
	ASSERT_FALSE( ( *incomplete_request_response.response ).body.empty() );
}

TEST( UnitTest, HttpsLiveStream_NameOfWrittenFile ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	std::size_t read_packets_to = 97 /* last part of last record of third http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto name_of_written_file = ntk::https_live_stream_friend_helper::name_of_written_file( live_stream );
	ASSERT_TRUE( name_of_written_file );
}

TEST( UnitTest, HttpsLiveStream_FileWrittenToDisk ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	std::size_t read_packets_to = 97 /* last part of last record of tnird http response */;
	for ( std::size_t i = 0; i < read_packets_to; ++i ) {
		live_stream.feed( packet_data[ i ] );
	}
	auto output_file = ntk::https_live_stream_friend_helper::name_of_written_file( live_stream );
	ASSERT_TRUE( std::filesystem::exists( output_file.value() ) );
    ASSERT_GT( std::filesystem::file_size( output_file.value() ), 0u );
    std::filesystem::remove( output_file.value() );
}

TEST( UnitTest, HttpsLiveStream_NameOfWrittenFile_BecomesNullOpt ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	for ( auto& packet : packet_data ) {
		live_stream.feed( packet );
	}
	auto name_of_written_file = ntk::https_live_stream_friend_helper::name_of_written_file( live_stream );
	ASSERT_FALSE( name_of_written_file );
}

TEST( UnitTest, HttpsLiveStream_IncompleteRequestResponse_Response_BecomesNullOpt ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	for ( auto& packet : packet_data ) {
		live_stream.feed( packet );
	}
	auto incomplete_request_response = ntk::https_live_stream_friend_helper::get_incomplete_request_response( live_stream );
	ASSERT_FALSE( incomplete_request_response.response );
}

TEST( UnitTest, HttpsLiveStream_IncompleteRequestResponse_Request_BecomesNullOpt ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto& tcp_syn_packet = packet_data.front();
	auto four_result = ntk::get_four_from_ethernet( tcp_syn_packet );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	std::string ssl_keys_log = "sslkeys.log";
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	for ( auto& packet : packet_data ) {
		live_stream.feed( packet );
	}
	auto incomplete_request_response = ntk::https_live_stream_friend_helper::get_incomplete_request_response( live_stream );
	ASSERT_FALSE( incomplete_request_response.request );
}

TEST( UnitTest, HttpsLiveStream_SegmentCapture ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
	ASSERT_FALSE( packet_data.empty() );
	std::string ssl_keys_log = "../server/session_keys.log";
	auto four_result = ntk::get_four_from_ethernet( packet_data.front() );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	for ( std::size_t i = 0; i < packet_data.size(); ++i ) {
		auto feed_result = live_stream.feed( packet_data[ i ] );
		ASSERT_TRUE( feed_result ) << feed_result.error() << std::endl;
	}
}

TEST( UnitTest, HttpsLiveStream_SegmentCapture_ClientHelloPopulated ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
	ASSERT_FALSE( packet_data.empty() );
	std::string ssl_keys_log = "../server/session_keys.log";
	auto four_result = ntk::get_four_from_ethernet( packet_data.front() );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_to = 7 /* client hello */;
	for ( std::size_t i = 0; i < read_to; ++i ) {
		auto feed_result = live_stream.feed( packet_data[ i ] );
		ASSERT_TRUE( feed_result ) << feed_result.error() << std::endl;
	}
	auto client_hello_populated = ntk::tls_live_stream_friend_helper::client_hello_populated( live_stream );
	ASSERT_TRUE( client_hello_populated );
}

TEST( UnitTest, HttpsLiveStream_SegmentCapture_ServerHelloPopulated_HasSecrets ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
	ASSERT_FALSE( packet_data.empty() );
	std::string ssl_keys_log = "../server/session_keys.log";
	auto four_result = ntk::get_four_from_ethernet( packet_data.front() );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	auto& four = four_result.value();
	ntk::https_live_stream live_stream( four, ssl_keys_log );
	const std::size_t read_to = 9 /* server hello */;
	for ( std::size_t i = 0; i < read_to; ++i ) {
		auto feed_result = live_stream.feed( packet_data[ i ] );
		ASSERT_TRUE( feed_result ) << feed_result.error() << std::endl;
	}
	ASSERT_TRUE( live_stream.has_secrets() );
}