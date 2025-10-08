#include <gtest/gtest.h>
#include <qt.hpp>

#include <https.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( VisualTest, Segment ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "segment_capture" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto four_result = ntk::get_four_from_ethernet( packet_data.front() );
	ASSERT_TRUE( four_result ) << four_result.error() << std::endl;
	std::string ssl_keys_log = "../server/session_keys.log";
	ntk::https_live_stream live_stream( four_result.value(), ssl_keys_log );
	std::string file_name;
	for ( auto& packet : packet_data ) {
		live_stream.feed( packet );
		auto file_name_opt = ntk::https_live_stream_friend_helper::name_of_written_file( live_stream );
		if ( file_name_opt ) {
			file_name = file_name_opt.value();
		}
	}
	test::show_ts_in_qt_window( QString::fromStdString( "../assets/segment.ts" ) );
}