#include <gtest/gtest.h>

#include <cstdint>
#include <span>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, TcpTerminationFeed ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "lena" ] );
	auto four = *ntk::get_four_from_ethernet( packet_data.front() );
	ntk::tcp_termination_feed termination_feed( four );
	for ( auto& packet : packet_data ) {
		auto feed_result = termination_feed.feed( packet );
		if ( !feed_result ) {
			std::cout << feed_result.error() << std::endl;
		}
	}
	ASSERT_TRUE( termination_feed.m_complete );
}
