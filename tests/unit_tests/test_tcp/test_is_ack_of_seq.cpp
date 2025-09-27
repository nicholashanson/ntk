#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsAckOfSeq ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "lena" ] );
	auto result = ntk::is_ack_of_seq( packet_data[ 458 ], packet_data[ 459 ] );
	ASSERT_TRUE( result );
	ASSERT_TRUE( result.value() );
}

TEST( UnitTest, IsAckOfSeq_CounterCase ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "lena" ] );
	auto result = ntk::is_ack_of_seq( packet_data[ 458 ], packet_data[ 458 ] );
	ASSERT_TRUE( result );
	ASSERT_FALSE( result.value() );
}