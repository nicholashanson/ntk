#include <gtest/gtest.h>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsValidFinAckFinAck ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "lena"] );
	ntk::fin_ack_fin_ack closing_sequence{ packet_data[ 458 ], packet_data[ 459 ], packet_data[ 459 ], packet_data[ 460 ] };
	auto result = ntk::is_valid_fin_ack_fin_ack( closing_sequence );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_TRUE( result.value() ); 
}

TEST( UnitTest, IsValidFinAckFinAck_CounterCase ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "lena"] );
	ntk::fin_ack_fin_ack closing_sequence{ packet_data[ 458 ], packet_data[ 458 ], packet_data[ 459 ], packet_data[ 460 ] };
	auto result = ntk::is_valid_fin_ack_fin_ack( closing_sequence );
	ASSERT_TRUE( result ) << result.error() << std::endl;
	ASSERT_FALSE( result.value() ); 
}