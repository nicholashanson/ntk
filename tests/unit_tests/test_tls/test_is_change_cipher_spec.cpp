#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, IsChangeCipherSpec_Record ) {
	auto parse_result = ntk::get_parsed_tls_record( test_constants::tls_change_cipher_spec_record );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	ASSERT_TRUE( ntk::is_change_cipher_spec( parse_result.value() ) );
}

TEST( UnitTest, IsChangeCipherSpec ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto& packet = packet_data[ 10 ];
	auto record_result = ntk::get_tls_records_from_ethernet( packet );
	ASSERT_TRUE( record_result ) << record_result.error() << std::endl;
	auto [ records, offset_reached ] = record_result.value();
	ASSERT_FALSE( records.empty() );
	ASSERT_TRUE( ntk::is_change_cipher_spec( records.front() ) );
}

