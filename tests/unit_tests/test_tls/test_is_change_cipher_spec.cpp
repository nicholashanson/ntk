#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>
#include <test_tls_handshake_packets.hpp>

TEST( UnitTest, IsChangeCipherSpec_Record ) {
	auto tls_change_cipher_spec_record = *ntk::get_parsed_tls_record( test_constants::tls_change_cipher_spec_record );
	ASSERT_TRUE( ntk::is_change_cipher_spec( tls_change_cipher_spec_record ) );
}

TEST( UnitTest, IsChangeCipherSpec ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto& change_cipher_spec_packet = packet_data[ 10 ];
	auto [ records, offset_reached ] = *ntk::get_tls_records_from_ethernet( change_cipher_spec_packet );
	ASSERT_TRUE( ntk::is_change_cipher_spec( records.front() ) );
}