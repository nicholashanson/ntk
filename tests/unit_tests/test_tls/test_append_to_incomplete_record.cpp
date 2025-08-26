#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, AppendToIncompleteRecord_CompleteRecord ) {
	std::vector<uint8_t> complete_record_bytes = { 0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03 };
	auto complete_record = *ntk::get_parsed_tls_record( complete_record_bytes );
	auto incomplete_record = ntk::incomplete_tls_record{ complete_record, complete_record.payload.size() };
	auto result = ntk::append_to_incomplete_record( incomplete_record, std::vector<uint8_t>{} );  
	ASSERT_TRUE( std::holds_alternative<ntk::tls_record>( result ) ); 
}

TEST( UnitTest, AppendToIncompleteRecord_IncompleteRecord ) {
	std::vector<uint8_t> complete_record_bytes = { 0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03 };
	auto complete_record = *ntk::get_parsed_tls_record( complete_record_bytes );
	complete_record.payload.pop_back();
	auto incomplete_record = ntk::incomplete_tls_record{ complete_record, complete_record_bytes.size() };
	auto result = ntk::append_to_incomplete_record( incomplete_record, std::vector<uint8_t>{} );  
	ASSERT_TRUE( std::holds_alternative<ntk::incomplete_tls_record>( result ) ); 
}

TEST( UnitTest, AppendToIncompleteRecord_LongStream ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto incomplete_record = ntk::get_complete_or_incomplete_record( packet_data[ 18 ] );
	std::size_t record_payload_length_before = std::get<ntk::incomplete_tls_record>( incomplete_record ).record.payload.size();
	auto appended_to_incomplete_record = ntk::append_to_incomplete_record( std::get<ntk::incomplete_tls_record>( incomplete_record ), packet_data[ 20 ] );
	std::size_t record_payload_length_after = std::get<ntk::incomplete_tls_record>( appended_to_incomplete_record ).record.payload.size();
	ASSERT_GT( record_payload_length_after, record_payload_length_before ); 
}

TEST( UnitTest, AppendToIncompleteRecord_LongStream_CompleteRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	auto incomplete_record = ntk::get_complete_or_incomplete_record( packet_data[ 18 ] );
	std::vector<std::size_t> indices = { 20, 22, 24, 26 };
    std::variant<ntk::tls_record, ntk::incomplete_tls_record> current_record = incomplete_record;
    for ( std::size_t index : indices ) {
        if ( std::holds_alternative<ntk::incomplete_tls_record>( current_record ) ) {
            current_record = ntk::append_to_incomplete_record(
                std::get<ntk::incomplete_tls_record>( current_record ),
                packet_data[ index ]
            );
        }
    }
    ASSERT_TRUE(std::holds_alternative<ntk::tls_record>( current_record ) );
}