#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, AppendToIncompleteRecord_CompleteRecord ) {
	std::vector<uint8_t> complete_record_bytes = { 0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03 };
	auto parse_result = ntk::get_parsed_tls_record( complete_record_bytes );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& complete_record = parse_result.value();
	auto incomplete_record = ntk::incomplete_tls_record{ complete_record, complete_record.payload.size() };
	auto result = ntk::append_to_incomplete_record( incomplete_record, std::vector<uint8_t>{} );  
	ASSERT_TRUE( std::holds_alternative<ntk::tls_record>( result ) ); 
}

TEST( UnitTest, AppendToIncompleteRecord_IncompleteRecord ) {
	std::vector<uint8_t> complete_record_bytes = { 0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03 };
	auto parse_result = ntk::get_parsed_tls_record( complete_record_bytes );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& complete_record = parse_result.value();
	complete_record.payload.pop_back();
	auto incomplete_record = ntk::incomplete_tls_record{ complete_record, complete_record_bytes.size() };
	auto result = ntk::append_to_incomplete_record( incomplete_record, std::vector<uint8_t>{} );  
	ASSERT_TRUE( std::holds_alternative<ntk::incomplete_tls_record>( result ) ); 
}

TEST( UnitTest, AppendToIncompleteRecord_LongStream ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
	ASSERT_FALSE( packet_data.empty() );
	auto parse_result = ntk::get_complete_or_incomplete_record( packet_data[ 18 /* first part of tls record */ ] );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& record_variant = parse_result.value();
	ASSERT_TRUE( std::holds_alternative<ntk::incomplete_tls_record>( record_variant ) );
	auto& incomplete_record = std::get<ntk::incomplete_tls_record>( record_variant ); 
	std::size_t record_payload_length_before = incomplete_record.record.payload.size();
	auto appended_to_record_variant = ntk::append_to_incomplete_record( incomplete_record, packet_data[ 20 /* second part of tls record */ ] );
	ASSERT_TRUE( std::holds_alternative<ntk::incomplete_tls_record>( appended_to_record_variant ) );
	auto& appended_to_record = std::get<ntk::incomplete_tls_record>( appended_to_record_variant );
	std::size_t record_payload_length_after = appended_to_record.record.payload.size();
	ASSERT_GT( record_payload_length_after, record_payload_length_before ); 
}

TEST( UnitTest, AppendToIncompleteRecord_LongStream_CompleteRecord ) {
	auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );\
	ASSERT_FALSE( packet_data.empty() );
	auto parse_result = ntk::get_complete_or_incomplete_record( packet_data[ 18 /* first part of tls record */ ] );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& incomplete_record = parse_result.value();
	std::vector<std::size_t> indices = { 20, 22, 24, 26 /* indices of the other parts of the tls record */ };
    std::variant<ntk::tls_record, ntk::incomplete_tls_record> current_record = incomplete_record;
    for ( std::size_t index : indices ) {
        if ( std::holds_alternative<ntk::incomplete_tls_record>( current_record ) ) {
            current_record = ntk::append_to_incomplete_record(
                std::get<ntk::incomplete_tls_record>( current_record ),
                packet_data[ index ]
            );
        }
    }
    ASSERT_TRUE( std::holds_alternative<ntk::tls_record>( current_record ) );
}
