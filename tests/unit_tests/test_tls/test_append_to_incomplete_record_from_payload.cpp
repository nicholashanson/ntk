#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, AppendToIncompleteRecordFromPayload_IncompleteRecord_BecomesComplete ) {
	std::vector<uint8_t> first_half_of_record = { 0x16, 0x03, 0x03, 0x00, 0x03, 0x01 };
	std::vector<uint8_t> second_half_of_record = { 0x02, 0x03 };
	auto parse_result = ntk::get_complete_or_incomplete_record_from_payload( first_half_of_record );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& record_variant = parse_result.value();
	ASSERT_TRUE( std::holds_alternative<ntk::incomplete_tls_record>( record_variant ) );
	auto& incomplete_record = std::get<ntk::incomplete_tls_record>( record_variant );
	auto result = ntk::append_to_incomplete_record_from_payload( incomplete_record, second_half_of_record );  
	ASSERT_TRUE( std::holds_alternative<ntk::tls_record>( result ) ); 
}