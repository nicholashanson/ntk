#include <gtest/gtest.h>

#include <x_509.hpp>

TEST( UnitTest, ParseUtcTime ) {
	std::vector<uint8_t> utc_time{ 0x32, 0x35, 0x30, 0x35, 0x32, 0x37, 0x30, 0x37, 0x33, 0x33, 0x30, 0x38, 0x5a };
	auto time_result = ntk::parse_utc_time( utc_time );
    ASSERT_TRUE( time_result ) << time_result.error() << std::endl;
    auto& time = time_result.value();
    std::tm tm{};
    tm.tm_year = 2025 - 1900; 
    tm.tm_mon  = 5 - 1;      
    tm.tm_mday = 27;
    tm.tm_hour = 7;
    tm.tm_min  = 33;
    tm.tm_sec  = 8;
    std::time_t expected_time_t = timegm( &tm ); 
    auto expected_time = std::chrono::system_clock::from_time_t( expected_time_t );
	EXPECT_EQ( time, expected_time );
}