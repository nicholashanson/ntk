#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetTbsValidity ) {
	auto certificate_bytes = std::span<const uint8_t>( test::tls_certificate );
    certificate_bytes = certificate_bytes.subspan( 104, 32 );
	auto validity_result = ntk::get_tbs_validity( certificate_bytes );
    ASSERT_TRUE( validity_result ) << validity_result.error() << std::endl;
    std::tm tm{};
    tm.tm_year = 2025 - 1900; 
    tm.tm_mon  = 5 - 1;      
    tm.tm_mday = 27;
    tm.tm_hour = 7;
    tm.tm_min  = 33;
    tm.tm_sec  = 8;
    std::time_t expected_time_t = timegm( &tm ); 
    auto expected_time = std::chrono::system_clock::from_time_t( expected_time_t );
	EXPECT_EQ( validity_result.value().not_before, expected_time );
}