#include <gtest/gtest.h>

#include <x_509.hpp>

#include <test_constants.hpp>

TEST( UnitTest, GetTbsRdns ) {
	auto certificate_bytes = std::span<const uint8_t>( test::tls_certificate );
    certificate_bytes = certificate_bytes.subspan( 138, 23 );
    auto rdns_result = ntk::get_tbs_rdns( certificate_bytes );
    ASSERT_TRUE( rdns_result ) << rdns_result.error() << std::endl;
    auto& rdns = rdns_result.value();
    std::vector<uint8_t> expected_id{ 0x55, 0x04, 0x03 };
    ASSERT_EQ( rdns.size(), 1 );
    EXPECT_EQ( rdns.front().oid, expected_id );
    EXPECT_EQ( rdns.front().value, "earthcam.com" );
	
}