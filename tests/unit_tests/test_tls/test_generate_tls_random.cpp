#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, GenerateTlsRandom ) {
	const uint32_t dummy_timestamp = 0x64a7b2c1;
	std::array<uint8_t,4> expected_bytes = { 0x64, 0xa7, 0xB2, 0xc1 };
	auto random = ntk::generate_tls_random( dummy_timestamp );
	bool match = std::equal( expected_bytes.begin(), expected_bytes.end(), random.begin() );
	ASSERT_TRUE( match );
}