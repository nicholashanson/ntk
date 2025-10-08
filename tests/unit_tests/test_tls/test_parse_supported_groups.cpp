#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, ParseSupportedGroups ) {
	std::vector<uint8_t> supported_groups = { 0x00, 0x0c, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01 };
	auto parse_result = ntk::parse_supported_groups( supported_groups );
	ASSERT_TRUE( parse_result ) << parse_result.error() << std::endl;
	auto& named_groups = parse_result.value();
	EXPECT_EQ( named_groups.size(), 6 );
}