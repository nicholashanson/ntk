#include <gtest/gtest.h>

#include <tls.hpp>

TEST( UnitTest, Pkcs7Pad_Empty ) {
	const std::size_t block_size = 8;
	std::vector<uint8_t> data = {};
	std::vector<uint8_t> expected( block_size, static_cast<uint8_t>( block_size ) );
	EXPECT_EQ( ntk::pkcs7_pad( data, block_size), expected );
}

TEST( UnitTest, Pkcs7Pad_Shorter ) {
	const std::size_t block_size = 8;
	std::vector<uint8_t> data = { 0x01, 0x02, 0x03 };
	std::vector<uint8_t> expected = { 0x01, 0x02, 0x03, 0x05, 0x05, 0x05, 0x05, 0x05 };
	EXPECT_EQ( ntk::pkcs7_pad( data, block_size ), expected );
}

TEST( UnitTest, Pkcs7Pad_Equal ) {
	const std::size_t block_size = 8;
	std::vector<uint8_t> data = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	std::vector<uint8_t> expected = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
									  0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 };
	EXPECT_EQ( ntk::pkcs7_pad( data, block_size ), expected );
}