#include <gtest/gtest.h> 

#include <tcp.hpp>

struct  tcp_option_test_case {
	uint8_t option_byte;
	ntk::tcp_option_type expected;
};

class UnitTest : public ::testing::TestWithParam<tcp_option_test_case> {};

TEST_P( UnitTest, GetTcpOptionType ) {
	const auto& param = GetParam();
	auto result = ntk::get_tcp_option_type( param.option_byte );
	ASSERT_TRUE( result.has_value() );
	EXPECT_EQ( result.value(), param.expected );
}

INSTANTIATE_TEST_SUITE_P(
	TcpOptionsTest,
	UnitTest,
	::testing::Values(
		tcp_option_test_case{ 0x00, ntk::tcp_option_type::end_of_options_list },
        tcp_option_test_case{ 0x01, ntk::tcp_option_type::nop },
        tcp_option_test_case{ 0x02, ntk::tcp_option_type::mss },
        tcp_option_test_case{ 0x03, ntk::tcp_option_type::window_scale },
        tcp_option_test_case{ 0x04, ntk::tcp_option_type::sack_permitted },
        tcp_option_test_case{ 0x08, ntk::tcp_option_type::timestamp }
	)
);

TEST( UnitTest, GetTcpOptionType_CounterCase ) {
	const uint8_t invalid_byte = 0xff;
	auto result = ntk::get_tcp_option_type( invalid_byte );
	ASSERT_FALSE( result.has_value() );
}