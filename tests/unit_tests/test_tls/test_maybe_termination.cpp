#include <gtest/gtest.h>

#include <tcp.hpp>

#include <test_lena_termination.hpp>

TEST( UnitTest, MaybeTermination_Feed ) {
	ntk::maybe_termination termination;
	std::vector<uint8_t> initiator_fin( std::begin( test_constants::lena_initiator_fin), std::end( test_constants::lena_initiator_fin ) );
	termination.feed( initiator_fin );
	ASSERT_EQ( termination.initiator_fin, initiator_fin );
} 