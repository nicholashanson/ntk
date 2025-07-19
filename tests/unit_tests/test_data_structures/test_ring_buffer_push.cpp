#include <gtest/gtest.h>

#include <ring_buffer.hpp>

TEST( UnitTest, RingBufferPush_OverfillBuffer ) {
    ntk::ring_buffer<int,4> buf;
    EXPECT_TRUE( buf.push( 1 ) );
    EXPECT_TRUE( buf.push( 2 ) );
    EXPECT_TRUE( buf.push( 3 ) );
    EXPECT_FALSE( buf.push( 4 ) );
}
