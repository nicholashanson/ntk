#include <gtest/gtest.h>

#include <ring_buffer.hpp>

TEST( UnitTest, RingBufferPop_UnderflowBuffer ) {
    ntk::ring_buffer<int,4> buf;
    int val;
    EXPECT_FALSE( buf.pop( val ) );
}