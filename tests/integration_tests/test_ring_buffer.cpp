#include <gtest/gtest.h>

#include <ring_buffer.hpp>

TEST( IntegrationTest, RingBuffer_PushAndPop ) {
    ntk::ring_buffer<int,4> buf;
    EXPECT_TRUE( buf.push( 10 ) );

    int val;
    EXPECT_TRUE( buf.pop( val ) );
    EXPECT_EQ( val, 10 );
}

TEST( IntegrationTest, RingBuffer_FIFOOrder ) {
    ntk::ring_buffer<int,4> buf;
    buf.push( 1 ); 
    buf.push( 2 ); 
    buf.push( 3 );

    int val;
    buf.pop( val ); EXPECT_EQ( val, 1 );
    buf.pop( val ); EXPECT_EQ( val, 2 );
    buf.pop( val ); EXPECT_EQ( val, 3 );
}

TEST( IntegrationTest, RingBuffer_WrapAround ) {
    ntk::ring_buffer<int,4> buf;
    buf.push( 1 );
    buf.push( 2 );
    buf.push( 3 );

    int val;
    buf.pop( val ); EXPECT_EQ( val, 1 );
    buf.push( 4 ); 
    buf.pop( val ); EXPECT_EQ( val, 2 );
    buf.pop( val ); EXPECT_EQ( val, 3 );
    buf.pop( val ); EXPECT_EQ( val, 4 );
}
