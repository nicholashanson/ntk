#include <gtest/gtest.h>

#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, ReadPacketsFromFile_TinyCross ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "tiny_cross" ] );
    ASSERT_EQ( packet_data.size(), 13 );
}
