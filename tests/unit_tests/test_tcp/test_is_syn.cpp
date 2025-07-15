#include <gtest/gtest.h>

#include <span>
#include <cstdint>

#include <tcp.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsSyn_CheckerBoard ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "checkerboard" ] );
    ASSERT_TRUE( ntk::is_syn( packet_data[ 0 ] ) );
}