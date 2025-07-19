#include <gtest/gtest.h>

#include <ipv4.hpp>
#include <tcp.hpp>
#include <utils.hpp>
#include <io.hpp>

#include <test_constants.hpp>

TEST( UnitTest, IsAckOfSeq ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "lena" ] );
    auto& initiator_fin = packet_data[ 458 ];
    auto& piggbacked_responder_fin = packet_data[ 459 ];
    ASSERT_TRUE( ntk::is_ack_of_seq( initiator_fin, piggbacked_responder_fin ) );
}