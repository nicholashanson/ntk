#include <gtest/gtest.h>

#include <tls.hpp>
#include <io.hpp>    

#include <test_constants.hpp>

TEST( UnitTest, GetTlsRecordsFromEthernet ) {
    auto packet_data = ntk::read_packets_from_file( test::packet_data_files[ "long_stream" ] );
    auto split_result = ntk::get_tls_records_from_ethernet( packet_data[ 13 ] );
    if ( !split_result ) { 
        std::cout << split_result.error() << std::endl;
    }
    auto [ records, offset_reached ] = split_result.value();
    ASSERT_EQ( records.size(), 1 );
}