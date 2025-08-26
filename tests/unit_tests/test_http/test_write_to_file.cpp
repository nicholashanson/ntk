#include <gtest/gtest.h>

#include <fstream>
#include <filesystem>

#include <http.hpp>

TEST( UnitTest, WriteToFile ) {
    std::vector<uint8_t> data = { 'h', 'e', 'l', 'l', 'o' };
    ntk::file_extension extension = ntk::file_extension::TS;
    auto filename = ntk::write_to_file( data, extension );
    ASSERT_TRUE( std::filesystem::exists( filename ) );
    std::ifstream in( filename, std::ios::binary );
    ASSERT_TRUE( in.is_open() );
    std::vector<uint8_t> read_data( ( std::istreambuf_iterator<char>( in ) ), std::istreambuf_iterator<char>() );
    ASSERT_EQ( data, read_data );
    in.close();
    std::filesystem::remove( filename );
}