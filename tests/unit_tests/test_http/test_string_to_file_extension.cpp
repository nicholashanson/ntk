#include <gtest/gtest.h>

#include <http.hpp>

#include <test_constants.hpp>

TEST( UnitTest, StringToFileExtension ) {
	ASSERT_EQ( ntk::string_to_file_extension( "m3u8" ), ntk::file_extension::M3U8 );
}