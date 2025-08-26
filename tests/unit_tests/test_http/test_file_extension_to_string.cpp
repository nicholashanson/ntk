#include <gtest/gtest.h>

#include <http.hpp>

TEST( UnitTest, FileExtensionToString ) {
	ASSERT_EQ ( "ts", *ntk::file_extension_to_string( ntk::file_extension::TS ) );
}
