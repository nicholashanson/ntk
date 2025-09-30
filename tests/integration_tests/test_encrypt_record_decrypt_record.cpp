#include <gtest/gtest.h>

#include <tls.hpp>

TEST( IntegrationTest, EncryptRecordDecryptRecord ) {
	std::array<uint8_t,32> client_random{};
	std::array<uint8_t,32> server_random{};
	std::string client_random_string = ntk::client_random_to_hex( client_random );
	ntk::tls_version version = ntk::tls_version::tls_1_3;
	uint16_t cipher_suite_id = static_cast<uint16_t>( ntk::cipher_suite::TLS_AES_256_GCM_SHA384 );
	uint64_t seq_num = 0;
	ntk::secrets session_keys;
	session_keys[ client_random_string ][ "application_traffic_secret_0" ] = {
   		0x8d, 0x1d, 0x1e, 0x3b, 0x3e, 0x5f, 0x8b, 0xe8,
    	0xe6, 0xa5, 0x3e, 0xd3, 0xad, 0x2c, 0x23, 0xf1,
    	0xc1, 0xba, 0xd2, 0xce, 0x86, 0xfd, 0xdc, 0x25,
    	0xe8, 0x2c, 0x90, 0x24, 0xb0, 0xef, 0xd5, 0xfe,
    	0xd4, 0xe5, 0x56, 0xd6, 0xf1, 0x95, 0xb9, 0x3e,
    	0x39, 0x2c, 0xa5, 0xfc, 0xad, 0xb3, 0x74, 0x67
    };
    ntk::tls_record plain_record {
    	ntk::tls_content_type::application_data,
    	version,
    	{ 'h', 'e', 'l', 'l', 'o' }
    };
    ntk::tls_record encrypted_record = ntk::encrypt_record( client_random,
                                                            server_random,
                                                            version,
                                                            cipher_suite_id,
                                                            plain_record,
                                                            session_keys,
                                                            "application_traffic_secret_0",
                                                            seq_num );
    ntk::tls_record decrypted_record = ntk::decrypt_record( client_random,
                                                            server_random,
                                                            version,
                                                            cipher_suite_id,
                                                            encrypted_record,
                                                            session_keys,
                                                            "application_traffic_secret_0",
                                                            seq_num );
    ASSERT_EQ( decrypted_record, plain_record );
}

TEST( IntegrationTest, EncryptRecordDecryptRecord_ChaCha ) {
    std::array<uint8_t,32> client_random{};
    std::array<uint8_t,32> server_random{};
    std::string client_random_string = ntk::client_random_to_hex( client_random );
    ntk::tls_version version = ntk::tls_version::tls_1_3;
    uint16_t cipher_suite_id = static_cast<uint16_t>( ntk::cipher_suite::TLS_CHACHA20_POLY1305_SHA256 );
    uint64_t seq_num = 0;
    ntk::secrets session_keys;
    session_keys[ client_random_string ][ "application_traffic_secret_0" ] = {
        0x8d, 0x1d, 0x1e, 0x3b, 0x3e, 0x5f, 0x8b, 0xe8,
        0xe6, 0xa5, 0x3e, 0xd3, 0xad, 0x2c, 0x23, 0xf1,
        0xc1, 0xba, 0xd2, 0xce, 0x86, 0xfd, 0xdc, 0x25,
        0xe8, 0x2c, 0x90, 0x24, 0xb0, 0xef, 0xd5, 0xfe
    };
    ntk::tls_record plain_record {
        ntk::tls_content_type::application_data,
        version,
        { 'h', 'e', 'l', 'l', 'o' }
    };
    ntk::tls_record encrypted_record = ntk::encrypt_record( client_random,
                                                            server_random,
                                                            version,
                                                            cipher_suite_id,
                                                            plain_record,
                                                            session_keys,
                                                            "application_traffic_secret_0",
                                                            seq_num );
    ntk::tls_record decrypted_record = ntk::decrypt_record( client_random,
                                                            server_random,
                                                            version,
                                                            cipher_suite_id,
                                                            encrypted_record,
                                                            session_keys,
                                                            "application_traffic_secret_0",
                                                            seq_num );
    ASSERT_EQ( decrypted_record, plain_record );
}


