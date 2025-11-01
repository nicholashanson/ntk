#include <dtls.hpp>

namespace ntk {

	std::expected<std::optional<dtls_version>,std::string> get_dtls_version_from_handshake_message( std::span<const uint8_t> handshake_message_bytes ) {
        if ( handshake_message_bytes.size() < constants::version_len  ) {
            return std::unexpected( "Handshake Message too short for DTLS Version" );
        }
        return get_dtls_version( read_uint16_be( handshake_message_bytes, 0 ) );
    }

	std::expected<dtls_client_hello,std::string> parse_dtls_client_hello( std::span<const uint8_t> client_hello_bytes ) {
		dtls_client_hello c_hello;
        auto version_result = get_dtls_version_from_handshake_message( client_hello_bytes );
        if ( !version_result ) {
            return std::unexpected( version_result.error() );
        }
        if ( !version_result.value() ) {
            return std::unexpected( "Unrecognized DTLS Version in ClientHello" );
        }
        c_hello.version = version_result.value().value();
        return c_hello;
	}

} // namespace ntk