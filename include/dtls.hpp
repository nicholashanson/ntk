#ifndef DTLS_HPP
#define DTLS_HPP

#include <tls.hpp>

namespace ntk {

	enum class dtls_version : uint16_t {
		dtls_1_2 = 0xfefd
	};

	static const std::unordered_map<dtls_version,std::string> dtls_version_names = {
        { dtls_version::dtls_1_2, "Version 1.2" },
    };

    namespace look_up {

        constexpr std::array<dtls_version,1/* entries in enum dtls_version */> dtls_versions = {
            dtls_version::dtls_1_2
        };

    } // namespace look_up

    inline auto get_dtls_version = make_lookup( look_up::dtls_versions );

	struct dtls_client_hello {
		dtls_version version;
	};

	std::expected<dtls_client_hello,std::string> parse_dtls_client_hello( std::span<const uint8_t> client_hello_bytes );
 
} // namespace ntk

#endif // DTLS_HPP