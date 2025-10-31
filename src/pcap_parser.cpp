#include <pcap_parser.hpp>

namespace ntk {

	// ======================
    //  Is Pcap Magic Number
    // ======================

	bool is_pcap_magic_number( uint32_t magic_number ) {
		return magic_number == pcap_magic_number || magic_number == swap_endian( pcap_magic_number );
	}

	// ==============
    //  Is Pcap File
    // ==============

	std::expected<bool,std::string> is_pcap_file( std::span<const uint8_t> first_four_bytes ) {
		if ( first_four_bytes.size() != pcap_global_header_len::magic_number ) {
			return std::unexpected( "PCAP Magic Number should be only four bytes" );
		}
		auto magic_number = read_uint32_be( first_four_bytes, pcap_global_header_offset::magic_number );
		return is_pcap_magic_number( magic_number );
	}

	// ====================
    //  Parse Magic Number
    // ====================

	std::expected<gh_parse_result,std::string> parse_magic_number( gh_parse_result p_result ) {
		if ( p_result.buffer.size() < pcap_global_header_len::magic_number ) {
			return std::unexpected( "PCAP Global Header too short for Magic Number" );
		}
		p_result.header.magic_number = read_uint32_be( p_result.buffer, pcap_global_header_offset::magic_number );
		return p_result;
	}

	// =====================
    //  Parse Version Major
    // =====================

    std::expected<gh_parse_result,std::string> parse_version_major( gh_parse_result p_result ) {
    	if ( p_result.buffer.size() < pcap_global_header_offset::version_major + pcap_global_header_len::version_major ) {
    		return std::unexpected( "PCAP Global Header too short for Version Major" );
    	}
    	auto version_major_bytes = read_uint16_be( p_result.buffer, pcap_global_header_offset::version_major );
    	p_result.header.version_major = static_cast<pcap_version_major>( version_major_bytes );
    	return p_result;
    }

    // =====================
    //  Parse Version Minor
    // =====================

    std::expected<gh_parse_result,std::string> parse_version_minor( gh_parse_result p_result ) {
    	if ( p_result.buffer.size() < pcap_global_header_offset::version_minor + pcap_global_header_len::version_minor ) {
    		return std::unexpected( "PCAP Global Header too short for Version Minor" );
    	}
    	auto version_minor_bytes = read_uint16_be( p_result.buffer, pcap_global_header_offset::version_minor );
    	p_result.header.version_minor = static_cast<pcap_version_minor>( version_minor_bytes );
    	return p_result;
    }

    // =================
    //  Parse This Zone
    // =================

    std::expected<gh_parse_result,std::string> parse_this_zone( gh_parse_result p_result ) {
    	if ( p_result.buffer.size() < pcap_global_header_offset::this_zone + pcap_global_header_len::this_zone ) {
    		return std::unexpected( "PCAP Global Header too short for This Zone" );
    	}
    	p_result.header.this_zone = read_uint32_be( p_result.buffer, pcap_global_header_offset::this_zone );
    	return p_result;
    }

    // ================
    //  Parse Sig Figs
    // ================

	std::expected<gh_parse_result,std::string> parse_sig_figs( gh_parse_result p_result ) {
		if ( p_result.buffer.size() < pcap_global_header_offset::sig_figs + pcap_global_header_len::sig_figs ) {
			return std::unexpected( "PCAP Global Header too short for Sig Figs" );
		}
		p_result.header.sig_figs = read_uint32_be( p_result.buffer, pcap_global_header_offset::sig_figs );
		return p_result;
	}

	// ================
    //  Parse Snap Len
    // ================

	std::expected<gh_parse_result,std::string> parse_snap_len( gh_parse_result p_result ) {
		if ( p_result.buffer.size() < pcap_global_header_offset::snap_len + pcap_global_header_len::snap_len ) {
			return std::unexpected( "PCAP Global Header too short for Snap Len" );
		}
		p_result.header.snap_len = read_uint32_be( p_result.buffer, pcap_global_header_offset::snap_len );
		return p_result;
	}

	// ===============
    //  Parse Network
    // ===============

	std::expected<gh_parse_result,std::string> parse_network( gh_parse_result p_result ) {
		if ( p_result.buffer.size() < pcap_global_header_offset::network + pcap_global_header_len::network ) {
			return std::unexpected( "PCAP Global Header too short for Network" );
		}
		auto network_bytes = read_uint32_be( p_result.buffer, pcap_global_header_offset::network );
		p_result.header.network = static_cast<pcap_network>( network_bytes );
		return p_result;
	}

	// =====================
    //  Parse Global Header
    // =====================

    std::expected<gh_parse_result,std::string> parse_global_header( std::span<const uint8_t> buffer ) {
    	return parse_magic_number( { pcap_global_header{}, buffer } )
    		.and_then( parse_version_major )
    		.and_then( parse_version_minor )
    		.and_then( parse_this_zone )
    		.and_then( parse_sig_figs )
    		.and_then( parse_snap_len )
    		.and_then( parse_network );
    }

} // namespace ntk
