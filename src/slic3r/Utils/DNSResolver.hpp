#ifndef __DNS_RESOLVER_HPP__
#define __DNS_RESOLVER_HPP__

#include <string>
#include <vector>
#include <optional>

namespace Slic3r {

/**
 * DNSResolver - Utility class for resolving DNS hostnames to IP addresses
 * 
 * Supports:
 * - Standard DNS hostname resolution (e.g., printer.example.com)
 * - mDNS resolution for .local domains (e.g., orca-printer.local)
 * - IPv4 and IPv6 resolution
 * - Timeout handling for network failures
 */
class DNSResolver {
public:
    /**
     * Resolve a hostname to an IP address
     * 
     * @param hostname The hostname or FQDN to resolve
     * @param timeout_ms Timeout in milliseconds (default 5000ms)
     * @return Optional string containing the resolved IP address, or std::nullopt if resolution fails
     */
    static std::optional<std::string> resolve(const std::string& hostname, int timeout_ms = 5000);

    /**
     * Resolve a hostname to a vector of IP addresses
     * 
     * @param hostname The hostname or FQDN to resolve
     * @param timeout_ms Timeout in milliseconds (default 5000ms)
     * @return Vector of resolved IP addresses (empty if resolution fails)
     */
    static std::vector<std::string> resolve_all(const std::string& hostname, int timeout_ms = 5000);

    /**
     * Check if the given string is already a valid IP address
     * 
     * @param address The string to check
     * @return true if address is a valid IPv4 or IPv6 address, false otherwise
     */
    static bool is_ip_address(const std::string& address);

    /**
     * Check if the given hostname is a mDNS hostname (.local domain)
     * 
     * @param hostname The hostname to check
     * @return true if hostname ends with .local, false otherwise
     */
    static bool is_mdns_hostname(const std::string& hostname);

    /**
     * Resolve a hostname, returning either the IP address or the original hostname if resolution fails
     * This is useful for fallback scenarios
     * 
     * @param hostname_or_ip The hostname or IP address to resolve
     * @param timeout_ms Timeout in milliseconds (default 5000ms)
     * @return Resolved IP address or the original input if resolution fails or input is already an IP
     */
    static std::string resolve_or_fallback(const std::string& hostname_or_ip, int timeout_ms = 5000);
};

} // namespace Slic3r

#endif // __DNS_RESOLVER_HPP__
