#include "DNSResolver.hpp"
#include <boost/log/trivial.hpp>
#include <boost/asio.hpp>
#include <regex>

#ifdef _WIN32
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
#endif

namespace Slic3r {

bool DNSResolver::is_ip_address(const std::string& address) {
    // Check IPv4 format (simple validation)
    std::regex ipv4_pattern(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    if (std::regex_match(address, ipv4_pattern)) {
        // Additional validation: each octet should be 0-255
        int octets[4];
        if (sscanf(address.c_str(), "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
            for (int i = 0; i < 4; i++) {
                if (octets[i] < 0 || octets[i] > 255) return false;
            }
            return true;
        }
    }

    // Check IPv6 format (simple validation)
    std::regex ipv6_pattern(R"(^([\da-fA-F]{0,4}:){2,7}[\da-fA-F]{0,4}$)");
    if (std::regex_match(address, ipv6_pattern)) {
        return true;
    }

    return false;
}

bool DNSResolver::is_mdns_hostname(const std::string& hostname) {
    return hostname.length() > 6 && 
           hostname.substr(hostname.length() - 6) == ".local";
}

std::optional<std::string> DNSResolver::resolve(const std::string& hostname, int timeout_ms) {
    try {
        // If already an IP address, return it directly
        if (is_ip_address(hostname)) {
            BOOST_LOG_TRIVIAL(debug) << "DNSResolver: Input is already an IP address: " << hostname;
            return hostname;
        }

        BOOST_LOG_TRIVIAL(info) << "DNSResolver: Attempting to resolve hostname: " << hostname;

        // Use getaddrinfo for cross-platform DNS resolution
        struct addrinfo hints, *result, *p;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;     // Allow both IPv4 and IPv6
        hints.ai_socktype = SOCK_STREAM; // TCP socket

        int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
        
        if (status != 0) {
            BOOST_LOG_TRIVIAL(warning) << "DNSResolver: Failed to resolve hostname '" << hostname 
                                       << "': " << gai_strerror(status);
            return std::nullopt;
        }

        // Get the first resolved address
        std::string resolved_ip;
        char ip_str[INET6_ADDRSTRLEN];

        for (p = result; p != nullptr; p = p->ai_next) {
            void* addr = nullptr;
            
            if (p->ai_family == AF_INET) {
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                addr = &(ipv4->sin_addr);
            } else if (p->ai_family == AF_INET6) {
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
                addr = &(ipv6->sin6_addr);
            }

            if (addr && inet_ntop(p->ai_family, addr, ip_str, sizeof(ip_str))) {
                resolved_ip = ip_str;
                BOOST_LOG_TRIVIAL(info) << "DNSResolver: Resolved '" << hostname << "' to '" << resolved_ip << "'";
                break;
            }
        }

        freeaddrinfo(result);

        if (!resolved_ip.empty()) {
            return resolved_ip;
        }

        BOOST_LOG_TRIVIAL(warning) << "DNSResolver: Could not resolve hostname: " << hostname;
        return std::nullopt;

    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << "DNSResolver: Exception during resolution: " << e.what();
        return std::nullopt;
    } catch (...) {
        BOOST_LOG_TRIVIAL(error) << "DNSResolver: Unknown exception during hostname resolution";
        return std::nullopt;
    }
}

std::vector<std::string> DNSResolver::resolve_all(const std::string& hostname, int timeout_ms) {
    std::vector<std::string> results;

    try {
        // If already an IP address, return it in a vector
        if (is_ip_address(hostname)) {
            results.push_back(hostname);
            return results;
        }

        BOOST_LOG_TRIVIAL(info) << "DNSResolver: Attempting to resolve all IPs for hostname: " << hostname;

        struct addrinfo hints, *result, *p;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
        
        if (status != 0) {
            BOOST_LOG_TRIVIAL(warning) << "DNSResolver: Failed to resolve hostname '" << hostname 
                                       << "': " << gai_strerror(status);
            return results;
        }

        char ip_str[INET6_ADDRSTRLEN];
        for (p = result; p != nullptr; p = p->ai_next) {
            void* addr = nullptr;
            
            if (p->ai_family == AF_INET) {
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                addr = &(ipv4->sin_addr);
            } else if (p->ai_family == AF_INET6) {
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
                addr = &(ipv6->sin6_addr);
            }

            if (addr && inet_ntop(p->ai_family, addr, ip_str, sizeof(ip_str))) {
                results.push_back(ip_str);
                BOOST_LOG_TRIVIAL(debug) << "DNSResolver: Found IP for '" << hostname << "': " << ip_str;
            }
        }

        freeaddrinfo(result);

        if (!results.empty()) {
            BOOST_LOG_TRIVIAL(info) << "DNSResolver: Resolved '" << hostname << "' to " 
                                    << results.size() << " IP address(es)";
        }

    } catch (const std::exception& e) {
        BOOST_LOG_TRIVIAL(error) << "DNSResolver: Exception during multi-resolution: " << e.what();
    } catch (...) {
        BOOST_LOG_TRIVIAL(error) << "DNSResolver: Unknown exception during multi-resolution";
    }

    return results;
}

std::string DNSResolver::resolve_or_fallback(const std::string& hostname_or_ip, int timeout_ms) {
    // If already an IP address, return as-is
    if (is_ip_address(hostname_or_ip)) {
        BOOST_LOG_TRIVIAL(debug) << "DNSResolver: Input is already an IP: " << hostname_or_ip;
        return hostname_or_ip;
    }

    // Try to resolve the hostname
    auto resolved = resolve(hostname_or_ip, timeout_ms);
    if (resolved) {
        return resolved.value();
    }

    // Fallback: return the original input
    BOOST_LOG_TRIVIAL(warning) << "DNSResolver: Failed to resolve '" << hostname_or_ip 
                               << "', falling back to original input";
    return hostname_or_ip;
}

} // namespace Slic3r
