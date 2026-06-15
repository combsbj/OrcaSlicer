int MachineObject::connect(bool use_openssl)
{
    if (get_dev_ip().empty()) return -1;
    std::string username = "bblp";
    std::string password = get_access_code();

    // Import DNSResolver for hostname support
    #include "slic3r/Utils/DNSResolver.hpp"
    
    std::string connection_address = get_dev_ip();
    
    // Check if the address is a hostname that needs resolution
    if (!DNSResolver::is_ip_address(connection_address)) {
        BOOST_LOG_TRIVIAL(info) << "MachineObject::connect: Resolving hostname '" << connection_address << "'";
        
        // Attempt to resolve the hostname to an IP address
        auto resolved_ip = DNSResolver::resolve(connection_address);
        
        if (resolved_ip) {
            connection_address = resolved_ip.value();
            BOOST_LOG_TRIVIAL(info) << "MachineObject::connect: Resolved hostname to IP: " << connection_address;
        } else {
            BOOST_LOG_TRIVIAL(warning) << "MachineObject::connect: Failed to resolve hostname '" 
                                       << get_dev_ip() << "'. Attempting connection anyway.";
            // Continue with the original hostname - some systems may support direct hostname connection
        }
    }

    if (m_agent) {
        try {
            return m_agent->connect_printer(get_dev_id(), connection_address, username, password, use_openssl);
        } catch (...) {
            ;
        }
    }
    return -1;
}
