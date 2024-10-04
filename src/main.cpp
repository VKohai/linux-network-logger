#include <string.h>     // Provides string manipulation functions such as strncpy and memset.
#include <stdio.h>      // Standard input and output library for functions like printf and scanf.
#include <sys/types.h>  // Defines data types used in system calls, such as size_t and ssize_t.
#include <sys/socket.h> // Provides definitions for socket programming, including socket creation and communication.
#include <sys/ioctl.h>  // Includes the ioctl function for device-specific input/output operations.
#include <netinet/in.h> // Contains constants and structures for internet domain addresses (IPv4).
#include <net/if.h>     // Defines structures and functions for network interface management, including if_nameindex and ifreq.
#include <arpa/inet.h>  // Provides functions for converting IP addresses between binary and text forms (e.g., inet_ntoa).
#include <unistd.h>     // Provides access to the POSIX operating system API, including functions for closing file descriptors (e.g., close).

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip> // To use std::hex
#include <sstream>

/**
 * @brief Gets the names of network interfaces
 *
 * @return std::vector<std::string>: list of interfaces
 */
std::vector<std::string> getInterfaces()
{
    std::vector<std::string> interfaces;

    // Pointers for interface index structure
    struct if_nameindex *if_nidxs, *intf;

    // Get the list of network interfaces
    if_nidxs = if_nameindex();
    if (if_nidxs != NULL)
    {
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++)
        {
            interfaces.push_back(std::string(intf->if_name));
        }

        // Free the allocated memory for interface list
        if_freenameindex(if_nidxs);
    }
    return interfaces;
}

/**
 * @brief Gets IP addresses associated with the given interfaces
 *
 * @param interfaces
 * @return std::vector<std::string>: list of ip
 */
std::vector<std::string> getIP(const std::vector<std::string> &interfaces)
{
    std::vector<std::string> IPs;

    // File descriptor for socket
    int fd;

    // Structure to hold interface request
    struct ifreq ifr;

    // Create a socket for IPv4
    fd = socket(AF_INET, SOCK_DGRAM, 0);

    // Set the address family to IPv4
    ifr.ifr_addr.sa_family = AF_INET;

    for (const auto &interface : interfaces)
    {
        // Copy the interface name into the ifreq structure
        strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

        // Get the IP address using ioctl
        ioctl(fd, SIOCGIFADDR, &ifr);
        auto ip = std::string(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
        IPs.push_back(ip);
    }

    // Close the socket
    close(fd);
    return IPs;
}

/**
 * @brief Get the Mac Addresses associated with the given interfaces
 *
 * @param interfaces
 * @return std::vector<std::string>: list of mac addresses
 */
std::vector<std::string> getMacAddress(const std::vector<std::string> &interfaces)
{
    std::vector<std::string> macAddresses;

    // File descriptor for socket
    int fd;

    // Structure to hold interface request
    struct ifreq ifr;

    // Create a socket for IPv4
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    for (const auto &interface : interfaces)
    {
        const char *iface = interface.c_str();
        unsigned char *mac;

        // Set address family to IPv4
        ifr.ifr_addr.sa_family = AF_INET;

        // Copy interface name into ifreq structure
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

        // Get the MAC address using ioctl
        ioctl(fd, SIOCGIFHWADDR, &ifr);

        // Extract MAC address from ifreq structure
        mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

        // Format the MAC address as a hexadecimal string
        std::ostringstream oss;
        oss << std::hex;

        const size_t macLength = sizeof(mac) / sizeof(mac[0]);
        for (size_t i = 0; i < macLength - 1; ++i)
        {
            oss << std::setw(2) << static_cast<int>(mac[i]) << ":";
        }
        oss << std::setw(2) << static_cast<int>(mac[macLength - 1]);

        auto formattedMacAddress = oss.str();
        macAddresses.push_back(formattedMacAddress);
    }

    // Close the socket
    close(fd);
    return macAddresses;
}

std::string getTimeNow()
{
    time_t now = time(0);
    struct tm tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%d-%m-%Y %H-%M-%S", &tstruct);
    return buf;
}

std::string setRecordFormat(const std::string &interface, const std::string &ip, const std::string &mac)
{
    std::string timestamp = getTimeNow();
    return timestamp + " | " + mac + " | " + ip + " | " + interface + ".log";
}

std::vector<std::string> parseRecordLog(const std::string &logMessage, char delimeter = '|')
{
    std::vector<std::string> logData;

    size_t left = 0, right = 0;
    std::string data;

    // Parse a record
    for (; right < logMessage.length(); ++right)
    {
        if (logMessage[right] == delimeter)
        {
            data = logMessage.substr(left, right - left);
            data.erase(std::remove_if(data.begin(), data.end(), ::isspace), data.end());
            logData.push_back(data);
            left = ++right;
        }
    }

    data = logMessage.substr(left);
    data.erase(0, 1);

    logData.push_back(data);
    return logData;
}

void log(const std::string &path, const std::string &data)
{
    std::ofstream logFile(path, std::ios::app);
    if (logFile.is_open())
    {
        logFile << data << "\n";
        logFile.close();
    }
    else
    {
        std::cerr << "Unable to open log file." << std::endl;
    }
}

bool checkLoggedIP(const std::string &path, const std::string &ip)
{
    auto isIpEqual = [ip](const std::string &filename)
    {
        std::ifstream logFile(filename);
        if (logFile.is_open())
        {
            std::string record;
            while (std::getline(logFile, record))
            {
                auto parsedRecord = parseRecordLog(record);
                if (parsedRecord[2] == ip)
                {
                    return true;
                }
            }
        }
        return false;
    };

    for (const auto &entry : std::filesystem::directory_iterator(path))
    {
        if (isIpEqual(entry.path()))
        {
            return true;
        }
    }
    return false;
}

int main()
{
    auto interfaces = getInterfaces();
    auto ips = getIP(interfaces);
    auto macAddress = getMacAddress(interfaces);

    std::string fileName = "network.log";
    for (size_t i = 0; i < interfaces.size(); ++i)
    {
        auto record = setRecordFormat(interfaces[i], ips[i], macAddress[i]);
        if (checkLoggedIP("./../logs/", ips[i]))
            break;
        log("./../logs/" + fileName, record);
    }
    return 0;
}