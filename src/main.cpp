#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#include <vector>
 
#include "ip_filter.h"

int main()
{
	try {
		std::vector<std::string> strings;
		std::string line;

		while (std::getline(std::cin, line))
			strings.push_back(line);

		// Reverse lexicographically sort
		auto ipv4 = ip_filter::fill<std::vector<ip_filter::address>>(strings);

		// Output
		ip_filter::print(ipv4, [](auto /*addr*/) { return true; });

		// Filter by first byte and output
		ip_filter::print(ipv4, ip_filter::filter_by_mask(0x1000000, 0xff000000));

		// Filter by first and second bytes and output
		ip_filter::print(ipv4, ip_filter::filter_by_mask(0x2e460000, 0xffff0000));

		// Filter by any byte and output
		ip_filter::print(ipv4, ip_filter::filter_by_any_byte(46));

	} catch(const std::exception& e) {
		std::cerr << e.what() << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
