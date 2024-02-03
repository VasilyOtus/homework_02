#ifndef _IP_FILTER_H
#define _IP_FILTER_H

#include <cstdint>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <functional>

namespace ip_filter {

using address = uint32_t;

template<typename Container>
auto fill(const std::vector<std::string>& input)
{
	Container ipv4;

	const std::string byte("(\\d|[1-9]\\d|1\\d\\d|2[0-4]\\d|25[0-5])");
	const std::regex re("^" + byte + "\\." + byte + "\\." + byte + "\\." + byte + "\t\\w+\t\\w+");

	std::smatch m;

	for (const auto& line : input) {
		if (!std::regex_search(line, m, re))
			continue;

		const auto addr = (std::stoi(m[1].str()) << 24) +
				  (std::stoi(m[2].str()) << 16) +
				  (std::stoi(m[3].str()) << 8) +
				  std::stoi(m[4].str());

		ipv4.push_back(addr);
	}

	std::sort(ipv4.begin(), ipv4.end(), std::greater());

	return ipv4;
}

struct filter_by_mask {
	explicit filter_by_mask(address addr, address mask)
		: addr_(addr),
		  mask_(mask)
	{
	}

	bool operator()(const address a) const
	{
		return (a & mask_) == (addr_ & mask_);
	}

private:
	address addr_, mask_;
};

struct filter_by_any_byte {
	explicit filter_by_any_byte(uint8_t byte)
		: byte_(byte)
	{
	}

	bool operator()(const address a) const
	{
		for (size_t i = 0; i < sizeof(a); ++i) {
			if (((a >> (8 * i)) & 0xff) == byte_)
				return true;
		}
		return false;
	}

private:
	uint8_t byte_;
};

template<typename Container, typename Filter>
void print(const Container& c, Filter f)
{
	std::for_each(
		c.begin(),
		c.end(), 
		[&f](auto addr) {
			if (!f(addr))
				return;
			std::cout <<
				std::to_string(addr >> 24) << "." <<
				std::to_string((addr >> 16) & 0xff) << "." <<
				std::to_string((addr >> 8) & 0xff) << "." <<
				std::to_string(addr & 0xff) <<
				std::endl;
		});
};

};

#endif // _IP_FILTER_H
