#include <gtest/gtest.h>

#include "ip_filter.h"

TEST(ip_filter_test, test_fill)
{
	const std::vector<std::string> input = {
		"1.1.1.1\t900\t991",
		"1.2.1.1\t902\t993",
		"1.10.1.1\t904\t995"};
	std::vector<ip_filter::address> expected = {
		0x010a0101,
		0x01020101,
		0x01010101};

	auto ipv4 = ip_filter::fill<decltype(expected)>(input);

	EXPECT_EQ(ipv4, expected);
}

TEST(ip_filter_test, test_filter_by_mask)
{
	std::vector<ip_filter::address> pool;
	const decltype(pool) ipv4 = {
		0x0a090801,
		0x02030405,
		0x01020304};
	decltype(ipv4) expected = {
		0x02030405};

	auto filter = ip_filter::filter_by_mask(0x30000, 0xff0000);
	for (const auto& a : ipv4) {
		if (filter(a))
			pool.push_back(a);
	}

	EXPECT_EQ(pool, expected);
}

TEST(ip_filter_test, test_filter_by_any_byte)
{
	std::vector<ip_filter::address> pool;
	const decltype(pool) ipv4 = {
		0x0a090801,
		0x02030405,
		0x01020304};
	decltype(ipv4) expected = {
		0x0a090801,
		0x01020304};

	auto filter = ip_filter::filter_by_any_byte(1);
	for (const auto& a : ipv4) {
		if (filter(a))
			pool.push_back(a);
	}

	EXPECT_EQ(pool, expected);
}
