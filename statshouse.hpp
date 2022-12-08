/* Copyright 2022 V Kontakte LLC
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#pragma once

// Header-only no dependency c++11 compatible implementation of statshouse UDP transport
// tested on linux for now. Implementations for incompatible platforms should use simple #ifdefs around network code
// packing of integers is platform-independent, packing of double may need #ifdef in doubleBits function

// should compile without warnings with -Wno-noexcept-type -g -Wall -Wextra -Werror=return-type

#define STATSHOUSE_TRANSPORT_VERSION "2022-11-24"
#define STATSHOUSE_USAGE_METRICS "statshouse_transport_metrics"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#define STATSHOUSE_UNLIKELY(x) __builtin_expect((x), 0) // could improve packing performance on your platform. Set to (x) to disable

namespace statshouse {

struct stringview { // slightly different name to avoid stupid name clashes
    const char * data = nullptr;
    size_t size = 0;

    stringview() {}
    stringview(const char * str):data(str), size(std::strlen(str)) {}
    stringview(const std::string & str):data(str.data()), size(str.size()) {}
    stringview(const char * data, size_t size):data(data), size(size) {}

    std::string as_string()const { return std::string{data, size}; }
};

class TransportUDP {
public:
	enum {
		DEFAULT_PORT          = 13337,
		SAFE_DATAGRAM_SIZE    = 508,   // https://stackoverflow.com/questions/1098897/what-is-the-largest-safe-udp-packet-size-on-the-internet
		DEFAULT_DATAGRAM_SIZE = 1232,
		MAX_DATAGRAM_SIZE     = 65507, // https://stackoverflow.com/questions/42609561/udp-maximum-packet-size/42610200
		MAX_KEYS              = 16,
	};

	// Key builder. Use by calling transport.metric("").tag("tag1").tag("tag2").write_count(1);
	// Do not store, use immediately, as it contains simple pointer to passed values
	class Metric {
	public:
		Metric & tag(stringview str) {
			if (tags_count < MAX_KEYS*2) {
				if (!kv) {
					tags[tags_count] = transport.tag_names[tags_count/2]; tags_count++;
				}
				tags[tags_count++] = str; // cannot overshoot
			}
			return *this;
		}
		Metric & tag(const char * data, size_t size) {
			if (tags_count < MAX_KEYS*2) {
				if (!kv) {
					tags[tags_count] = transport.tag_names[tags_count/2]; tags_count++;
				}
				tags[tags_count++] = stringview{data, size}; // cannot overshoot
			}
			return *this;
		}

		Metric & env(stringview str) {
			tags[1] = str;
			return *this;
		}
		Metric & env(const char * data, size_t size) {
			tags[1] = stringview{data, size};
			return *this;
		}

		// for write_count. if writing with sample factor, set count to # of events before sampling
		bool write_count(double count, uint32_t tsUnixSec = 0) {
			return transport.write_count_impl(metric, tags, tags_count, count, tsUnixSec);
		}
		// for write_values. set count to # of events before sampling, values to sample of original values
		// if no sampling is performed, pass 0 (interperted as values_count) to count
		bool write_values(const double *values, size_t values_count, double count = 0, uint32_t tsUnixSec = 0) {
			return transport.write_values_impl(metric, tags, tags_count, values, values_count, count, tsUnixSec);
		}
		bool write_value(double value, uint32_t tsUnixSec = 0) {
			return write_values(&value, 1, 0, tsUnixSec);
		}
		// for write_unique, set count to # of events before sampling, values to sample of original hashes
		// for example, if you recorded events [1,1,1,1,2], you could pass them as is or as [1, 2] into 'values' and 5 into 'count'.
		bool write_unique(const uint64_t *values, size_t values_count, double count, uint32_t tsUnixSec = 0) {
			return transport.write_unique_impl(metric, tags, tags_count, values, values_count, count, tsUnixSec);
		}
		bool write_unique(uint64_t value, uint32_t tsUnixSec = 0) {
			return write_unique(&value, 1, 1, tsUnixSec);
		}
	private:
		friend class TransportUDP;
		explicit Metric(TransportUDP & transport, stringview metric, stringview env, bool kv):transport(transport), kv(kv), metric(metric), tags_count(2) {
			tags[0] = stringview{"0"};
			tags[1] = env;
		}
		TransportUDP & transport;
		bool kv = false;
		stringview metric;
		size_t tags_count = 0;
		stringview tags[MAX_KEYS*2]; // Uninitialized, due to performance considerations.
	};

	// no functions of this class throw
	// pass empty ip to use as dummy writer
	// access last error and statistics with move_stats()
	// all functions return false in case error happened, you can ignore them or write last error to log periodically
	// in multithread environment use external lock to access this instance
	TransportUDP():TransportUDP("127.0.0.1", DEFAULT_PORT) {}
	TransportUDP(const std::string &ip, int port) {
		if (!ip.empty() && port != 0) {
			udp_socket = create_socket(ip, port);
		}
		while (tag_names.size() < MAX_KEYS) {
			tag_names.push_back(std::to_string(tag_names.size())); // tag names are "0", "1", etc.
		}
	}
	TransportUDP(const TransportUDP &) = delete;
	TransportUDP &operator=(const TransportUDP &) = delete;
	~TransportUDP() {
		(void)flush(true);  // errors do not matter here
		(void)::close(udp_socket);
	}
	bool is_socket_valid() const { return udp_socket >= 0; }

	void set_default_env(const std::string & env) { default_env = env; } // automatically sent as tag '0'

	// write_* functions treat tags as tag values only, names are assumed to be ['1', '2', ...]
	// write_*_kv functions treat tags as list pairs of (tag name, tag value), like ['platform', 'android', '7', '123', ...]
	// default_env is sent as 'tag0', to overwrite pass env != nullptr to the last parameter of write_* functions
	Metric metric(stringview name) { return Metric(*this, name, default_env, false); }
	Metric metric(const char * name, size_t size) { return Metric(*this, stringview{name, size}, default_env, false); }

	Metric metric_kv(stringview name) { return Metric(*this, name, default_env, true); }
	Metric metric_kv(const char * name, size_t size) { return Metric(*this, stringview{name, size}, default_env, true); }

	// if true, will flush immediately, otherwise if hundreds milliseconds passed since previous flush
	bool flush(bool force) {
		if (!is_socket_valid()) {  // dummy instance or connection error
			return true;
		}
		auto now = now_or_0();
		return force ? flush_impl(now) : maybe_flush(now);
	}

	// settings can be changed at any point in instance lifetime with more or less sane behavior
	void set_max_udp_packet_size(size_t s) { max_payload_size = std::max<size_t>(SAFE_DATAGRAM_SIZE, std::min<size_t>(s, MAX_DATAGRAM_SIZE)); }
	void set_immediate_flush(bool f) { immediate_flush = f; }
	// turn off to avoid calls to chrono::now() inside transport, but you are responsible for calling flush(true) every second
	void set_flush_clock(bool f) { flush_clock = f; }

	struct Stats {
		size_t metrics_sent     = 0;
		size_t metrics_overflow = 0;
		size_t metrics_failed   = 0;
		size_t metrics_odd_kv   = 0;
		size_t metrics_too_big  = 0;
		size_t packets_sent     = 0;
		size_t packets_overflow = 0;
		size_t packets_failed   = 0;
		size_t bytes_sent       = 0;
		std::string last_error;
	};
	const Stats & get_stats()const {
		return stats;
	}
	void cleat_stats() { stats = Stats{}; }

	// writes and clears per metric counters to meta metric STATSHOUSE_USAGE_METRICS
	// status "ok" is written always, error statuses only if corresponding counter != 0
	bool write_usage_metrics(stringview project, stringview cluster) {
		auto result = true;
		result = write_usage_metric_impl(project, cluster, "ok",                     &stats.metrics_sent    , true ) && result;
		result = write_usage_metric_impl(project, cluster, "err_sendto_would_block", &stats.metrics_overflow, false) && result;
		result = write_usage_metric_impl(project, cluster, "err_sendto_other",       &stats.metrics_failed  , false) && result;
		result = write_usage_metric_impl(project, cluster, "err_odd_kv",             &stats.metrics_odd_kv  , false) && result;
		result = write_usage_metric_impl(project, cluster, "err_header_too_big",     &stats.metrics_too_big , false) && result;
		return result;
	}

	static std::string version() { return STATSHOUSE_TRANSPORT_VERSION; }

	static int test_main() {  // call from your main for testing
		TransportUDP statshouse;

		statshouse.set_default_env("production");

		statshouse.metric("toy" ).tag("android").tag("count").write_count(7);
		std::vector<double> values{1, 2, 3};
		statshouse.metric("toy" ).tag("android").tag("values").write_values(values.data(), values.size(), 6);
		std::vector<uint64_t> uniques{1, 2, 3};
		statshouse.metric("toy" ).tag("android").tag("uniques").env("staging").write_unique(uniques.data(), uniques.size(), 5, 1630000000);

		statshouse.metric_kv("toy" ).tag("platform").tag("android").tag("2").tag("count_kv").write_count(1);

		statshouse.write_usage_metrics("test_main", "toy");
		return 0;
	}
	static size_t benchmark_pack_header(size_t total_size) {
		TransportUDP tmp("", 0);
		tmp.benchmark = true; // so there is no dummy optimization
		tmp.set_default_env("production");
		tmp.set_max_udp_packet_size(MAX_DATAGRAM_SIZE);
		tmp.set_flush_clock(false);

		while (tmp.stats.bytes_sent < total_size) {
			tmp.metric("typical_metric_name").tag("tag1_name").tag("tag2_name").tag("tag4_name").tag(
					"tag4_name").write_count(1);
		}
		return tmp.stats.metrics_sent;
	}
private:
	enum {
		MAX_STRING_LEN                  = 128, // defined in statshouse/internal/format/format.go
		FLUSH_INTERVAL_MILLISECOND      = 400, // arbitrary, several # per second flush.
		TL_INT_SIZE                     = 4,
		TL_LONG_SIZE                    = 8,
		TL_DOUBLE_SIZE                  = 8,
		TL_MAX_TINY_STRING_LEN          = 253,
		TL_BIG_STRING_LEN               = 0xffffff,
		TL_BIG_STRING_MARKER            = 0xfe,
		TL_STATSHOUSE_METRICS_BATCH_TAG = 0x56580239,
		TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK = 1 << 0,
		TL_STATSHOUSE_METRIC_TS_FIELDS_MASK      = 1 << 4,
		TL_STATSHOUSE_METRIC_VALUE_FIELDS_MASK   = 1 << 1,
		TL_STATSHOUSE_METRIC_UNIQUE_FIELDS_MASK  = 1 << 2,
		TL_STATSHOUSE_METRIC_NS_FIELDS_MASK      = 1 << 31, // new value semantic, will be removed after all libs are updated
		BATCH_HEADER_LEN = TL_INT_SIZE * 3  // TL tag, fields_mask, # of batches
	};
	size_t batch_size = 0; // we fill packet header before sending
	size_t packet_len = BATCH_HEADER_LEN;

	using clock = std::chrono::steady_clock;
	clock::time_point next_flush_ts;
	std::vector<std::string> tag_names;
	std::string default_env;
	int udp_socket = -1;
	bool benchmark = false;

	size_t max_payload_size = DEFAULT_DATAGRAM_SIZE;
	bool immediate_flush    = false;
	bool flush_clock        = true;

	Stats stats;

	char packet[MAX_DATAGRAM_SIZE]{};  // zeroing is cheap, we are cautious

	clock::time_point now_or_0() const {
		return flush_clock ? clock::now() : clock::time_point{};
	}
	static void put32(char *buf, uint32_t val) {  // optimized to mov by modern compiler
		buf[0] = char(val);
		buf[1] = char(val >> 8);
		buf[2] = char(val >> 16);
		buf[3] = char(val >> 24);
	}
	static void put64(char *buf, uint64_t val) {  // optimized to mov by modern compiler
		buf[0] = char(val);
		buf[1] = char(val >> 8);
		buf[2] = char(val >> 16);
		buf[3] = char(val >> 24);
		buf[4] = char(val >> 32);
		buf[5] = char(val >> 40);
		buf[6] = char(val >> 48);
		buf[7] = char(val >> 56);
	}
	static bool enoughSpace(char * begin, const char * end, size_t req) { return begin + req <= end; }
	static char * pack32(char * begin, const char  * end, size_t v) {
		if (STATSHOUSE_UNLIKELY(!enoughSpace(begin, end, 4))) { return nullptr; }
		put32(begin, uint32_t(v));
		return begin + 4;
	}
	static char * pack64(char * begin, const char * end, uint64_t v) {
		if (STATSHOUSE_UNLIKELY(!enoughSpace(begin, end, 8))) { return nullptr; }
		put64(begin, v);
		return begin + 8;
	}
	static uint64_t doubleBits(double v) {
		uint64_t v64 = 0;
		static_assert(
				sizeof(v) == sizeof v64, "Please make ifdef here with code writing IEEE 64-bit LE double for your (exotic?) platform");
		std::memcpy(&v64, &v, sizeof(v));
		return v64;
	}
	static size_t tlPadSize(size_t n) { return (-n) & 3; }
//	Trim is VERY costly, 2x slowdown even when no actual trim performed. We do not want to punish good guys, and for bad guys
//		we have 'err_header_too_big' usage meta metric
//	static char * pack_string_trim(char * begin, const char * end, const char *str, size_t len) {
//		while (STATSHOUSE_UNLIKELY(len > 0 && std::isspace(static_cast<unsigned char>(*str)))) {
//			++str;
//			--len;
//		}
//		if (STATSHOUSE_UNLIKELY(len > MAX_STRING_LEN)) {
//			len = MAX_STRING_LEN;
//		}
//		return pack_string(begin, end, str, len);
//	}
	static char * pack_string(char * begin, const char * end, const char * str, size_t len) {
		if (STATSHOUSE_UNLIKELY(len > TL_MAX_TINY_STRING_LEN)) {
			if (STATSHOUSE_UNLIKELY(len > TL_BIG_STRING_LEN)) {
				return nullptr;
			}
			auto fullLen = (4 + len + 3) & ~3;
			if (STATSHOUSE_UNLIKELY(!enoughSpace(begin, end, fullLen))) {
				return nullptr;
			}
			put32(begin + fullLen - 4, 0); // padding first
			put32(begin, (len << 8U) | TL_BIG_STRING_MARKER);
			std::memcpy(begin+4, str, len);
			begin += fullLen;
		} else {
			auto fullLen = (1 + len + 3) & ~3;
			if (STATSHOUSE_UNLIKELY(!enoughSpace(begin, end, fullLen))) {
				return nullptr;
			}
			put32(begin + fullLen - 4, 0); // padding first
			*begin = len; // or put32(p, len);
			std::memcpy(begin+1, str, len);
			begin += fullLen;
		}
		return begin;
	}
	char * pack_header(clock::time_point now, size_t min_space, stringview metric, const stringview * tags, size_t tags_count,
					   double counter, uint32_t tsUnixSec, size_t fields_mask) {
		if (STATSHOUSE_UNLIKELY(tags_count % 2 != 0)) {
			stats.last_error.clear(); // prevent allocations
			stats.last_error.append("statshouse::TransportUDP write_*_kv function has odd number of elements in tags array for metric=");
			stats.last_error.append(metric.as_string());
			++stats.metrics_odd_kv;
			return nullptr;
		}
		char * begin = packet + packet_len;
		const char * end = packet + max_payload_size;
		if ((begin = pack_header_impl(begin, end, metric, tags, tags_count, counter, tsUnixSec, fields_mask)) && enoughSpace(begin, end, min_space)) {
			return begin;
		}
		if (packet_len != BATCH_HEADER_LEN) {
			if (!flush_impl(now)) {
				return nullptr;
			}
			begin = packet + packet_len;
			if ((begin = pack_header_impl(begin, end, metric, tags, tags_count, counter, tsUnixSec, fields_mask)) && enoughSpace(begin, end, min_space)) {
				return begin;
			}
		}
		stats.last_error.clear(); // prevent allocations
		stats.last_error.append("statshouse::TransportUDP header too big for metric=");
		stats.last_error.append(metric.as_string());
		++stats.metrics_too_big;
		return nullptr;
	}
	static char * pack_header_impl(char * begin, const char * end, const stringview & metric, const stringview * tags, size_t tags_count,
							double counter, uint32_t tsUnixSec, size_t fields_mask) {
		if (STATSHOUSE_UNLIKELY(tsUnixSec != 0)) {
			fields_mask |= TL_STATSHOUSE_METRIC_TS_FIELDS_MASK;
		}
		fields_mask |= TL_STATSHOUSE_METRIC_NS_FIELDS_MASK;
		if (STATSHOUSE_UNLIKELY(!(begin = pack32(begin, end, fields_mask))))                   { return nullptr; }
		if (STATSHOUSE_UNLIKELY(!(begin = pack_string(begin, end, metric.data, metric.size)))) { return nullptr; }

		auto pair_count = tags_count / 2;
		if (STATSHOUSE_UNLIKELY(!(begin = pack32(begin, end, pair_count))))               { return nullptr; }

		for (size_t i = 0; i != pair_count*2; ++i) { // tags_count should be never odd here, but check is cheap
			if (STATSHOUSE_UNLIKELY(!(begin = pack_string(begin, end, tags[i].data, tags[i].size)))) { return nullptr; }
		}
		if (fields_mask & TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK) {
			if (STATSHOUSE_UNLIKELY(!(begin = pack64(begin, end, doubleBits(counter))))) { return nullptr;}
		}
		if (fields_mask & TL_STATSHOUSE_METRIC_TS_FIELDS_MASK) {
			if (STATSHOUSE_UNLIKELY(!(begin = pack32(begin, end, tsUnixSec)))) { return nullptr; }
		}
		return begin;
	}
	bool write_count_impl(stringview metric, const stringview * tags, size_t tags_count, double count, uint32_t tsUnixSec) {
		if (!is_socket_valid() && !benchmark) {  // dummy instance or connection error
			return true;
		}
		auto now = now_or_0();
		char * begin = pack_header(now, 0, metric, tags, tags_count, count, tsUnixSec, TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK);
		if (!begin) {
			return false;  // did not fit into empty buffer
		}
		packet_len = begin - packet;
		++batch_size;
		return maybe_flush(now);
	}
	bool write_values_impl(stringview metric, const stringview * tags, size_t tags_count,
						   const double *values, size_t values_count, double count, uint32_t tsUnixSec) {
		if (!is_socket_valid() && !benchmark) {  // dummy instance or connection error
			return true;
		}
		size_t fields_mask = TL_STATSHOUSE_METRIC_VALUE_FIELDS_MASK;
		if (count != 0 && count != double(values_count)) {
			fields_mask |= TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK;
		}
		auto now = now_or_0();
		const char * end = packet + max_payload_size;
		while (values_count != 0) {
			char * begin = pack_header(now, TL_INT_SIZE + TL_DOUBLE_SIZE, metric, tags, tags_count, count, tsUnixSec, fields_mask);
			if (!begin) {
				return false;  // did not fit into empty buffer
			}
			auto write_count = std::min<size_t>(values_count, (end - begin - TL_INT_SIZE) / TL_DOUBLE_SIZE); // at least 1
			put32(begin, write_count);
			begin += TL_INT_SIZE;
			for (size_t j = 0; j != write_count; ++j) {
				put64(begin+j*TL_DOUBLE_SIZE, doubleBits(values[j]));
			}
			values += write_count;
			values_count -= write_count;
			packet_len = begin + write_count*TL_DOUBLE_SIZE - packet;
			++batch_size;
		}
		return maybe_flush(now);
	}
	bool write_unique_impl(stringview metric, const stringview * tags, size_t tags_count,
						   const uint64_t *values, size_t values_count, double count, uint32_t tsUnixSec) {
		if (!is_socket_valid() && !benchmark) {  // dummy instance or connection error
			return true;
		}
		size_t fields_mask = TL_STATSHOUSE_METRIC_UNIQUE_FIELDS_MASK;
		if (count != 0 && count != double(values_count)) {
			fields_mask |= TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK;
		}
		auto now = now_or_0();
		const char * end = packet + max_payload_size;
		while (values_count != 0) {
			char * begin = pack_header(now, TL_INT_SIZE + TL_LONG_SIZE, metric, tags, tags_count, count, tsUnixSec, fields_mask);
			if (!begin) {
				return false;  // did not fit into empty buffer
			}
			auto write_count = std::min<size_t>(values_count, (end - begin - TL_INT_SIZE) / TL_LONG_SIZE); // at least 1
			put32(begin, write_count);
			begin += TL_INT_SIZE;
			for (size_t j = 0; j != write_count; ++j) {
				put64(begin+j*TL_LONG_SIZE, values[j]);
			}
			values += write_count;
			values_count -= write_count;
			packet_len = begin + write_count*TL_LONG_SIZE - packet;
			++batch_size;
		}
		return maybe_flush(now);
	}
	bool write_usage_metric_impl(stringview project, stringview cluster, stringview status, size_t * value, bool send_if_0) {
		if (*value || send_if_0) {
			auto count = double(*value);
			*value = 0;
			return metric_kv(STATSHOUSE_USAGE_METRICS)
			    .tag("status").tag(status)
			    .tag("project").tag(project)
			    .tag("cluster").tag(cluster)
			    .tag("protocol").tag("udp")
			    .tag("language").tag("cpp")
			    .tag("version").tag(STATSHOUSE_TRANSPORT_VERSION).write_count(count);
		}
		return true;
	}
	void set_errno_error(int err, const char *msg) {
		stats.last_error.clear();  // prevent allocations
		stats.last_error.append(msg);
		stats.last_error.append(" errno=");
		stats.last_error.append(std::to_string(err));
		stats.last_error.append(", ");
		stats.last_error.append(strerror(err));
	}
	int create_socket(const std::string &ip, int port) {
		if (port < 0 || port > 0xffff) {
			stats.last_error = "statshouse::TransportUDP invalid port=" + std::to_string(port);
			return -1;
		}
		::sockaddr_storage addr = {};
		auto ap                 = reinterpret_cast<sockaddr *>(&addr);
		auto ap6                = reinterpret_cast<sockaddr_in6 *>(ap);
		auto ap4                = reinterpret_cast<sockaddr_in *>(ap);
		int ap_len              = 0;
		if (inet_pton(AF_INET6, ip.c_str(), &ap6->sin6_addr) == 1) {
			addr.ss_family = AF_INET6;
			ap6->sin6_port = htons(uint16_t(port));
			ap_len         = sizeof(*ap6);
			// TODO - check if localhost and increase default packet size
		} else if (inet_pton(AF_INET, ip.c_str(), &ap4->sin_addr) == 1) {
			addr.ss_family = AF_INET;
			ap4->sin_port  = htons(uint16_t(port));
			ap_len         = sizeof(*ap4);
			char high_byte = 0;
			std::memcpy(&high_byte, &ap4->sin_addr, 1); // this is correct, sin_addr in network byte order
			if (high_byte == 0x7F) {
				max_payload_size = MAX_DATAGRAM_SIZE;
			}
		} else {
			stats.last_error = "statshouse::TransportUDP could not parse ip=" + ip;
			return -1;
		}
		auto sock = ::socket(addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
		if (sock < 0) {
			set_errno_error(errno, "statshouse::TransportUDP socket() failed");
			return -1;
		}
		if (::connect(sock, ap, ap_len) < 0) {
			::close(sock);
			set_errno_error(errno, "statshouse::TransportUDP connect() failed");
			return -1;
		}
		return sock;
	}
	bool maybe_flush(clock::time_point now) { return (!immediate_flush && now <= next_flush_ts) || flush_impl(now); }
	bool flush_impl(clock::time_point now) {
		if (batch_size == 0) {
			return true;
		}
		const auto was_batch_size = batch_size;
		put32(packet, TL_STATSHOUSE_METRICS_BATCH_TAG);
		put32(packet + TL_INT_SIZE, 0);  // fields mask
		put32(packet + 2*TL_INT_SIZE, uint32_t(batch_size));  // batch size

		ssize_t result = benchmark ? ssize_t(packet_len) : ::sendto(udp_socket, packet, packet_len, MSG_DONTWAIT, nullptr, 0);

		batch_size = 0;
		packet_len = BATCH_HEADER_LEN;
		next_flush_ts  = now + std::chrono::milliseconds(FLUSH_INTERVAL_MILLISECOND);
		// we will lose usage metrics if packet with usage is discarded, but we are ok with that

		if (result < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				++stats.packets_overflow;
				stats.metrics_overflow += was_batch_size;
				return false;
			}
			set_errno_error(errno, "statshouse::TransportUDP sendto() failed");
			++stats.packets_failed;
			stats.metrics_failed += was_batch_size;
			return false;
		}
		++stats.packets_sent;
		stats.metrics_sent += was_batch_size;
		stats.bytes_sent += size_t(result);
		return true;
	}
};

} // namespace statshouse

#undef STATSHOUSE_UNLIKELY
#undef STATSHOUSE_USAGE_METRIC
#undef STATSHOUSE_TRANSPORT_VERSION
