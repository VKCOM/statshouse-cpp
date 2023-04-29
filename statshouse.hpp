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

#define STATSHOUSE_TRANSPORT_VERSION "2023-04-29"
#define STATSHOUSE_USAGE_METRICS "statshouse_transport_metrics"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

// Use #ifdefs to include headers for various platforms here
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#define STATSHOUSE_UNLIKELY(x) __builtin_expect((x), 0) // could improve packing performance on your platform. Set to (x) to disable

namespace statshouse {

struct stringview { // slightly different name to avoid stupid name clashes
    const char * data = nullptr;
    size_t size = 0;

    stringview() = default;
    stringview(const char * str):data(str), size(std::strlen(str)) {}
    stringview(const std::string & str):data(str.data()), size(str.size()) {}
    stringview(const char * data, size_t size):data(data), size(size) {}

    std::string as_string()const { return std::string{data, size}; }
};

class TransportUDPBase {
public:
	enum {
		DEFAULT_PORT          = 13337,
		SAFE_DATAGRAM_SIZE    = 508,   // https://stackoverflow.com/questions/1098897/what-is-the-largest-safe-udp-packet-size-on-the-internet
		DEFAULT_DATAGRAM_SIZE = 1232,
		MAX_DATAGRAM_SIZE     = 65507, // https://stackoverflow.com/questions/42609561/udp-maximum-packet-size/42610200
		MAX_KEYS              = 16,
		MAX_FULL_KEY_SIZE     = 1024, // roughly metric plus all tags
	};

	// Metric name builder. Use by calling transport.metric("metric").tag("tag1").tag("tag2").write_count(1);
	// Contains reference to transport and must outlive it
	class Metric {
	public:
		// Assigns next tag value, starting from 1
		Metric & tag(stringview str) {
			return tag_id(next_tag++, str);
		}
		// Sets env (tag 0)
		Metric & env(stringview str) {
			env_set = true;
			return tag_id(0, str);
		}
		// Assigns arbitrary tag value
		Metric & tag(stringview key, stringview str) {
			auto begin = buffer + buffer_pos;
			auto end = buffer + MAX_FULL_KEY_SIZE;
			if (STATSHOUSE_UNLIKELY(!(begin = pack_string(begin, end, key.data, key.size)))) { did_not_fit = true; return *this; }
			if (STATSHOUSE_UNLIKELY(!(begin = pack_string(begin, end, str.data, str.size)))) { did_not_fit = true; return *this; }
			buffer_pos = begin - buffer;
			tags_count++;
			return *this;
		}

		// for write_count. if writing with sample factor, set count to # of events before sampling
		bool write_count(double count, uint32_t tsUnixSec = 0) {
			return transport.write_count_impl(*this, count, tsUnixSec);
		}
		// for write_values. set count to # of events before sampling, values to sample of original values
		// if no sampling is performed, pass 0 (interpreted as values_count) to count
		bool write_values(const double *values, size_t values_count, double count = 0, uint32_t tsUnixSec = 0) {
			return transport.write_values_impl(*this, values, values_count, count, tsUnixSec);
		}
		bool write_value(double value, uint32_t tsUnixSec = 0) {
			return write_values(&value, 1, 0, tsUnixSec);
		}
		// for write_unique, set count to # of events before sampling, values to sample of original hashes
		// for example, if you recorded events [1,1,1,1,2], you could pass them as is or as [1, 2] into 'values' and 5 into 'count'.
		bool write_unique(const uint64_t *values, size_t values_count, double count, uint32_t tsUnixSec = 0) {
			return transport.write_unique_impl(*this, values, values_count, count, tsUnixSec);
		}
		bool write_unique(uint64_t value, uint32_t tsUnixSec = 0) {
			return write_unique(&value, 1, 1, tsUnixSec);
		}
	private:
		stringview metric_name() const { return {buffer + 1, metric_name_len}; }  // see pack_string
		size_t tags_count_pos()const { return (1 + metric_name_len + 3) & ~3; } // see pack_string

		Metric & tag_id(size_t i, stringview str) {
			auto begin = buffer + buffer_pos;
			auto end = buffer + MAX_FULL_KEY_SIZE;
			if (STATSHOUSE_UNLIKELY(i >= MAX_KEYS)) { did_not_fit = true; return *this; }
			if (STATSHOUSE_UNLIKELY(!(begin = pack32(begin, end, transport.tag_names_tl[i]))))    { did_not_fit = true; return *this; }
			if (STATSHOUSE_UNLIKELY(!(begin = pack_string(begin, end, str.data, str.size)))) { did_not_fit = true; return *this; }
			buffer_pos = begin - buffer;
			tags_count++;
			return *this;
		}

		friend class TransportUDPBase;
		explicit Metric(TransportUDPBase & transport, stringview m):transport(transport), metric_name_len(m.size) {
			static_assert(MAX_FULL_KEY_SIZE > 4 + TL_MAX_TINY_STRING_LEN + 4, "not enough space to not overflow in constructor");
			auto begin = buffer + buffer_pos;
			auto end = buffer + MAX_FULL_KEY_SIZE;
			begin = pack_string(begin, end, m.data, m.size);
			begin = pack32(begin, end, 0); // place for tags_count. Never updated in buffer and always stays 0,
			buffer_pos = begin - buffer;
		}
		TransportUDPBase & transport;
		bool env_set = false; // so current default_env will be added in pack_header
		bool did_not_fit = false;
		size_t next_tag = 1;
		size_t tags_count = 0;
		size_t metric_name_len = 0;
		size_t buffer_pos = 0; // not ptr because we want safe copy
		char buffer[MAX_FULL_KEY_SIZE]; // Uninitialized, due to performance considerations.
	};

	explicit TransportUDPBase() {
		while (tag_names_tl.size() < MAX_KEYS) {
			tag_names_tl.push_back(pack_key_name(tag_names_tl.size()));  // tag names are "0", "1", etc.
		}
	}
	virtual ~TransportUDPBase() = default;

	void set_default_env(const std::string & env) { // automatically sent as tag '0'
		default_env = env; //.substr(0, TL_MAX_TINY_STRING_LEN);

		char buffer[TL_MAX_TINY_STRING_LEN + 8]{}; // key name, env, padding
		auto begin = buffer;
		auto end = buffer + sizeof(buffer);

		auto short_env = shorten(env);
		begin = pack32(begin, end, pack_key_name(0));
		begin = pack_string(begin, end, short_env.data, short_env.size);

		default_env_tl_pair.assign(buffer, begin - buffer);
	}

	Metric metric(stringview name) { return Metric(*this, shorten(name)); }

	// if true, will flush immediately, otherwise if hundreds milliseconds passed since previous flush
	bool flush(bool force) {
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

protected:
	Stats stats; // allow implementations to update stats directly for simplicity
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
		BATCH_HEADER_LEN = TL_INT_SIZE * 3  // TL tag, fields_mask, # of batches
	};
	size_t batch_size = 0; // we fill packet header before sending
	size_t packet_len = BATCH_HEADER_LEN; // reserve space for metric batch header

	using clock = std::chrono::steady_clock;
	clock::time_point next_flush_ts;
	std::vector<uint32_t> tag_names_tl;
	std::string default_env; // not used
	std::string default_env_tl_pair; // "0", default_env in TL format to optimized writing

	size_t max_payload_size = DEFAULT_DATAGRAM_SIZE;
	bool immediate_flush    = false;
	bool flush_clock        = true;

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
	static bool enoughSpace(const char * begin, const char * end, size_t req) { return begin + req <= end; }
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
	static stringview shorten(stringview x) { return stringview{x.data, std::min<size_t>(x.size, TL_MAX_TINY_STRING_LEN)}; }
	static size_t tlPadSize(size_t n) { return (-n) & 3; }
//	Trim is VERY costly, 2x slowdown even when no actual trim performed. We do not want to punish good guys, and for bad guys
//		we have 'err_header_too_big' usage meta metric
//	static char * pack_string_trim(char * begin, const char * end, const char *str, size_t len) {
//		while (STATSHOUSE_UNLIKELY(len > 0 && std::isspace(static_cast<unsigned char>(*str)))) {
//			++str;
//			--len;
//		}
//		return pack_string(begin, end, str, len);
//	}
	static uint32_t pack_key_name(size_t i) {
		static_assert(MAX_KEYS <= 100, "key names up to 100 supported");
		if (i < 10) {
			return 1 | (uint32_t('0' + i) << 8);
		}
		return 2 | (uint32_t('0' + i/10) << 8) | (uint32_t('0' + i%10) << 16);
	}
	static char * pack_string(char * begin, const char * end, const char * str, size_t len) {
//		We call shorten() on all outside strings, so can remove code path for long strings here
//		if (STATSHOUSE_UNLIKELY(len > TL_MAX_TINY_STRING_LEN)) {
//			if (STATSHOUSE_UNLIKELY(len > TL_BIG_STRING_LEN)) {
//				return nullptr;
//			}
//			auto fullLen = (4 + len + 3) & ~3;
//			if (STATSHOUSE_UNLIKELY(!enoughSpace(begin, end, fullLen))) {
//				return nullptr;
//			}
//			put32(begin + fullLen - 4, 0); // padding first
//			put32(begin, (len << 8U) | TL_BIG_STRING_MARKER);
//			std::memcpy(begin+4, str, len);
//			begin += fullLen;
//		} else {
		auto fullLen = (1 + len + 3) & ~3;
		if (STATSHOUSE_UNLIKELY(!enoughSpace(begin, end, fullLen))) {
			return nullptr;
		}
		put32(begin + fullLen - 4, 0); // padding first
		*begin = len; // or put32(p, len);
		std::memcpy(begin+1, str, len);
		begin += fullLen;
//		}
		return begin;
	}
	char * pack_header(clock::time_point now, size_t min_space, const Metric & metric,
						double counter, uint32_t tsUnixSec, size_t fields_mask) {
		if (STATSHOUSE_UNLIKELY(metric.did_not_fit)) {
			stats.last_error.clear(); // prevent allocations
			stats.last_error.append("statshouse::TransportUDP header too big for metric=");
			stats.last_error.append(metric.metric_name().as_string());
			++stats.metrics_too_big;
			return nullptr;
		}
		char * begin = packet + packet_len;
		const char * end = packet + max_payload_size;
		if ((begin = pack_header_impl(begin, end, metric, counter, tsUnixSec, fields_mask)) && enoughSpace(begin, end, min_space)) {
			return begin;
		}
		if (packet_len != BATCH_HEADER_LEN) {
			if (!flush_impl(now)) {
				return nullptr;
			}
			begin = packet + packet_len;
			if ((begin = pack_header_impl(begin, end, metric, counter, tsUnixSec, fields_mask)) && enoughSpace(begin, end, min_space)) {
				return begin;
			}
		}
		stats.last_error.clear(); // prevent allocations
		stats.last_error.append("statshouse::TransportUDP header too big for metric=");
		stats.last_error.append(metric.metric_name().as_string());
		++stats.metrics_too_big;
		return nullptr;
	}
	char * pack_header_impl(char * begin, const char * end, const Metric & metric,
									double counter, uint32_t tsUnixSec, size_t fields_mask) {
		if (tsUnixSec != 0) {
			fields_mask |= TL_STATSHOUSE_METRIC_TS_FIELDS_MASK;
		}
		if (STATSHOUSE_UNLIKELY(!(begin = pack32(begin, end, fields_mask))))   { return nullptr; }
		if (STATSHOUSE_UNLIKELY(!enoughSpace(begin, end, metric.buffer_pos))) { return nullptr; }
		std::memcpy(begin, metric.buffer, metric.buffer_pos);
		const auto add_env = !metric.env_set && !default_env.empty();
		put32(begin + metric.tags_count_pos(), add_env ? metric.tags_count + 1 : metric.tags_count);
		begin += metric.buffer_pos;
		if (add_env) {
			if (STATSHOUSE_UNLIKELY(!enoughSpace(begin, end, default_env_tl_pair.size()))) { return nullptr; }
			std::memcpy(begin, default_env_tl_pair.data(), default_env_tl_pair.size());
			begin += default_env_tl_pair.size();
		}
		if (fields_mask & TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK) {
			if (STATSHOUSE_UNLIKELY(!(begin = pack64(begin, end, doubleBits(counter))))) { return nullptr;}
		}
		if (fields_mask & TL_STATSHOUSE_METRIC_TS_FIELDS_MASK) {
			if (STATSHOUSE_UNLIKELY(!(begin = pack32(begin, end, tsUnixSec)))) { return nullptr; }
		}
		return begin;
	}
	bool write_count_impl(const Metric & metric, double count, uint32_t tsUnixSec) {
		auto now = now_or_0();
		char * begin = pack_header(now, 0, metric, count, tsUnixSec, TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK);
		if (!begin) {
			return false;  // did not fit into empty buffer
		}
		packet_len = begin - packet;
		++batch_size;
		return maybe_flush(now);
	}
	bool write_values_impl(const Metric & metric, const double *values, size_t values_count, double count, uint32_t tsUnixSec) {
		size_t fields_mask = TL_STATSHOUSE_METRIC_VALUE_FIELDS_MASK;
		if (count != 0 && count != double(values_count)) {
			fields_mask |= TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK;
		}
		auto now = now_or_0();
		const char * end = packet + max_payload_size;
		while (values_count != 0) {
			char * begin = pack_header(now, TL_INT_SIZE + TL_DOUBLE_SIZE, metric, count, tsUnixSec, fields_mask);
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
	bool write_unique_impl(const Metric & metric, const uint64_t *values, size_t values_count, double count, uint32_t tsUnixSec) {
		size_t fields_mask = TL_STATSHOUSE_METRIC_UNIQUE_FIELDS_MASK;
		if (count != 0 && count != double(values_count)) {
			fields_mask |= TL_STATSHOUSE_METRIC_COUNTER_FIELDS_MASK;
		}
		auto now = now_or_0();
		const char * end = packet + max_payload_size;
		while (values_count != 0) {
			char * begin = pack_header(now, TL_INT_SIZE + TL_LONG_SIZE, metric, count, tsUnixSec, fields_mask);
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
			return metric(STATSHOUSE_USAGE_METRICS)
			    .tag("status", status)
			    .tag("project" ,project)
			    .tag("cluster", cluster)
			    .tag("protocol", "udp")
			    .tag("language", "cpp")
			    .tag("version", STATSHOUSE_TRANSPORT_VERSION).write_count(count);
		}
		return true;
	}
	bool maybe_flush(clock::time_point now) { return (!immediate_flush && now <= next_flush_ts) || flush_impl(now); }
	virtual bool on_flush_packet(const char * data, size_t size, size_t batch_size) = 0;
	bool flush_impl(clock::time_point now) {
		if (batch_size == 0) {
			return true;
		}
		put32(packet, TL_STATSHOUSE_METRICS_BATCH_TAG);
		put32(packet + TL_INT_SIZE, 0);  // fields mask
		put32(packet + 2*TL_INT_SIZE, uint32_t(batch_size));  // batch size

		auto result = on_flush_packet(packet, packet_len, batch_size);
		if (result) {
			++stats.packets_sent;
			stats.metrics_sent += batch_size;
			stats.bytes_sent += packet_len;
		} else {
			++stats.packets_failed;
			stats.metrics_failed += batch_size;
		}

		batch_size = 0;
		packet_len = BATCH_HEADER_LEN;
		next_flush_ts  = now + std::chrono::milliseconds(FLUSH_INTERVAL_MILLISECOND);

		// we will lose usage metrics if packet with usage is discarded, but we are ok with that
		return result;
	}
};

// Use #ifdefs to customize for various platforms here
class TransportUDP : public TransportUDPBase {
public:
	// no functions of this class throw
	// pass empty ip to use as dummy writer
	// access last error and statistics with move_stats()
	// all functions return false in case error happened, you can ignore them or write last error to log periodically
	// in multithread environment use external lock to access this instance
	TransportUDP():TransportUDP("127.0.0.1", DEFAULT_PORT) {}
	TransportUDP(const std::string &ip, int port): dummy_instance(ip.empty() || port == 0) {
		if (!dummy_instance) {
			udp_socket = create_socket(ip, port);
		}
	}
	TransportUDP(const TransportUDP &) = delete;
	TransportUDP &operator=(const TransportUDP &) = delete;
	~TransportUDP() override {
		(void)flush(true);  // errors do not matter here
		(void)::close(udp_socket);
	}
	bool is_socket_valid() const { return udp_socket >= 0; }

	static int test_main() {  // call from your main for testing
		TransportUDP statshouse;

		statshouse.set_default_env("production");

		statshouse.metric("toy" ).tag("android").tag("count").write_count(7);
		std::vector<double> values{1, 2, 3};
		statshouse.metric("toy" ).tag("android").tag("values").write_values(values.data(), values.size(), 6);
		std::vector<uint64_t> uniques{1, 2, 3};
		statshouse.metric("toy" ).tag("android").tag("uniques").env("staging").write_unique(uniques.data(), uniques.size(), 5, 1630000000);

		statshouse.metric("toy" ).tag("platform", "android").tag("2", "count_kv").write_count(1);

		statshouse.write_usage_metrics("test_main", "toy");
		return 0;
	}
	static size_t benchmark_pack_header(size_t total_size) {
		TransportUDP tmp("", 0);
		tmp.set_default_env("production");
		tmp.set_max_udp_packet_size(MAX_DATAGRAM_SIZE);
		tmp.set_flush_clock(false);

		std::vector<std::string> dynamic_tags;
		while(dynamic_tags.size() < 1000000) {
			dynamic_tags.push_back("tag3" + std::to_string(dynamic_tags.size()));
		}
		size_t next_tag_value = 0;

		while (tmp.stats.bytes_sent < total_size) {
			// when all tags are static, this compiles into setting metric memory to fixed bytes corresponding to TL representation of strings
			tmp.metric("typical_metric_name").tag("tag1_name").tag("tag2_name").tag(dynamic_tags[next_tag_value]).tag(
					"tag4_name").write_count(1);
			if (++next_tag_value >= dynamic_tags.size())
				next_tag_value = 0;
		}

		return tmp.stats.metrics_sent;
	}
private:
	int udp_socket = -1;
	bool dummy_instance = false; // better than separate class, because can be set depending on config

	bool on_flush_packet(const char * data, size_t size, size_t batch_size) override {
		if (dummy_instance) {
			return true;
		}
		if (!is_socket_valid()) { // we reported connection error after start
			return false;
		}

		ssize_t result = ::sendto(udp_socket, data, size, MSG_DONTWAIT, nullptr, 0);

		if (result >= 0) {
			return true;
		}
		auto err = errno;
		if (err == EAGAIN) { //  || err == EWOULDBLOCK
			++stats.packets_overflow;
			stats.metrics_overflow += batch_size;
			return false;
		}
		set_errno_error(err, "statshouse::TransportUDP sendto() failed");
		return false;
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
				set_max_udp_packet_size(MAX_DATAGRAM_SIZE);
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
	void set_errno_error(int err, const char *msg) {
		stats.last_error.clear();  // prevent allocations
		stats.last_error.append(msg);
		stats.last_error.append(" errno=");
		stats.last_error.append(std::to_string(err));
		stats.last_error.append(", ");
		stats.last_error.append(strerror(err));
	}
};

} // namespace statshouse

#undef STATSHOUSE_UNLIKELY
#undef STATSHOUSE_USAGE_METRIC
#undef STATSHOUSE_TRANSPORT_VERSION
