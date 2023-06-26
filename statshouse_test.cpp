#include "statshouse.hpp"
#include <cstdio>

namespace statshouse {
namespace test {

template<typename T>
struct traits {};

template<>
struct traits<TransportUDP> {
    static const char* get_name() {
        static char name[] = "TransportUDP";
        return name;
    }
    static TransportUDP::Stats& get_stats(TransportUDP &t) {
        return t.stats;
    }
};

template<>
struct traits<Registry> {
    static const char* get_name() {
        static char name[] = "Registry";
        return name;
    }
    static TransportUDP::Stats& get_stats(Registry &t) {
        return t.transport.stats;
    }
};

template<typename T>
void benchmark_pack_header(size_t benchmark_size = 1024*1024*1024) {
    std::vector<std::string> dynamic_tags;
    dynamic_tags.reserve(1000000);
    for (auto n = dynamic_tags.capacity(); n; n--) {
        dynamic_tags.push_back("tag3" + std::to_string(dynamic_tags.size()));
    }
    T t{"", 0};
    TransportUDP::Stats &stats{traits<T>::get_stats(t)};
    t.set_default_env("production");
    t.set_max_udp_packet_size(TransportUDP::MAX_DATAGRAM_SIZE);
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t next_tag_value{0}; stats.bytes_sent < benchmark_size;) {
        t.metric("typical_metric_name")
            .tag("tag1_name")
            .tag("tag2_name")
            .tag(dynamic_tags[next_tag_value])
            .tag("tag4_name")
            .write_count(1);
        if (++next_tag_value >= dynamic_tags.size()) {
            next_tag_value = 0;
        }
    }
    // print results
    auto mksec = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start).count();
    auto batches = stats.metrics_sent;
    std::printf("%s benchmark %d MB, %ld batches, %d mksec, %d MB/sec\n", traits<T>::get_name(), int(benchmark_size/1024/1024), batches, int(mksec), int(benchmark_size/mksec));
}

template<typename T>
void benchmark_write_value() {
    T t;
    auto begin = std::chrono::steady_clock::now();
    for (auto i=0; i < 1000000; i++) {
        t.metric("malpinskiy_investigation")
            .tag("a976207097145020")
            .tag("a058992634786402")
            .tag("a361387731010001")
            .tag("a057341188320915")
            .tag("a913170170684600")
            .tag("a268289295741267")
            .tag("a704131134786936")
            .write_value(1);
    }
    t.flush(true);
    auto end = std::chrono::steady_clock::now();
    std::printf("%s elapsed %ld milliseconds\n", traits<T>::get_name(), std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());
}

template<>
void benchmark_write_value<Registry>() {
    Registry t;
    auto begin = std::chrono::steady_clock::now();
    auto m = t.metric("malpinskiy_investigation")
        .tag("a976207097145020")
        .tag("a058992634786402")
        .tag("a361387731010001")
        .tag("a057341188320915")
        .tag("a913170170684600")
        .tag("a268289295741267")
        .tag("a704131134786936");
    for (auto i=0; i < 1000000; i++) {
        m.write_value(1);
    }
    t.flush(true);
    auto end = std::chrono::steady_clock::now();
    std::printf("Registry! elapsed %ld milliseconds\n", std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());
}

template<typename T>
void benchmark_worst_case() {
    std::vector<std::string> dynamic_tags;
    dynamic_tags.reserve(100000);
    for (auto n = dynamic_tags.capacity(); n; n--) {
        dynamic_tags.push_back(std::to_string(dynamic_tags.size()));
    }
    T t;
    auto begin = std::chrono::steady_clock::now();
    for (auto i = 0; i < 100000; i++) {
        t.metric("malpinskiy_investigation")
            .tag("9",  dynamic_tags[(i+0)%dynamic_tags.size()])
            .tag("10", dynamic_tags[(i+1)%dynamic_tags.size()])
            .tag("11", dynamic_tags[(i+2)%dynamic_tags.size()])
            .tag("12", dynamic_tags[(i+3)%dynamic_tags.size()])
            .tag("13", dynamic_tags[(i+4)%dynamic_tags.size()])
            .tag("14", dynamic_tags[(i+5)%dynamic_tags.size()])
            .tag("15", dynamic_tags[(i+6)%dynamic_tags.size()])
            .write_value(1);
    }
    t.flush(true);
    auto end = std::chrono::steady_clock::now();
    std::printf("%s elapsed %ld milliseconds\n", traits<T>::get_name(), std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());
}

template<>
void benchmark_worst_case<Registry>() {
    std::vector<std::string> dynamic_tags;
    dynamic_tags.reserve(100000);
    for (auto n = dynamic_tags.capacity(); n; n--) {
        dynamic_tags.push_back(std::to_string(dynamic_tags.size()));
    }
    Registry t;
    auto begin = std::chrono::steady_clock::now();
    for (auto i = 0; i < 100000; i++) {
        t.metric("malpinskiy_investigation")
            .tag("9",  dynamic_tags[(i+0)%dynamic_tags.size()])
            .tag("10", dynamic_tags[(i+1)%dynamic_tags.size()])
            .tag("11", dynamic_tags[(i+2)%dynamic_tags.size()])
            .tag("12", dynamic_tags[(i+3)%dynamic_tags.size()])
            .tag("13", dynamic_tags[(i+4)%dynamic_tags.size()])
            .tag("14", dynamic_tags[(i+5)%dynamic_tags.size()])
            .tag("15", dynamic_tags[(i+6)%dynamic_tags.size()])
            .write_value(1);
    }
    t.flush(true);
    auto end = std::chrono::steady_clock::now();
    std::printf("Registry! elapsed %ld milliseconds\n", std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());
}

template<typename T>
void benchmark_best_case() {
    std::vector<std::string> dynamic_tags;
    dynamic_tags.reserve(7);
    for (auto n = dynamic_tags.capacity(); n; n--) {
        dynamic_tags.push_back(std::to_string(dynamic_tags.size()));
    }
    T t;
    auto begin = std::chrono::steady_clock::now();
    for (auto i = 0; i < 10000000; i++) {
        t.metric("malpinskiy_investigation")
            .tag("9",  dynamic_tags[0])
            .tag("10", dynamic_tags[1])
            .tag("11", dynamic_tags[2])
            .tag("12", dynamic_tags[3])
            .tag("13", dynamic_tags[4])
            .tag("14", dynamic_tags[5])
            .tag("15", dynamic_tags[6])
            .write_value(1);
    }
    t.flush(true);
    auto end = std::chrono::steady_clock::now();
    std::printf("%s elapsed %ld milliseconds\n", traits<T>::get_name(), std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());
}

template<>
void benchmark_best_case<Registry>() {
    std::vector<std::string> dynamic_tags;
    dynamic_tags.reserve(7);
    for (auto n = dynamic_tags.capacity(); n; n--) {
        dynamic_tags.push_back(std::to_string(dynamic_tags.size()));
    }
    Registry t;
    auto m = t.metric("malpinskiy_investigation")
        .tag("9",  dynamic_tags[0])
        .tag("10", dynamic_tags[1])
        .tag("11", dynamic_tags[2])
        .tag("12", dynamic_tags[3])
        .tag("13", dynamic_tags[4])
        .tag("14", dynamic_tags[5])
        .tag("15", dynamic_tags[6])
        .ref();
    for (auto i = 0; i < 1000000; i++) {
        m.write_value(1);
    }
    auto begin = std::chrono::steady_clock::now();
    for (auto i = 0; i < 1000000; i++) {
        m.write_value(1);
    }
    t.flush(true);
    auto end = std::chrono::steady_clock::now();
    std::printf("Registry! elapsed %ld milliseconds\n", std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());
}

void send_regular() {
    Registry t;
    t.disable_incremental_flush();
    auto m = t.metric("malpinskiy_investigation")
            .tag("a976207097145020")
            .tag("a058992634786402")
            .tag("a361387731010001")
            .tag("a057341188320915")
            .tag("a913170170684600")
            .tag("a268289295741267")
            .tag("a704131134786936")
            .value_ref();;
    m.set_value(1);
    for (;;) {
        std::this_thread::sleep_until(std::chrono::time_point_cast<std::chrono::seconds>(
            std::chrono::system_clock::now()) + std::chrono::seconds{1});
        t.flush();
    }
}

void registry_logging() {
    Registry::options opt{};
    opt.logger = puts;
    Registry t{opt};
    t.set_metrics_logging_enabled(true);
    auto m = t.metric("malpinskiy_investigation")
        .tag(std::string(256, 'q'), "9")
        .tag("10", std::string(256, '0'))
        .tag("11", "1")
        .tag("12", "2")
        .tag("13", std::string(512, '0'))
        .tag("14", "")
        .tag("15", "");
    m.write_count(1);
    m.write_value(2);
    m.write_unique(3);
}

} // namespace test
} // namespace statshouse

int main() {
    // statshouse::test::benchmark_pack_header<statshouse::TransportUDP>();
    // statshouse::test::benchmark_pack_header<statshouse::Registry>();
    // statshouse::test::benchmark_write_value<statshouse::TransportUDP>();
    // statshouse::test::benchmark_write_value<statshouse::Registry>();
    statshouse::test::benchmark_worst_case<statshouse::Registry>();
    // statshouse::test::benchmark_worst_case<statshouse::TransportUDP>();
    // statshouse::test::benchmark_best_case<statshouse::TransportUDP>();
    // statshouse::test::benchmark_best_case<statshouse::Registry>();
    // statshouse::test::send_regular();
    // statshouse::test::registry_logging();
}
