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

void print(const statshouse::TransportUDP::Stats &s) {
    std::printf("metrics_sent      %zu\n", s.metrics_sent);
    std::printf("metrics_overflow  %zu\n", s.metrics_overflow);
    std::printf("metrics_failed    %zu\n", s.metrics_failed);
    std::printf("metrics_odd_kv    %zu\n", s.metrics_odd_kv);
    std::printf("metrics_too_big   %zu\n", s.metrics_too_big);
    std::printf("packets_sent      %zu\n", s.packets_sent);
    std::printf("packets_overflow  %zu\n", s.packets_overflow);
    std::printf("packets_failed    %zu\n", s.packets_failed);
    std::printf("bytes_sent        %zu\n", s.bytes_sent);
}

void print(const statshouse::Registry::Stats &s) {
    print(static_cast<const statshouse::TransportUDP::Stats &>(s));
    std::printf("queue_size        %zu\n", s.queue_size);
    std::printf("freelist_size     %zu\n", s.freelist_size);
    std::printf("bucket_count      %zu\n", s.bucket_count);
}

template<typename T>
void benchmark_best_case() {
}

template<>
void benchmark_best_case<statshouse::TransportUDP>() {
    statshouse::TransportUDP t{"", 0}; // don't open socket
    auto begin = std::chrono::steady_clock::now();
    for (auto i = 0; i < 1000000000; i++) {
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
    std::printf("TransportUDP elapsed %ld milliseconds\n", std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());
    print(t.get_stats());
}

template<>
void benchmark_best_case<Registry>() {
    Registry::options opt{};
    opt.port = 0; // don't open socket
    Registry t{opt};
    auto m = t.metric("malpinskiy_investigation")
        .tag("a976207097145020")
        .tag("a058992634786402")
        .tag("a361387731010001")
        .tag("a057341188320915")
        .tag("a913170170684600")
        .tag("a268289295741267")
        .tag("a704131134786936")
        .ref();
    auto begin = std::chrono::steady_clock::now();
    for (auto i = 0; i < 1000000000; i++) {
        m.write_value(1);
    }
    t.flush(true);
    auto end = std::chrono::steady_clock::now();
    std::printf("Registry elapsed %ld milliseconds\n", std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());
    print(t.get_stats());
}

void benchmark_multithread_registry() {
    Registry::options opt{};
    Registry t{opt};
    auto begin = std::chrono::steady_clock::now();
    std::vector<std::thread> w;
    for (auto i = 0; i < 1000; i++) {
        auto delay = 200;
        w.emplace_back([&t, delay](){
            for (auto i = 0; i < 1000; i++) {
                auto m = t.metric("malpinskiy_investigation")
                    .tag("a976207097145020")
                    .tag("a058992634786402")
                    .tag("a361387731010001")
                    .tag("a057341188320915")
                    .tag("a913170170684600")
                    .tag("a268289295741267")
                    .tag("a704131134786936")
                    .ref();
                std::this_thread::sleep_until(std::chrono::time_point_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now()) + std::chrono::milliseconds{delay});
                m.write_value(1);
                // m.write_count(1);
            }
        });
    }
    for (auto &t: w) {
        t.join();
    }
    t.flush(true);
    auto end = std::chrono::steady_clock::now();
    std::printf("MT Registry elapsed %ld milliseconds\n", std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());
    print(t.get_stats());
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
    // statshouse::test::benchmark_multithread_registry();
}
