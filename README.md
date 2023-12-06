# statshouse-cpp
StatsHouse client library for C++

```cpp
#include "statshouse.hpp"
#include <cstdio>

using namespace statshouse;

Registry r{{
    logger: puts // debug output
}};

int main() {
    // Enable debug output
    r.set_metrics_logging_enabled(true);

    // Write "counter" metric
    auto c = r.metric("demo_counter_metric")
        .tag("1", "foo")
        .tag("2", "bar")
        .event_count_metric_ref();
    c.write_count(100); // there were 100 events (e.g. requests)

    // Write "value" metric
    auto v = r.metric("demo_value_metric")
        .tag("1", "foo")
        .tag("2", "bar")
        .event_metric_ref();
    for (auto i = 0; i < 100; ++i) { // there were 100 events
        v.write_value(i+1);           // each with value "i+1" (e.g. request duration)
    }

    // Write "waterlevel" metric
    auto w = r.metric("demo_waterlevel_metric")
        .tag("1", "foo")
        .tag("2", "bar")
        .waterlevel_metric_ref();
    w.set(1024*1024); // current (e.g. memory usage) value is 1MB
    w.add(1024*1024); // value goes up by 1MB (current reported value is 2MB)

    // Write "uniques" metric
    auto u = r.metric("demo_uniques_metric")
        .tag("1", "foo")
        .tag("2", "bar")
        .unique_metric_ref();
    for (auto i=0; i < 10; ++i) {
        for (auto j=0; j < 10; ++j) { // there were 10 unique values among 100 events
            u.write_unique(i+1);      // (e.g. user ID)
        }
    }

    // Keep writing some to use "incremental flush"
    for (;;) {
        std::this_thread::sleep_for(std::chrono::seconds{1});
        w.add(1024); // increase waterlevel by 1KB
    }
}
```
