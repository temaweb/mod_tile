#ifndef measure_h
#define measure_h

#include <chrono>

using namespace std::chrono;

void measure(const std::string & message, std::function<void()> measure_block)
{
    const auto & begin = high_resolution_clock::now();
    
    measure_block();

    const auto & end = high_resolution_clock::now();
    const auto & elapsed = duration_cast<milliseconds>(end - begin);
    
    syslog(LOG_DEBUG, "%s, block executed in %.3lf seconds", message.c_str(), elapsed.count() / 1000.0);
}

#endif /* measure_h */
