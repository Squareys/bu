// thread.hpp — pthread mutex/condvar/thread wrappers and a parallel-for pool.
//
// No std::thread (no STL), and no pthread.h outside thread.cpp: the wrappers
// hold the pthread objects as opaque, correctly sized storage, and thread.cpp
// static_asserts the sizes, so the ~20 TUs that need a lock do not all parse
// pthread.h. Linux x86-64 glibc only, like everything else here.
//
// Two shapes of parallelism exist in backu and this header provides both:
//   * the create pipeline (src/cmd/create.cpp) builds its own stages from
//     Mutex + Cond + Thread, because its stages have different jobs;
//   * restore, check and merge are "do N independent things, then continue",
//     which is `ThreadPool::run(n, fn)` — a persistent pool so that a restore
//     of 100k small files does not pay a thread spawn per batch.
#pragma once

#include "types.hpp"

namespace bk {

struct Mutex {
    alignas(8) u8 storage[40];
    void init();
    void destroy();
    void lock();
    void unlock();
};

struct Cond {
    alignas(8) u8 storage[48];
    void init();
    void destroy();
    void wait(Mutex& m);
    void signal();
    void broadcast();
};

// RAII lock for a scope with early returns.
struct Lock {
    Mutex& m;
    explicit Lock(Mutex& mu) : m(mu) { m.lock(); }
    ~Lock() { m.unlock(); }
    Lock(const Lock&) = delete;
    Lock& operator=(const Lock&) = delete;
};

struct Thread {
    u64 handle = 0;   // pthread_t
    // False if the thread could not be created (resource limit); the caller
    // falls back to doing the work itself.
    [[nodiscard]] bool start(void* (*fn)(void*), void* arg);
    void join();
};

// Online CPUs (sysconf), at least 1. The default for -j.
u32 cpuCount();

// A fixed set of worker threads that runs `fn(ctx, i, worker)` for i in [0, n)
// and returns when all calls finished. The calling thread works too, so a pool
// of `threads` runs `threads` calls at once with threads-1 helpers; worker ids
// are 0..threads-1 (0 is the caller) and index per-worker scratch buffers.
// Items are claimed in increasing order, one at a time, so work is balanced even
// when items differ wildly in cost (a 4 KB file next to a 4 GB one).
struct ThreadPool {
    using Fn = void (*)(void* ctx, u32 index, u32 worker);

    Mutex mu;
    Cond wake;      // helpers wait for a new batch
    Cond finished;  // the caller waits for the batch to drain
    Thread* helpers = nullptr;
    u32 helperCount = 0;
    u32 threads = 1;

    // The current batch, guarded by mu.
    Fn fn = nullptr;
    void* ctx = nullptr;
    u32 n = 0;
    u32 nextItem = 0;
    u32 active = 0;       // helpers currently inside the batch
    u64 generation = 0;   // bumps per batch so a helper never runs one twice
    bool stopping = false;

    void init(u32 threadCount);
    void shutdown();
    void run(u32 count, Fn f, void* c);
};

} // namespace bk
