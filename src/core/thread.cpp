// thread.cpp — the one TU that includes pthread.h; see thread.hpp.

#include "thread.hpp"
#include "memory.hpp"

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h> // sysconf

namespace bk {

static_assert(sizeof(pthread_mutex_t) <= sizeof(Mutex::storage), "Mutex storage too small");
static_assert(sizeof(pthread_cond_t) <= sizeof(Cond::storage), "Cond storage too small");
static_assert(sizeof(pthread_t) == sizeof(u64), "pthread_t is an integer on glibc x86-64");

static pthread_mutex_t* pm(Mutex* m) { return reinterpret_cast<pthread_mutex_t*>(m->storage); }
static pthread_cond_t* pc(Cond* c) { return reinterpret_cast<pthread_cond_t*>(c->storage); }

// A failing lock or wait on a correctly initialised object is a program bug
// (EINVAL/EDEADLK); there is no way to continue with a broken lock, so abort.
void Mutex::init()    { if (pthread_mutex_init(pm(this), nullptr)) abort(); }
void Mutex::destroy() { pthread_mutex_destroy(pm(this)); }
void Mutex::lock()    { if (pthread_mutex_lock(pm(this))) abort(); }
void Mutex::unlock()  { if (pthread_mutex_unlock(pm(this))) abort(); }

void Cond::init()           { if (pthread_cond_init(pc(this), nullptr)) abort(); }
void Cond::destroy()        { pthread_cond_destroy(pc(this)); }
void Cond::wait(Mutex& m)   { if (pthread_cond_wait(pc(this), pm(&m))) abort(); }
void Cond::signal()         { pthread_cond_signal(pc(this)); }
void Cond::broadcast()      { pthread_cond_broadcast(pc(this)); }

bool Thread::start(void* (*fn)(void*), void* arg) {
    pthread_t t;
    if (pthread_create(&t, nullptr, fn, arg) != 0) return false;
    handle = u64(t);
    return true;
}

void Thread::join() { pthread_join(pthread_t(handle), nullptr); }

u32 cpuCount() {
    const long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n < 1 ? 1u : (n > 1024 ? 1024u : u32(n));
}

namespace {

struct HelperArg { ThreadPool* pool; u32 worker; };

// Claim and run items of the current batch until none are left. Called with
// the lock held; drops it around each call.
void drain(ThreadPool& p, u32 worker) {
    while (p.nextItem < p.n) {
        const u32 i = p.nextItem++;
        const ThreadPool::Fn f = p.fn;
        void* const c = p.ctx;
        p.mu.unlock();
        f(c, i, worker);
        p.mu.lock();
    }
}

void* helperMain(void* argp) {
    HelperArg* arg = static_cast<HelperArg*>(argp);
    ThreadPool& p = *arg->pool;
    const u32 worker = arg->worker;
    defaultAllocator().free(arg);
    u64 seen = 0;
    p.mu.lock();
    for (;;) {
        while (!p.stopping && p.generation == seen) p.wake.wait(p.mu);
        if (p.stopping) break;
        seen = p.generation;
        ++p.active;
        drain(p, worker);
        if (--p.active == 0) p.finished.broadcast();
    }
    p.mu.unlock();
    return nullptr;
}

} // namespace

void ThreadPool::init(u32 threadCount) {
    mu.init(); wake.init(); finished.init();
    threads = threadCount ? threadCount : 1;
    helperCount = 0;
    if (threads > 1) {
        helpers = static_cast<Thread*>(defaultAllocator().alloc(sizeof(Thread) * (threads - 1)));
        for (u32 i = 1; i < threads; ++i) {
            HelperArg* a = static_cast<HelperArg*>(defaultAllocator().alloc(sizeof(HelperArg)));
            a->pool = this; a->worker = i;
            if (!helpers[helperCount].start(helperMain, a)) { defaultAllocator().free(a); break; }
            ++helperCount;
        }
    }
    threads = helperCount + 1;   // what we actually got
}

void ThreadPool::shutdown() {
    mu.lock(); stopping = true; wake.broadcast(); mu.unlock();
    for (u32 i = 0; i < helperCount; ++i) helpers[i].join();
    defaultAllocator().free(helpers);
    helpers = nullptr; helperCount = 0;
    finished.destroy(); wake.destroy(); mu.destroy();
}

void ThreadPool::run(u32 count, Fn f, void* c) {
    if (count == 0) return;
    if (helperCount == 0 || count == 1) {           // no point waking anybody
        for (u32 i = 0; i < count; ++i) f(c, i, 0);
        return;
    }
    mu.lock();
    fn = f; ctx = c; n = count; nextItem = 0;
    ++generation;
    wake.broadcast();
    drain(*this, 0);
    // Every item is claimed; wait for helpers still inside one. A helper that
    // has not woken yet will find nextItem == n and leave without touching ctx.
    while (active > 0) finished.wait(mu);
    fn = nullptr; ctx = nullptr; n = 0;
    mu.unlock();
}

} // namespace bk
