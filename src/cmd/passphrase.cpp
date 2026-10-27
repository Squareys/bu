// passphrase.cpp — see passphrase.hpp.
//
// Echo is turned off with termios on /dev/tty for the length of one read.
// A signal that arrives meanwhile (Ctrl-C at the prompt) would otherwise
// leave the user's terminal silent after bu dies, so the fatal ones are
// caught for that window only: the handler puts the saved settings back and
// re-raises with the default action. SIGTSTP (Ctrl-Z) is blocked for the same
// window instead: stopped with echo off, the shell the user returns to would
// be silent. Blocked, it stays pending and stops bu right after the settings
// are restored; on `fg` bu is past the prompt. Catching it and re-raising
// SIGSTOP, then turning echo off again on SIGCONT, was the alternative: more
// handler code for the same outcome a moment earlier.
//
// mlock is not used. The master key is needed for the whole run and is
// expanded into per-segment key schedules that the worker threads share;
// locking the passphrase buffer alone would protect the least valuable
// secret, and locking all of it would need RLIMIT_MEMLOCK beyond the
// default. Swap exposure is the swap's to solve (encrypted swap). Every
// buffer that held a secret is wiped instead.

#include "cmd/passphrase.hpp"
#include "io/io.hpp"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

namespace bk {

namespace {

int gTtyFd = -1;
struct termios gTtySaved;
const int kSignals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT};

void restoreTtyAndDie(int sig) {
    if (gTtyFd >= 0) tcsetattr(gTtyFd, TCSAFLUSH, &gTtySaved);
    signal(sig, SIG_DFL);
    raise(sig);
}

// Bytes up to the first newline (an optional CR before it is dropped too)
// or end of input. Over-long input is refused, not truncated: a truncated
// passphrase would silently become a different, weaker one.
bool takeLine(const char* data, usize n, Passphrase& out, String& err) {
    usize len = 0;
    while (len < n && data[len] != '\n') ++len;
    if (len && data[len - 1] == '\r') --len;
    if (len > kPassphraseMax) return errSet(err, "passphrase longer than 1024 bytes");
    memCopy(out.buf, data, len);
    out.len = u32(len);
    if (!len) return errSet(err, "empty passphrase");
    return true;
}

bool readFd(int fd, Passphrase& out, String& err) {
    // One byte at a time: whatever follows the first line stays unread for
    // its owner (cheap at <= 1 KiB, and a pipe gives no other way to stop).
    char buf[kPassphraseMax + 2];
    usize n = 0;
    bool ok = true;
    for (;;) {
        char c;
        const ssize_t r = ::read(fd, &c, 1);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) { ok = errSet(err, "reading the passphrase: ", strerror(errno)); break; }
        if (r == 0 || c == '\n') break;
        if (n == sizeof buf) { ok = errSet(err, "passphrase longer than 1024 bytes"); break; }
        buf[n++] = c;
    }
    if (ok) ok = takeLine(buf, n, out, err);
    secureZero(buf, sizeof buf);
    return ok;
}

bool readTty(int tty, StringView prompt, Passphrase& out, String& err) {
    struct termios t;
    if (tcgetattr(tty, &t) != 0) return errSet(err, "cannot turn off echo on the terminal: ", strerror(errno));
    struct sigaction old[sizeof kSignals / sizeof kSignals[0]];
    struct sigaction sa;
    memSet(&sa, 0, sizeof sa);
    sa.sa_handler = restoreTtyAndDie;
    gTtySaved = t;
    gTtyFd = tty;
    sigset_t stop, oldMask;
    sigemptyset(&stop);
    sigaddset(&stop, SIGTSTP);
    sigprocmask(SIG_BLOCK, &stop, &oldMask);
    for (u32 i = 0; i < sizeof kSignals / sizeof kSignals[0]; ++i) sigaction(kSignals[i], &sa, &old[i]);
    t.c_lflag &= ~tcflag_t(ECHO);
    t.c_lflag |= ECHONL;        // the Enter still moves the cursor down
    bool ok = tcsetattr(tty, TCSAFLUSH, &t) == 0;
    if (!ok) errSet(err, "cannot turn off echo on the terminal: ", strerror(errno));
    if (ok && !writeAll(tty, prompt.ptr, prompt.count)) ok = errSet(err, "writing to the terminal: ", strerror(errno));
    if (ok) ok = readFd(tty, out, err);
    tcsetattr(tty, TCSAFLUSH, &gTtySaved);
    gTtyFd = -1;
    for (u32 i = 0; i < sizeof kSignals / sizeof kSignals[0]; ++i) sigaction(kSignals[i], &old[i], nullptr);
    sigprocmask(SIG_SETMASK, &oldMask, nullptr);    // a pending Ctrl-Z stops us here, echo back on
    return ok;
}

} // namespace

void warnIfShared(const char* what, const char* path) {
    // Like ssh with a private key. A warning, not a refusal: a file on a
    // read-only medium may have modes the user cannot change.
    struct stat st;
    if (stat(path, &st) == 0 && (st.st_mode & 077))
        fprintf(stderr, "bu: warning: %s %s is accessible by other users (chmod 600 it)\n", what, path);
}

void warnKdfSkipped(const char* path, const KeyFile& f, u32 kdfFailed) {
    for (u32 i = 0; i < kKeySlots; ++i) {
        if (!(kdfFailed & (1u << i))) continue;
        KeySlotInfo s;
        keyFileSlot(f, i, s);
        fprintf(stderr, "bu: warning: %s: slot %u skipped: Argon2id could not get the %u MiB it needs\n", path, i,
                s.kdf.memKiB >> 10);
    }
}

bool passphraseGet(const char* file, int fd, StringView prompt, StringView hint, bool confirm, Passphrase& out,
                   String& err) {
    if (file) {
        Array<u8> data;
        if (!readWholeFile(file, 1u << 20, data, err)) return false;
        String why;
        const bool ok = takeLine(reinterpret_cast<const char*>(data.ptr), data.count, out, why);
        secureZero(data.ptr, data.count);
        if (!ok) return errSet(err, file, ": ", why.view());
        // A passphrase file is the key file's second factor in plaintext.
        warnIfShared("passphrase file", file);
        return true;
    }
    if (fd >= 0) {
        String why;
        if (!readFd(fd, out, why)) return errSet(err, "--passphrase-fd: ", why.view());
        return true;
    }
    const int tty = ::open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (tty < 0)
        return errSet(err, "no terminal to ask for the passphrase on; give it with ", hint);
    bool ok = readTty(tty, prompt, out, err);
    if (ok && confirm) {
        Passphrase again;
        ok = readTty(tty, "Repeat the new passphrase: "_s, again, err);
        if (ok && !(again.view() == out.view())) ok = errSet(err, "the passphrases did not match");
    }
    ::close(tty);
    return ok;
}

bool unlockKeyForCommand(const Args& a, MasterKey& out) {
    String err;
    if (!cryptoCpuCheck(err)) { report(err); return false; }
    KeyFile f;
    if (!keyFileRead(a.key, f, err)) { report(err); return false; }
    // The file holds no plaintext key, but a copy lets others guess
    // passphrases offline.
    warnIfShared("key file", a.key);
    String prompt("Passphrase for "_s);
    prompt.append(StringView(a.key));
    prompt.append(": "_s);
    Passphrase pass;
    if (!passphraseGet(a.passFile, a.passFd, prompt, "--passphrase-file PATH or --passphrase-fd N"_s, false, pass,
                       err)) {
        report(err);
        return false;
    }
    Key k;
    u32 slot = 0, kdfFailed = 0;
    const bool ok = keyFileUnlock(f, pass.view(), k, slot, kdfFailed, err);
    warnKdfSkipped(a.key, f, kdfFailed);
    if (ok) masterKeyInit(k, out);
    secureZero(k.b, kKeyBytes);
    if (!ok) {
        String msg;
        errSet(msg, a.key, ": ", err.view());
        report(msg);
    }
    return ok;
}

int keyForChain(const Args& a, const char* cmd, bool plain, StringView what, MasterKey& out) {
    String msg(what);
    if (plain) {
        if (a.key) {
            msg.append(" is not encrypted (made with --no-key); drop --key"_s);
            return usage(cmd, msg.view());
        }
        masterKeyPlain(out);
        return kExitOk;
    }
    if (a.noKey) {
        msg.append(" is encrypted; give --key KEYFILE, not --no-key"_s);
        return usage(cmd, msg.view());
    }
    if (!a.key) {
        msg.append(" is encrypted: --key KEYFILE is required"_s);
        return usage(cmd, msg.view());
    }
    return unlockKeyForCommand(a, out) ? kExitOk : kExitRuntime;
}

} // namespace bk
