// commands.hpp — one entry point per subcommand; main.cpp dispatches.
// Each takes the full argv and the index of its first own argument, parses
// with argsParse and returns the process exit status (0 ok, 1 runtime, 2 usage,
// 3 create finished with warnings).
#pragma once

namespace bk {

int cmdCreate(int argc, char** argv, int first);
int cmdRestore(int argc, char** argv, int first);
int cmdMerge(int argc, char** argv, int first);
int cmdCheck(int argc, char** argv, int first);
int cmdIndex(int argc, char** argv, int first);
int cmdList(int argc, char** argv, int first);
int cmdKey(int argc, char** argv, int first);

} // namespace bk
