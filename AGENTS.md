# Introduction

The `eictar` program is an 'encrypted individually-compressed tar' program,
written in Go.  The design and the archive format are specified in doc/.


# Dev Guidelines

-  The program targets the Go version in go.mod (currently 1.27).
-  Build and test with the Makefile, which keeps the module cache, the build
   cache and temporary files inside the project (.gocache/, .gobuildcache/,
   .tmp/):
   -  `make build`: the binary, in .build/eictar
   -  `make check`: fmt, vet, the tests with -race, and the operational tests.
      It must pass before a change is done.
   -  `make fuzz FUZZTIME=5m`, `make bench`, `make stress`
-  To run go directly, use /opt/go/bin/go with the same settings as the
   Makefile: `GOMODCACHE=$PWD/.gocache GOCACHE=$PWD/.gobuildcache
   TMPDIR=$PWD/.tmp`.  Put scratch files in .tmp/.
-  Each bug fix comes with a test that fails without the fix.
-  When go.mod changes, update THIRD_PARTY.md: the table, and the license
   texts copied from each module's LICENSE file.  A test checks it.
-  Any documentation should be kept in the directory doc/: design.md,
   format.md, the man page eictar.1 and Security_Audit.md, with README.md at
   the top.  Documents here should always be considered when performing code
   changes, and updated with them.
-  Write documentation in the style of ASD-STE100 Simplified Technical
   English, as the documents in doc/ are: short sentences, one topic for each
   sentence, simple tenses, the active voice, and one meaning for each word.
-  The .html files are generated from the .md files with pandoc.  Do not edit
   them; I regenerate them.
-  Do not commit or push; I do that.  When a change is done, suggest a
   one-line commit message for it.
-  No changes to outside the directory should be done unless explicitly asked
   to.  You may suggest recommendations to me, but no change unless explicit
   approval is given.  See 'CRITICAL DIRECTORY RESTRICTION'.


# CRITICAL DIRECTORY RESTRICTION

You are ONLY allowed to read, list, grep, edit, or otherwise access files and
directories INSIDE the current project root.

NEVER use absolute paths outside this directory.
NEVER use ".." to go above the project root.
NEVER search in /home, ~/, /usr, parent directories, or any external folders.

The exceptions:

-  The Go toolchain at /opt/go (a symbolic link to some version).  You may
   run the go command from there.
-  tar, zstd, xz and gzip may be run to compare eictar with them in
   benchmarks (bench/compare.sh), on files inside the project.

If a tool call would touch any path outside the project root and these
exceptions, DO NOT make that tool call. Instead, respond with: "I cannot
access paths outside the allowed project directories as per my restrictions."

This rule overrides all other instructions. Violating it is not allowed.


# Tool paths

-  Use relative paths from the project root, with / as the separator, unless
   a tool requires an absolute path.
-  If a path contains a space, put the whole path in double quotes.
-  Before a tool call, check that the path exists in the directory structure.
