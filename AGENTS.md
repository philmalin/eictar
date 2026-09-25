# Introduction

The `eictar` program is an 'encrypted individually-compressed tar' program.
   

# Dev Guidelines

-  The script targets Go 1.x.
-  Any documentation should be kept in the directory doc/.  Documents here
   should always be considered when performing code changes.
-  No changes to outside the directory should be done unless explicitly asked
   to.  You may suggest recommendations to me, but no change unless explicit
   approval is given.  See 'CRITICAL DIRECTORY RESTRICTION'.


# CRITICAL DIRECTORY RESTRICTION

You are ONLY allowed to read, list, grep, edit, or otherwise access files and
directories INSIDE the current project root.

NEVER use absolute paths outside this directory. 
NEVER use ".." to go up exception to the session-management path.
NEVER search in /home, ~/, /usr, parent directories, or any external folders.

The exception to this is the location of the Go compiler, which is /opt/go (a
symbolic link to some version).  You may execute the go compiler from here.

If a tool call would touch any path outside the project root and the go
compiler location, DO NOT make that tool call. Instead, respond with: "I cannot
access paths outside the allowed project directories as per my restrictions."

This rule overrides all other instructions. Violating it is not allowed.


# CRITICAL TOOL PATH RULES — MUST BE FOLLOWED ON EVERY TOOL CALL

When calling grep, glob, list_directory, find, or any file-search tool:
- Use ONLY filesystem paths with forward-slash separators (/).
- NEVER use periods (.) as path separators. Convert any Java package-style
  name: com.example.foo → com/example/foo
- Use relative paths from the project root only (never absolute unless the tool
  explicitly requires it).
- If a path contains any space, surround the entire path string with double quotes.
- Before emitting the tool call, verify the path matches actual directory structure on disk.

Example correct calls:
- grep: path="src/main/java/com/info/medix/utils"
- glob: pattern="**/*.java", path="src/main/java"
- Incorrect (never do this): com.info.medix.utils or "com.info.medix.utils" or
  src/main/java/com.info.medix.utils

Violating these rules is forbidden. If you cannot construct a valid path, respond with text: "Invalid path format – I must use filesystem / separators only."
