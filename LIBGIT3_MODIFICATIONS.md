# LibGit3 Modifications Summary

This document outlines the key modifications made to transform libgit2 into libgit3, a library that works with Git3 repositories using SHA3-256 hashing and proof-of-work.

## Key Changes Made

### 1. Project Renaming
- **CMakeLists.txt**: Changed project name from `libgit2` to `libgit3`
- **Binary name**: Changed from `git2` to `git3`

### 2. SHA3-256 Integration
- **Added SHA3 implementation**: Copied SHA3 code from git3 to `src/util/hash/sha3/`
- **Created SHA3 wrapper**: Added `src/util/hash/sha3.h` and `sha3.c`
- **Updated hash system**: Modified `src/util/hash.h` to include SHA3 support
- **Extended hash.c**: Added SHA3 handling to all hash operations

### 3. Repository Format
- **Changed directory**: Modified `DOT_GIT` from `.git` to `.git3` in `src/libgit2/repository.h`
- **This makes libgit3 look for `.git3` directories instead of `.git`**

### 4. Build System
- **CMakeLists.txt**: Added SHA3 sources to the build
- **Updated util/CMakeLists.txt**: Included SHA3 source files

## Additional Work Required

### 1. Object ID System
To fully support SHA3-256, the following needs to be done:
- Add `GIT_OID_SHA3` type to the OID system
- Update all object creation to use SHA3-256 by default
- Modify object reading to handle SHA3-256 hashes

### 2. Proof-of-Work Integration
Add proof-of-work support:
- Create pow.h/pow.c similar to git3
- Integrate PoW validation into commit creation
- Add cumulative work tracking

### 3. Repository Initialization
- Update repository init to set format version 3
- Set `extensions.objectformat = sha3`
- Configure default hash algorithm to SHA3-256

### 4. Testing
- Update test suite to use `.git3` directories
- Add tests for SHA3 hashing
- Add tests for proof-of-work validation

## Building LibGit3

```bash
mkdir build
cd build
cmake ..
make
sudo make install
```

## Usage Example

Once fully implemented, libgit3 will work with Git3 repositories:

```c
#include <git3.h>

int main() {
    git_repository *repo;
    
    // Initialize a Git3 repository
    git_repository_init(&repo, "/path/to/repo", 0);
    
    // Repository will use .git3 directory and SHA3-256 hashing
    
    git_repository_free(repo);
    return 0;
}
```

## Compatibility Note

LibGit3 is designed to work exclusively with Git3 repositories that use:
- SHA3-256 hashing instead of SHA1/SHA256
- `.git3` directories instead of `.git`
- Proof-of-work for all commits
- Repository format version 3

This makes it incompatible with standard Git repositories but provides enhanced security through blockchain-like properties.