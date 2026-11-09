# Getting and updating the native SDK

Every [release](https://github.com/jongsu-king/anti-reverse-shield/releases/latest)
carries one archive per platform plus `SHA256SUMS.txt`:

| Platform | Archive |
|---|---|
| Linux x86-64 (glibc 2.35+) | `anti-reverse-shield-sdk-<version>-linux-x86_64.tar.gz` |
| Linux ARM64 (glibc 2.35+) | `anti-reverse-shield-sdk-<version>-linux-arm64.tar.gz` |
| macOS 11+ Apple silicon | `anti-reverse-shield-sdk-<version>-macos-arm64.tar.gz` |
| macOS 11+ Intel | `anti-reverse-shield-sdk-<version>-macos-x86_64.tar.gz` |
| Windows x64 (MSVC) | `anti-reverse-shield-sdk-<version>-windows-x64.zip` |

Layout of an archive:

```
anti-reverse-shield-sdk-<version>-<platform>/
├── include/shield.h, include/obfstr.hpp
├── lib/libars_shield.a        (ars_shield.lib on Windows)
├── lib/cmake/ars_shield/      CMake package: find_package(ars_shield) -> ars::shield
├── bin/ars_demo               runnable example
├── VERSION, LICENSE, README.md, NATIVE.md
```

## Using it from CMake

```cmake
find_package(ars_shield 0.3 REQUIRED)            # -DCMAKE_PREFIX_PATH=third_party/anti-reverse-shield
target_link_libraries(my_app PRIVATE ars::shield)
```

Without CMake: add `include/` to the include path and link `lib/libars_shield.a`
(plus `-ldl` on Linux). A complete consumer is in `native/examples/consumer/`.

## Updating a vendored copy

```bash
scripts/update-sdk.sh                         # Linux / macOS
scripts/update-sdk.sh --check                 # exit 10 if a newer release exists
scripts/update-sdk.sh --dir vendor/ars        # another folder
```

```powershell
scripts\update-sdk.ps1                        # Windows
scripts\update-sdk.ps1 -Check
```

The script asks the GitHub API for the latest release (one anonymous request),
downloads the archive for the current platform, compares its SHA-256 with the
release's `SHA256SUMS.txt` - on a mismatch nothing is changed - and replaces the
folder, writing the version to `VERSION`. Copy the script into your own project
(it has no dependencies besides `curl`, `tar` and `sha256sum`/`shasum`).

## Automatic update pull requests

To be told about new versions without checking by hand, add this workflow to
**your** repository (`.github/workflows/update-ars-shield.yml`). Once a week it
updates the vendored SDK and, if anything changed, opens a pull request, so your
tests run before the new version reaches a build:

```yaml
name: Update anti-reverse-shield
on:
  schedule: [{ cron: "0 3 * * 1" }]
  workflow_dispatch:
permissions:
  contents: write
  pull-requests: write
jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Update the vendored SDK
        run: |
          curl -fsSL -o /tmp/update-sdk.sh \
            https://raw.githubusercontent.com/jongsu-king/anti-reverse-shield/master/scripts/update-sdk.sh
          sh /tmp/update-sdk.sh --dir third_party/anti-reverse-shield
      - name: Open a pull request
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          git diff --quiet && exit 0
          V=$(cat third_party/anti-reverse-shield/VERSION)
          git switch -c "ars-shield-$V"
          git -c user.name=github-actions -c user.email=github-actions@users.noreply.github.com \
            commit -am "anti-reverse-shield $V"
          git push -u origin "ars-shield-$V"
          gh pr create --fill
```

The Linux x86-64 archive is what the workflow vendors; build machines for other
platforms run the script themselves (or vendor several archives side by side).

## Why there is no in-app updater

The library is linked into **your** program. A protection layer that fetched and
loaded code at run time would itself be something an attacker could redirect, so
updates are a build-time step: update the vendored SDK, test, ship your next build.
The Android, Electron, .NET and server modules are source files - update them with
`git pull` (or a git submodule) in the same way.
