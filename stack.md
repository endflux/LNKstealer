# Stack

## Language & Runtime
- **C++17** — primary language for all injector, payload, and crypto modules
- **MASM / ARM64 ASM** — syscall trampoline stubs (`syscall_trampoline_x64.asm`, `syscall_trampoline_arm64.asm`)
- **Python 3** — tooling scripts (`comrade_abe.py`, `browser_processes.py`)

## Build System
- **MSVC (`cl.exe`)** — compiler for all C++/ASM sources
- **`make.bat`** — custom build orchestrator (no CMake/MSBuild project file)
- **GitHub Actions** — CI producing `chromelevator_x64.exe` + `chromelevator_arm64.exe` release artifacts

## Compiler Flags (notable)
| Flag | Purpose |
|------|---------|
| `/MT` | Static CRT linkage — no runtime DLL dependency |
| `/GS-` | Stack cookies disabled — avoids CRT init overhead in payload |
| `/GL` + `/LTCG` | Whole-program optimization |
| `/O1 /Os` | Optimize for size |
| `/GR-` | RTTI disabled |
| `/Zc:threadSafeInit-` | Disable thread-safe static init (no CRT guards in payload) |

## Cryptography
- **ChaCha20** — payload DLL encryption at rest (compile-time byte array, compile-time derived key)
- **AES-256-GCM** — Chrome cookie/password/payment blob decryption (via `bcrypt.lib` Windows CNG)
- **Compile-time key derivation** — keys derived from build metadata (`key_derivation.hpp`)

## Windows Internals / APIs
- **Direct Syscalls (Hell's Gate)** — runtime SSN resolution via ntdll parsing + DJB2 hash matching; no plaintext `Nt*` names in binary
- **NT Native API** — `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtCreateThreadEx`, `NtTerminateProcess`, `NtGetNextProcess`, `NtDuplicateObject`
- **COM / IElevator** — `IElevator`, `IElevator2`, `IEdgeElevatorFinal`, `IAvastElevator` interfaces for ABE decryption
- **Named Pipes** — IPC channel between injector and in-process payload (browser IPC name mimicry)
- **PEB walking** — IAT resolution without `GetProcAddress`

## Data Storage
- **SQLite 3** — bundled single-file amalgamation (`libs/sqlite/sqlite3.c`) for querying browser DBs (`Cookies`, `Login Data`, `Web Data`) via syscall-based handle duplication to bypass file locks

## Output Format
- **JSON** — all extracted data (cookies, passwords, payment methods, IBANs, OAuth tokens, fingerprint) written to `<output>/<Browser>/<Profile>/`

## Target Platforms
- Windows x64
- Windows ARM64

## Supported Browsers
- Google Chrome (stable + beta)
- Microsoft Edge
- Brave
- Avast Secure Browser
