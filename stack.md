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

## Planned EDR Evasion Improvements
- **RecycledGate** (replaces Hell's Gate) — scans ntdll for unhooked neighbors when a JMP is detected at positions 1/3/8/10/12; reuses existing `syscall;ret` gadgets already in ntdll so no custom trampoline needed; ref: [RecycledGate](https://github.com/thefLink/RecycledGate), [TartarusGate](https://github.com/trickster0/TartarusGate)
  - Change in `src/sys/internal_api.cpp`: extend SSN resolver to walk ±N neighbors on hooked stub detection
  - `syscall_trampoline_x64.asm` can be removed — gadget address returned by RecycledGate used directly
- **ETW patching** — patch `NtTraceEvent` stub in ntdll to `ret` before injection; blinds kernel telemetry pipeline
  - Two-byte patch (`0xC3`) applied via `NtProtectVirtualMemory` + `NtWriteVirtualMemory` syscalls (already in project)
  - Must run inside the browser process after `Bootstrap()` maps the payload; ref: [ETW-Bypass](https://github.com/0xflux/ETW-Bypass-Rust)
- **`NtMapViewOfSection` injection** (replaces `NtWriteVirtualMemory`) — create a shared section object, map into both injector and target, write payload once; avoids the `NtWriteVirtualMemory` call that EDRs watch heavily
  - New call sequence: `NtCreateSection` → `NtMapViewOfSection` (local) → write payload → `NtMapViewOfSection` (remote) → `NtCreateThreadEx`
  - ref: [DarkWidow](https://github.com/reveng007/DarkWidow), [RefleXXion](https://github.com/hlldz/RefleXXion)
- **Thread hijacking** (replaces `NtCreateThreadEx`) — suspend an existing browser thread, overwrite its context (`RIP` → Bootstrap), resume; no new thread created, no `NtCreateThreadEx` telemetry
  - Uses `NtGetContextThread` / `NtSetContextThread` / `NtSuspendThread` / `NtResumeThread` — all resolvable via RecycledGate
  - ref: [Killer](https://github.com/0xHossam/Killer)

## Data Storage
- **SQLite 3** — bundled single-file amalgamation (`libs/sqlite/sqlite3.c`) for querying browser DBs (`Cookies`, `Login Data`, `Web Data`) via syscall-based handle duplication to bypass file locks

## Output / Exfiltration
- **HTTP POST via COM** — decrypted data transmitted using `WinHttp.WinHttpRequest.5.1` (`CoCreateInstance`); no files written to disk
- `TransmitViaCOM()` POSTs `Content-Type: application/json` to `https://<targetHost><endpoint>`; optional `Authorization: Bearer <token>` header for authenticated endpoints (e.g. Upstash Redis REST)
- Each extraction method sends a typed JSON envelope: `{"type":"cookies"|"passwords"|"cards"|"tokens","data":[...]}`
- **Upstash Redis REST** — supported via `LPUSH` pipeline; set host to your Upstash endpoint, endpoint to `/pipeline`, token to your REST token

## Target Platforms
- Windows x64
- Windows ARM64

## Supported Browsers
- Google Chrome (stable + beta)
- Microsoft Edge
- Brave
- Avast Secure Browser
