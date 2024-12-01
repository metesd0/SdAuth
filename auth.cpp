#include "auth.hpp"
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <ws2tcpip.h>
#include <Wbemidl.h>
#include <comdef.h> // _bstr_t için gerekli
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wbemuuid.lib")

std::string getDiskID() {
    std::string diskID = "";
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "COM kütüphanesi başlatılamadı!" << std::endl;
        return "";
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        std::cerr << "Güvenlik başlatılamadı!" << std::endl;
        CoUninitialize();
        return "";
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        std::cerr << "WMI bağlantısı kurulamadı!" << std::endl;
        CoUninitialize();
        return "";
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // Namespace
        NULL,
        NULL,
        0,
        NULL,
        NULL,
        0,
        &pSvc);
    if (FAILED(hres)) {
        std::cerr << "WMI servisine bağlanılamadı!" << std::endl;
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT SerialNumber FROM Win32_DiskDrive"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);
    if (FAILED(hres)) {
        std::cerr << "Sorgu çalıştırılamadı!" << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (uReturn == 0) {
        std::cerr << "Disk ID alınamadı!" << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    VARIANT vtProp;
    hres = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
    if (FAILED(hres)) {
        std::cerr << "Disk Serial Number alınamadı!" << std::endl;
        pclsObj->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    diskID = _bstr_t(vtProp.bstrVal);
    VariantClear(&vtProp);

    // Temizlik işlemleri
    pclsObj->Release();
    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    return diskID;
}


bool validateAuthKey(const std::string& authKey, const std::string& diskID) {
    return authKey == diskID;
}


void setTextColor(bool isValidKey, bool isExpired) {
    if (isExpired) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);  // Expired = Red
    }
    else if (isValidKey) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);  // Valid = Green
    }
    else {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);  // Invalid = Red
    }
}

void authenticate(const std::string& authKey) {
    // Sunucu IP'si ve portu
    std::string ip = "127.0.0.1";
    int port = 5555;

    // Disk ID'yi al
    std::string diskID = getDiskID();
    if (diskID.empty()) {
        std::cerr << "Disk ID alınamadı!" << std::endl;
        return;
    }

    // Winsock başlatma
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Winsock başlatılamadı!" << std::endl;
        return;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket oluşturulamadı!" << std::endl;
        WSACleanup();
        return;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    if (InetPton(AF_INET, ip.c_str(), &serverAddr.sin_addr) != 1) {
        std::cerr << "Geçersiz adres!" << std::endl;
        closesocket(sock);
        WSACleanup();
        return;
    }

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Sunucuya bağlanılamadı!" << std::endl;
        closesocket(sock);
        WSACleanup();
        return;
    }

    std::string authMessage = authKey + ":" + diskID;
    send(sock, authMessage.c_str(), authMessage.size(), 0);

    char buffer[256];
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived == SOCKET_ERROR) {
        std::cerr << "Sunucudan cevap alınamadı!" << std::endl;
        closesocket(sock);
        WSACleanup();
        return;
    }

    buffer[bytesReceived] = '\0';
    std::cout << "Sunucu cevabı: " << buffer << std::endl;

    bool isValidKey = validateAuthKey(authKey, diskID);
    bool isExpired = (std::string(buffer) == "LICENSE_EXPIRED");

    setTextColor(isValidKey, isExpired);

    if (isValidKey && !isExpired) {
        std::cout << "Key doğru ve geçerli!" << std::endl;
    }
    else if (isExpired) {
        std::cout << "Lisans süresi dolmuş!" << std::endl;
    }
    else {
        std::cout << "Key yanlış!" << std::endl;
    }

    closesocket(sock);
    WSACleanup();
}
