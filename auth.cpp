#include "auth.hpp"
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <ws2tcpip.h>
#include <Wbemidl.h>
#include <comdef.h> 
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wbemuuid.lib")

std::string getDiskID() {
    std::string diskID = "";
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "" << std::endl;
        return "";
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres)) {
        std::cerr << "" << std::endl;
        CoUninitialize();
        return "";
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        std::cerr << "" << std::endl;
        CoUninitialize();
        return "";
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), 
        NULL,
        NULL,
        0,
        NULL,
        NULL,
        0,
        &pSvc);
    if (FAILED(hres)) {
        std::cerr << "" << std::endl;
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
        std::cerr << "" << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
    if (uReturn == 0) {
        std::cerr << "" << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    VARIANT vtProp;
    hres = pclsObj->Get(L"SerialNumber", 0, &vtProp, 0, 0);
    if (FAILED(hres)) {
        std::cerr << "" << std::endl;
        pclsObj->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return "";
    }

    diskID = _bstr_t(vtProp.bstrVal);
    VariantClear(&vtProp);


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
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY);  
    }
    else if (isValidKey) {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);  
    }
    else {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED); 
    }
}

void authenticate(const std::string& authKey) {

    std::string ip = "98.81.220.75";
    int port = 5555;

    std::string diskID = getDiskID();
    if (diskID.empty()) {
        std::cerr << "" << std::endl;
        return;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "" << std::endl;
        return;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "" << std::endl;
        WSACleanup();
        return;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    if (InetPton(AF_INET, ip.c_str(), &serverAddr.sin_addr) != 1) {
        std::cerr << "" << std::endl;
        closesocket(sock);
        WSACleanup();
        return;
    }

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "" << std::endl;
        closesocket(sock);
        WSACleanup();
        return;
    }

    std::string authMessage = authKey + ":" + diskID;
    send(sock, authMessage.c_str(), authMessage.size(), 0);

    char buffer[256];
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived == SOCKET_ERROR) {
        std::cerr << "" << std::endl;
        closesocket(sock);
        WSACleanup();
        return;
    }

    buffer[bytesReceived] = '\0';
    std::cout << "Sunucu: " << buffer << std::endl;

    bool isValidKey = validateAuthKey(authKey, diskID);
    bool isExpired = (std::string(buffer) == "LICENSE_EXPIRED");

    setTextColor(isValidKey, isExpired);

    if (isValidKey && !isExpired) {
        std::cout << "valid key" << std::endl;
    }
    else if (isExpired) {
        std::cout << "expired key" << std::endl;
    }
    else {
        std::cout << "invalid key" << std::endl;
    }

    closesocket(sock);
    WSACleanup();
}
