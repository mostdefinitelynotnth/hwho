#include <windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <filesystem>
#include <wbemcli.h>

#include "MinHook.h"
#pragma comment(lib, "libMinHook.x64.lib")

static std::vector<unsigned char> key = { };

HRESULT __stdcall hooked(IWbemClassObject* pThis, LPCWSTR wszName, LONG lFlags, VARIANT* pVal, CIMTYPE* pType, long* plFlavor);
decltype(&hooked) original_func = nullptr;

HRESULT __stdcall hooked(IWbemClassObject* pThis, LPCWSTR wszName, LONG lFlags, VARIANT* pVal, CIMTYPE* pType, long* plFlavor)
{
    const auto original_result = original_func(pThis, wszName, lFlags, pVal, pType, plFlavor);

    // not string? uninterested
    if (pVal->vt != VT_BSTR)
        return original_result;

    printf("bsg wants %ws (%ws)\n", wszName, pVal->bstrVal);

    // samtulach said those should be ignored, thus they should be ignored
    if (lstrcmpW(wszName, L"__GENUS") == 0 || lstrcmpW(wszName, L"__PATH") == 0 || lstrcmpW(wszName, L"__RELPATH") == 0)
    {
        printf("returning original\n");
        return original_result;
    }

    const auto length = lstrlenW(pVal->bstrVal);
    for (size_t i = 0; i < length; i++)
    {
        // amazing algorithm below
        const auto original_character = (char)pVal->bstrVal[i]; // just get a byte out of a wide char, don't care what it is really
        auto cock = original_character ^ key[i % 8];

        if (std::isalpha(original_character))
        {
            if (std::isupper(original_character))
                cock = (unsigned(cock) % 25) + 65; // within boundaries of uppercase letters
            else
                cock = (unsigned(cock) % 25) + 97; // within boundaries of lowercase letters
        }
        else if (std::isdigit(original_character))
            cock = (unsigned(cock) % 10) + 48; // within boundaries of numbers
        else 
            continue;

        cock &= 0x7F; // no extended ascii please. shouldn't happen though unless i'm an idiot
        pVal->bstrVal[i] = (WCHAR)cock;
    }
    printf("mangled to %ws\n", pVal->bstrVal);

    return original_result;
}

std::vector<unsigned char> read_da_file(const char* filename)
{
    std::basic_ifstream<unsigned char> file(filename, std::ios::binary);
    return std::vector<unsigned char>((std::istreambuf_iterator<unsigned char>(file)), std::istreambuf_iterator<unsigned char>());
}

void write_da_file(const char* filename, std::vector<unsigned char> data)
{
    std::ofstream fout(filename, std::ios::out | std::ios::binary);
    fout.write((char*)data.data()/* lol */, data.size());
}

void start()
{
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    
    printf("hi :)\n");

    if (std::filesystem::exists("hwho.dat"))
    {
        printf("reading xor key from file\n");
        key = read_da_file("hwho.dat");

        printf("key: ");
        for (size_t i = 0; i < 8; i++) // this can be less/more than 8, i frankly don't care if you fuck it up
            printf("%02X ", key[i] & 0xFF);
        printf("\n");
    }
    else
    {
        printf("key file not found, generating new\n");
        srand(time(nullptr));

        printf("key: ");
        for (size_t i = 0; i < 8; i++)
        {
            key.emplace_back(rand() % 256);
            printf("%02X ", key[i] & 0xFF);
        }
        printf("\n");

        write_da_file("hwho.dat", key);
    }

    printf("waiting for fastprox.dll\n");
    HMODULE fastprox = nullptr;
    while (fastprox == nullptr)
    {
        fastprox = GetModuleHandleA("fastprox.dll");
        Sleep(100);
    }
    printf("fastprox.dll @ 0x%p\n", fastprox);

    const auto get_func = GetProcAddress(fastprox, "?Get@CWbemObject@@UEAAJPEBGJPEAUtagVARIANT@@PEAJ2@Z");
    if (get_func == nullptr)
    {
        printf("can't find CWbemObject::Get! exiting\n");
        exit(0);
        return;
    }
    printf("CWbemObject::Get @ 0x%p\n", get_func);

    if (MH_Initialize() != MH_OK)
    {
        printf("can't initialize minhook! exiting\n");
        exit(0);
        return;
    }

    if (MH_CreateHook(get_func, &hooked, (void**)&original_func) != MH_OK)
    {
        printf("can't create hook! exiting\n");
        exit(0);
        return;
    }

    if (MH_EnableHook(get_func) != MH_OK)
    {
        printf("can't enable hook! exiting\n");
        exit(0);
        return;
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, LPTHREAD_START_ROUTINE(start), nullptr, 0, nullptr);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

