#include <windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <filesystem>
#include <wbemcli.h>

#include "MinHook.h"
#pragma comment(lib, "libMinHook.x64.lib")

struct RawSMBIOSData
{
    BYTE    Used20CallingMethod;
    BYTE    SMBIOSMajorVersion;
    BYTE    SMBIOSMinorVersion;
    BYTE    DmiRevision;
    DWORD   Length;
    BYTE    SMBIOSTableData[];
};

struct RawSMBIOSTable
{
    BYTE    Type;
    BYTE    Length;
    WORD    Handle;
};

struct RawBiosInformationTable : public RawSMBIOSTable 
{
    BYTE    Vendor;
    BYTE    BiosVersion;
    UINT16  BiosSegment;
    BYTE    BiosReleaseDate;
    UINT8   BiosSize;
};

struct RawSystemInformationTable : public RawSMBIOSTable 
{
    BYTE    Manufacturer;
    BYTE    ProductName;
    BYTE    Version;
    BYTE    SerialNumber;
    GUID    Uuid;
    UINT8   WakeUpType;
    BYTE    SKUNumber;
    BYTE    Family;
};

struct RawBaseboardInformationTable : public RawSMBIOSTable
{
    BYTE    Manufacturer;
    BYTE    ProductName;
    BYTE    Version;
    BYTE    SerialNumber;
};

struct RawProcessorInformationTable : public RawSMBIOSTable
{
    BYTE    Socket;
    UINT8   ProcessorType;
    UINT8   ProcessorFamily;
    BYTE    ProcessorManufacturer;
    BYTE    ProcessorId[8];
    BYTE    ProcessorVersion;
    BYTE    Voltage;
    UINT16  ExternalClock;
    UINT16  MaxSpeed;
    UINT16  CurrentSpeed;
    UINT8   Status;
    UINT8   ProcessorUpgrade;
    UINT16  L1CacheHandle;
    UINT16  L2CacheHandle;
    UINT16  L3CacheHandle;
    BYTE    SerialNumber;
    BYTE    AssetTag;
    BYTE    PartNumber;
};

static std::vector<unsigned char> key = { };

UINT __stdcall GetSystemFirmwareTable_Hooked(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize);
decltype(&GetSystemFirmwareTable_Hooked) GetSystemFirmwareTable_Original = nullptr;

PSTR GetSmBiosString(RawSMBIOSTable* SmBiosTable, BYTE StringIndex)
{
    BYTE CurrentStringIndex = 1;
    PSTR currentString = (PSTR)(((BYTE*)SmBiosTable) + SmBiosTable->Length);

    while (*currentString) {
        if (CurrentStringIndex == StringIndex) {
            break;
        }

        ++currentString;

        if (!*currentString) {
            ++currentString;
            ++CurrentStringIndex;
        }
    }

    if (!*currentString)
        return nullptr;

    return currentString;
}

void MangleSmBiosString(RawSMBIOSTable* SmBiosTable, BYTE StringIndex)
{
    char* str = GetSmBiosString(SmBiosTable, StringIndex);
    if (!str) {
        return;
    }

    printf("bsg wants smbios (%s)\n", str);

    //amazing algo by hollow below
    const auto length = strlen(str);
    for (size_t i = 0; i < length; i++)
    {
        const auto original_character = (char)str[i]; // just get a byte out of a wide char, don't care what it is really
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
        str[i] = (char)cock;
    }
    printf("smbios mangled to %s\n", str);
}

UINT __stdcall GetSystemFirmwareTable_Hooked(DWORD FirmwareTableProviderSignature, DWORD FirmwareTableID, PVOID pFirmwareTableBuffer, DWORD BufferSize)
{
    printf("GetSystemFirmwareTable called\n");

    UINT result = GetSystemFirmwareTable_Original(FirmwareTableProviderSignature, FirmwareTableID, pFirmwareTableBuffer, BufferSize);

    if (FirmwareTableProviderSignature == 'RSMB' && FirmwareTableID == 0 && pFirmwareTableBuffer != nullptr) {
        auto SMBIOSData = (RawSMBIOSData*)pFirmwareTableBuffer;
        RawSMBIOSTable* smbiosTable = nullptr;
        ULONG i = 0;
        ULONG type = 0;

        bool properTermination = false;

        do {
            properTermination = false;

            // Check that the table header fits in the buffer.
            if (i + sizeof(RawSMBIOSTable) < SMBIOSData->Length) {

                type = SMBIOSData->SMBIOSTableData[i];

                if (type >= 0 && type <= 4)
                    smbiosTable = (RawSMBIOSTable*)&SMBIOSData->SMBIOSTableData[i];

                // Set i to the end of the formated section.
                i += SMBIOSData->SMBIOSTableData[i + 1];

                // Look for the end of the struct that must be terminated by \0\0
                while (i + 1 < SMBIOSData->Length) {
                    if (0 == SMBIOSData->SMBIOSTableData[i] &&
                        0 == SMBIOSData->SMBIOSTableData[i + 1]) {
                        properTermination = true;
                        i += 2;
                        break;
                    }

                    ++i;
                }

                if (properTermination && smbiosTable) {
                    switch (type) {
                        case 0: {
                            auto biosInfo = (RawBiosInformationTable*)smbiosTable;
                            MangleSmBiosString(smbiosTable, biosInfo->Vendor);
                            MangleSmBiosString(smbiosTable, biosInfo->BiosVersion);
                            MangleSmBiosString(smbiosTable, biosInfo->BiosReleaseDate);
                        } break;

                        case 1: {
                            auto systemInfo = (RawSystemInformationTable*)smbiosTable;

                            MangleSmBiosString(smbiosTable, systemInfo->Manufacturer);
                            MangleSmBiosString(smbiosTable, systemInfo->ProductName);
                            MangleSmBiosString(smbiosTable, systemInfo->Version);
                            MangleSmBiosString(smbiosTable, systemInfo->SerialNumber);

                            if (systemInfo->Length > 25) {
                                MangleSmBiosString(smbiosTable, systemInfo->SKUNumber);
                                MangleSmBiosString(smbiosTable, systemInfo->Family);
                            }

                            auto guidPtr = (char*)&systemInfo->Uuid;
                            for (int j = 0; j < sizeof(GUID); j++)
                                guidPtr[j] ^= key[j % 8];
                        } break;

                        case 2: {
                            auto baseboardInfo = (RawBaseboardInformationTable*)smbiosTable;

                            MangleSmBiosString(smbiosTable, baseboardInfo->Manufacturer);
                            MangleSmBiosString(smbiosTable, baseboardInfo->ProductName);
                            MangleSmBiosString(smbiosTable, baseboardInfo->Version);
                            MangleSmBiosString(smbiosTable, baseboardInfo->SerialNumber);
                        } break;

                        case 4: {
                            auto processorInfo = (RawProcessorInformationTable*)smbiosTable;

                            MangleSmBiosString(smbiosTable, processorInfo->ProcessorManufacturer);
                            MangleSmBiosString(smbiosTable, processorInfo->ProcessorVersion);
                            if (processorInfo->Length > 32) {
                                MangleSmBiosString(smbiosTable, processorInfo->SerialNumber);
                                MangleSmBiosString(smbiosTable, processorInfo->PartNumber);
                            }

                            for (int j = 0; j < 4; j++) // mangle PROCESSOR_SIGNATURE only
                                processorInfo->ProcessorId[j] ^= key[j % 8];

                        } break;

                        default:
                            break;
                    }

                    smbiosTable = nullptr;
                }
            }
        } while (properTermination);
    }

    return result;
}

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

    printf("waiting for kernel32.dll\n"); //Technically it is not necessary to wait for kernel32.dll, but I will anyway
    HMODULE kernel32 = nullptr;
    while (kernel32 == nullptr)
    {
        kernel32 = GetModuleHandleA("KernelBase.dll");
        Sleep(100);
    }
    printf("kernel32.dll @ 0x%p\n", kernel32);

    const auto get_func = GetProcAddress(fastprox, "?Get@CWbemObject@@UEAAJPEBGJPEAUtagVARIANT@@PEAJ2@Z");
    if (get_func == nullptr)
    {
        printf("can't find CWbemObject::Get! exiting\n");
        exit(0);
        return;
    }
    printf("CWbemObject::Get @ 0x%p\n", get_func);

    const auto firmware_func = GetProcAddress(kernel32, "GetSystemFirmwareTable");
    if (firmware_func == nullptr)
    {
        printf("can't find GetSystemFirmwareTable! exiting\n");
        exit(0);
        return;
    }
    printf("GetSystemFirmwareTable @ 0x%p\n", firmware_func);

    if (MH_Initialize() != MH_OK)
    {
        printf("can't initialize minhook! exiting\n");
        exit(0);
        return;
    }

    if (MH_CreateHook(get_func, &hooked, (void**)&original_func) != MH_OK)
    {
        printf("can't create hook CWbemObject::Get! exiting\n");
        exit(0);
        return;
    }

    if (MH_CreateHook(firmware_func, &GetSystemFirmwareTable_Hooked, (void**)&GetSystemFirmwareTable_Original) != MH_OK)
    {
        printf("can't create hook GetSystemFirmwareTable! exiting\n");
        exit(0);
        return;
    }

    if (MH_EnableHook(get_func) != MH_OK)
    {
        printf("can't enable hook! exiting\n");
        exit(0);
        return;
    }

    if (MH_EnableHook(firmware_func) != MH_OK)
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

