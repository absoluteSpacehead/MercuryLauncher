// Because external hooking is a fucking nightmare I'm just gonna inject this on launch, hook a func and inject the real Mercury DLL at that point.
// It's a bit hacky, but without a Mercury update to make things, functional, this is the best I can do :(

#include <iostream>
#include <ShlObj.h>
#include "MinHook/MinHook.h"

const uintptr_t SetSubGameOffset = 0x2E4F760;

HMODULE handle;

template<typename T>
static T* Offset(uintptr_t offset)
{
    return reinterpret_cast<T*>(reinterpret_cast<uintptr_t>(GetModuleHandle(0)) + offset);
}

void (*SetSubGame)(void* thisref, uint8_t SubGame) = nullptr;

void SetSubGameHook(void* thisref, uint8_t SubGame)
{
    if (SubGame != 0) // not campaign, ignore
    {
        SetSubGame(thisref, SubGame);
        return;
    }

    PWSTR rawLocalAppData;
    SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &rawLocalAppData);
    std::wstring dllPath(rawLocalAppData);
    dllPath += L"\\Mercury\\Mercury-1.8.dll";

    CoTaskMemFree(rawLocalAppData);

    // reference https://github.com/ZeroMemoryEx/Dll-Injector/blob/master/DLL-Injector/Dll-Injector.cpp#L43
    HANDLE fnHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, GetCurrentProcessId());
    void* location = VirtualAllocEx(fnHandle, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BOOL write = WriteProcessMemory(fnHandle, location, dllPath.c_str(), wcslen(dllPath.c_str()) * sizeof(wchar_t) + sizeof(wchar_t), 0);

    if (!write)
    {
        std::cerr << "\nDLL failed to inject (WriteProcessMemory failed).\n";

        MH_DisableHook(Offset<uintptr_t>(SetSubGameOffset));
        SetSubGame(thisref, SubGame);
        FreeLibraryAndExitThread(handle, 0);
        return;
    }

    HANDLE thread = CreateRemoteThread(fnHandle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, location, 0, 0);

    if (!thread)
    {
        std::cerr << "\nDLL failed to inject (CreateRemoteThread failed).\n";

        MH_DisableHook(Offset<uintptr_t>(SetSubGameOffset));
        SetSubGame(thisref, SubGame);
        FreeLibraryAndExitThread(handle, 0);
        return;
    }

    WaitForSingleObject(thread, INFINITE);
    VirtualFree(location, 0, MEM_RELEASE);

    MH_DisableHook(Offset<uintptr_t>(SetSubGameOffset));
    SetSubGame(thisref, SubGame);
    return;
}

DWORD MainThread(LPVOID)
{
    AllocConsole();
    ShowWindow(GetConsoleWindow(), SW_SHOW);
    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stderr);

    MH_Initialize();

    LPVOID off = Offset<uintptr_t>(SetSubGameOffset);
    MH_CreateHook(off, SetSubGameHook, reinterpret_cast<LPVOID*>(&SetSubGame));
    MH_EnableHook(off);

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            handle = hModule;
            CreateThread(0, 0, MainThread, 0, 0, 0);
            break;
    }

    return TRUE;
}

