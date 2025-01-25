#include <iostream>
#include <filesystem>
#include <Windows.h>
#include <ShlObj.h>
#include <conio.h>
#include <strsafe.h>
#include "cURL/curl.h"
#include "libzip/zip.h"

#define LAWIN_URL "https://github.com/Lawin0129/LawinServer/zipball/master"

#define BINARY_PATH_OT L".\\FortniteGame\\Binaries\\Win32\\FortniteClient-Win32-Shipping.exe"
#define BINARY_PATH_OT_FUCKBLK L".\\FortniteGame\\Binaries\\Win32\\FortniteClient-Win64-Shipping.exe" // what the actual fuck is wrong with this guy
#define CONTENT_PATH_OT L".\\FortniteGame\\Content\\"
#define CONFIG_PATH_OT L".\\FortniteGame\\Config\\"
#define DEFAULTENGINE_URL "https://github.com/absoluteSpacehead/MercuryLauncher-Assets/raw/refs/heads/main/DefaultEngine.ini"
#define DEFAULTGAME_URL "https://github.com/absoluteSpacehead/MercuryLauncher-Assets/raw/refs/heads/main/DefaultGame.ini"
#define ABILITIES_URL "https://github.com/absoluteSpacehead/MercuryLauncher-Assets/raw/refs/heads/main/GE_AllAbilities.uasset"
#define ACTOR_URL "https://github.com/absoluteSpacehead/MercuryLauncher-Assets/raw/refs/heads/main/InGame_Actor.uasset"
#define GAMEMODE_URL "https://github.com/absoluteSpacehead/MercuryLauncher-Assets/raw/refs/heads/main/InGame_Gamemode.uasset"
#define PAK_URL_OT "https://github.com/absoluteSpacehead/MercuryLauncher-Assets/raw/refs/heads/main/FortniteGame-WindowsClient_p.pak"

#define BINARY_PATH_1_8 L".\\FortniteGame\\Binaries\\Win64\\FortniteClient-Win64-Shipping.exe"
#define PAKS_PATH_1_8 L".\\FortniteGame\\Content\\Paks\\"
#define PRODUCT_VERSION_1_8 L"3724489"
#define DLL_URL "https://github.com/absoluteSpacehead/MercuryLauncher-Assets/raw/refs/heads/main/Mercury-1.8.dll"
#define PAK_URL_18 "https://github.com/absoluteSpacehead/MercuryLauncher-Assets/raw/refs/heads/main/zzz_LawinServer.pak"
#define SIG_URL_18 "https://github.com/absoluteSpacehead/MercuryLauncher-Assets/raw/refs/heads/main/zzz_LawinServer.sig"

HANDLE job;

bool verbosecURL;

void Exit()
{
    std::cout << "Press any key to exit.\n";
    TerminateJobObject(job, 0);
    _getch();
}

// https://stackoverflow.com/a/1636415
size_t WriteData(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return fwrite(ptr, size, nmemb, stream);
}

int DownloadFile(const char* URL, const wchar_t outName[FILENAME_MAX])
{
    CURL* curl;
    FILE* fp;
    CURLcode res;

    curl = curl_easy_init();

    if (!curl)
    {
        std::cout << "\ncURL init failed.\n";
        return 1;
    }

    errno_t fpOpen = _wfopen_s(&fp, outName, L"wb");
    if (fpOpen != 0)
    {
        char out[128];
        strerror_s(out, fpOpen);
        std::cout << "\n_wfopen_s failed (" << out << ") .\n";
        return 2;
    }
    
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_URL, URL);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteData);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

    if (verbosecURL)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    res = curl_easy_perform(curl);

    if (res != 0)
    {
        std::cout << "\ncURL failed (" << curl_easy_strerror(res) << ").\n";
        return 3;
    }

    curl_easy_cleanup(curl);
    fclose(fp);

    return 0;
}

void GetLocalAppData(std::wstring& out)
{
    PWSTR rawLocalAppData;
    SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &rawLocalAppData);
    out = *(new std::wstring(rawLocalAppData));

    out += L"\\Mercury";

    CoTaskMemFree(rawLocalAppData);
}

int RunLawin()
{
    std::wstring localAppData;
    GetLocalAppData(localAppData);

    // make sure the root mercury folder exists
    if (!std::filesystem::exists(localAppData))
    {
        std::filesystem::create_directory(localAppData);
    }

    // Check that lawinserver is installed to begin with
    // we delete the zip at the end, so if it still exists that means something went wrong. assume download fucked up, delete it and try again
    if (std::filesystem::exists(localAppData + L"\\LawinServer.zip"))
    {
        std::cout << "LawinServer.zip already exists! Last attempt may have failed. If this happens repeatedly, seek support on Discord.\nTrying again...\n";

        std::filesystem::remove(localAppData + L"\\LawinServer.zip");

        if (std::filesystem::exists(localAppData + L"\\LawinServer"))
        {
            std::filesystem::remove_all(localAppData + L"\\LawinServer");
        }
    }

    if (!std::filesystem::exists(localAppData + L"\\LawinServer"))
    {
        std::cout << "LawinServer is missing, downloading it now...\n";

        if (DownloadFile(LAWIN_URL, (localAppData + L"\\LawinServer.zip").c_str()) != 0)
        {
            std::cerr << "\nLawinServer failed to download.\n";
            return 1;
        }

        std::wcout << "LawinServer downloaded. Extracting to " << localAppData << "\\LawinServer...\n";

        std::filesystem::create_directory(localAppData + L"\\LawinServer");

        zip_error_t err;

        zip_source_t* src = zip_source_win32w_create((localAppData + L"\\LawinServer.zip").c_str(), 0, -1, &err);
        if (!src)
        {
            std::cerr << "\nSource creation failed (" << zip_error_strerror(&err) << ").\n";
            return 2;
        }

        zip* file = zip_open_from_source(src, 0, &err);
        if (!file)
        {
            std::cerr << "\nFile opening failed (" << zip_error_strerror(&err) << ").\n";
            zip_source_free(src);
            return 3;
        }

        // loop thru entries
        for (int i = 0; i < zip_get_num_entries(file, 0); i++)
        {
            const char* name = zip_get_name(file, i, 0);

            // strip out the top dir, its ANNOYING and i HATE IT
            const char* sName = strchr(name, '/');
            if (!sName || strlen(sName) <= 1)
            {
                continue;
            }
            sName++;

            // const char* -> wstring
            std::wstring wName(sName, sName + strlen(sName));
            std::wstring targ = localAppData + L"\\LawinServer\\" + wName;

            // dir? this setup is probably a bit sloppy tho
            if (name[strlen(name) - 1] == '/')
            {
                _wmkdir(targ.c_str());
                continue;
            }

            // not a dir, get the file out
            zip_file* zFile = zip_fopen_index(file, i, 0);
            if (!zFile)
            {
                std::cerr << "\nFailed to open file " << name << " (file may be corrupt).\n";
                return 4;
            }

            HANDLE fileHandle = CreateFileW(targ.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);

            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                std::wcerr << "\nFailed to create file " << targ << ".\n";
                return 5;
            }

            char buf[4096];
            DWORD written;
            zip_int64_t read;
            while ((read = zip_fread(zFile, buf, sizeof(buf))) > 0)
            {
                if (!WriteFile(fileHandle, buf, (DWORD)read, &written, nullptr))
                {
                    std::wcerr << "\nError writing file " << targ << ".\n";
                    return 6;
                }
            }

            zip_fclose(zFile);
            CloseHandle(fileHandle);
        }

        zip_close(file);
        std::cout << "Extraction complete.\n";

        // delete the zip
        std::filesystem::remove(localAppData + L"\\LawinServer.zip");
    }

    // packages
    if (!std::filesystem::exists(localAppData + L"\\LawinServer\\node_modules")) // just to be fancy
        std::cout << "Installing required packages...\n";
    else
        std::cout << "Checking for package updates...\n";

    STARTUPINFOW startupInfo = { 0 };
    startupInfo.cb = sizeof(STARTUPINFO);
    PROCESS_INFORMATION processInformation = { 0 };
    std::wstring cmd = L"cmd /c npm i";
    CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, (localAppData + L"\\LawinServer").c_str(), &startupInfo, &processInformation);

    WaitForSingleObject(processInformation.hProcess, INFINITE);

    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);

    // make sure that it actually. installed the packages
    if (!std::filesystem::exists(localAppData + L"\\LawinServer\\node_modules"))
    {
        std::cerr << "\nPackages were not installed correctly (node_modules doesn't exist).\n\nnpm may either not be installed or not be added to PATH. Ensure node.js and npm have been installed correctly.\nIf node.js has not yet been installed, visit https://nodejs.org to download and install it.\n";
        return 7;
    }

    // server
    std::cout << "Starting LawinServer...\n";

    // we already dealt with these earlier, we can reuse them
    startupInfo = { 0 };
    startupInfo.cb = sizeof(STARTUPINFO);
    processInformation = { 0 };
    cmd = L"node index.js";
    if (!CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE, 0x0, nullptr, (localAppData + L"\\LawinServer").c_str(), &startupInfo, &processInformation))
    {
        std::cerr << "\nLawinServer failed to start.\n\nnode.js may either not be installed or not be added to PATH. Ensure node.js and npm have been installed correctly.\nIf node.js has not yet been installed, visit https://nodejs.org to download and install it.\n";
        return 7;
    }

    AssignProcessToJobObject(job, processInformation.hProcess);

    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);

    std::cout << "LawinServer has been started.\n";

    return 0;
}

// The setup for OT / 1.8 are *completely* different, to the point where theres no code shared between them

int SetupOTPak()
{
    std::wstring pathAsWstring(CONTENT_PATH_OT);
    pathAsWstring += L"Paks\\";

    // https://forums.unrealengine.com/t/overriding-or-swapping-out-asset-in-a-pak-file/472404
    // despite arbitrary filenames working in 1.8, OT6.5 seemingly doesnt accept that?
    if (!std::filesystem::exists(pathAsWstring + L"FortniteGame-WindowsClient_p.pak"))
    {
        std::cout << "Required Mercury file is missing. Downloading...\n";

        if (DownloadFile(PAK_URL_OT, (pathAsWstring + L"FortniteGame-WindowsClient_p.pak").c_str()) != 0)
        {
            std::cerr << "\nFailed to download FortniteGame-WindowsClient_p.pak.\n";
            return 3;
        }

        std::cout << "File downloaded.\n";
    }

    return 0;
}

int SetupOTPakless()
{
    std::wstring pathAsWstring(CONTENT_PATH_OT);

    // check if we have InGame_Gamemode.uasset. we download this last so if we're missing this we can download everything just to be safe
    if (!std::filesystem::exists(pathAsWstring + L"InGame_Gamemode.uasset"))
    {
        std::cout << "Required Mercury files are missing. Downloading...\n";

        pathAsWstring = CONFIG_PATH_OT;
        if (DownloadFile(DEFAULTENGINE_URL, (pathAsWstring + L"DefaultEngine.ini").c_str()) != 0)
        {
            std::cerr << "\nFailed to download DefaultEngine.ini.\n";
            return 3;
        }

        if (DownloadFile(DEFAULTGAME_URL, (pathAsWstring + L"DefaultGame.ini").c_str()) != 0)
        {
            std::cerr << "\nFailed to download DefaultGame.ini.\n";
            return 3;
        }

        pathAsWstring = CONTENT_PATH_OT;
        if (DownloadFile(ABILITIES_URL, (pathAsWstring + L"GE_AllAbilities.uasset").c_str()) != 0)
        {
            std::cerr << "\nFailed to download GE_AllAbilities.uasset.\n";
            return 3;
        }

        if (DownloadFile(ACTOR_URL, (pathAsWstring + L"InGame_Actor.uasset").c_str()) != 0)
        {
            std::cerr << "\nFailed to download InGame_Actor.uasset.\n";
            return 3;
        }

        if (DownloadFile(GAMEMODE_URL, (pathAsWstring + L"InGame_Gamemode.uasset").c_str()) != 0)
        {
            std::cerr << "\nFailed to download InGame_Gamemode.uasset.\n";
            return 3;
        }

        std::cout << "All files downloaded.\n";
    }

    return 0;
}

int SetupOT()
{
    int lawinStatus = RunLawin();
    if (lawinStatus != 0)
        return 1;

    // i just cant fucking believe it
    if (std::filesystem::exists(BINARY_PATH_OT_FUCKBLK))
    {
        std::cout << "Looks like this build was downloaded from blk. Fixing your build files...\n";
        std::filesystem::rename(BINARY_PATH_OT_FUCKBLK, BINARY_PATH_OT);
        std::filesystem::remove(L".\\FortniteGame\\Binaries\\Win32\\FortniteLauncher.exe");
        std::filesystem::remove(L".\\FortniteGame\\Binaries\\Win32\\Launcher.bat");
    }

    // are we pakless?
    if (!std::filesystem::exists(CONFIG_PATH_OT))
    {
        if (SetupOTPak() != 0)
        {
            std::cerr << "\nFailed to set up Mercury. (OT6.5 pakked)\n";
            return 2;
        }
    }
    else
    {
        if (SetupOTPakless() != 0)
        {
            std::cerr << "\nFailed to set up Mercury. (OT6.5 pakless)\n";
            return 2;
        }
    }

    std::cout << "Starting Fortnite...\nLoading may take a while.\n";

    STARTUPINFOW startupInfo = { 0 };
    startupInfo.cb = sizeof(STARTUPINFO);
    PROCESS_INFORMATION processInformation = { 0 };
    std::wstring cmd(BINARY_PATH_OT);
    cmd += L" -log -AUTH_LOGIN=unknown -AUTH_PASSWORD=5001 -AUTH_TYPE=exchangecode";
    CreateProcessW(BINARY_PATH_OT, &cmd[0], nullptr, nullptr, FALSE, 0x0, nullptr, nullptr, &startupInfo, &processInformation);

    AssignProcessToJobObject(job, processInformation.hProcess);

    WaitForSingleObject(processInformation.hProcess, INFINITE);

    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);

    return 0;
}

int Setup18()
{
    int lawinStatus = RunLawin();
    if (lawinStatus != 0)
        return 1;

    std::wstring localAppData;

    GetLocalAppData(localAppData);

    // check that we have our dll. this isn't required for OT so it's not linked, means you only need one file in the OT dir
    if (!std::filesystem::exists(".\\MercuryInjector.dll"))
    {
        std::cerr << "Required DLL (MercuryInjector.dll) is missing. Ensure all files were extracted properly.\n";
        return 4;
    }

    // check that we have the mercury dll AND the sig. someone could be using the same build folder but have wiped their appdata, etc
    std::wstring pathAsWstring(PAKS_PATH_1_8);
    if (!std::filesystem::exists(localAppData + L"\\Mercury-1.8.dll") || !std::filesystem::exists(pathAsWstring + L"zzz_LawinServer.sig"))
    {
        std::cout << "Required Mercury files are missing. Downloading...\n";

        if (DownloadFile(DLL_URL, (localAppData + L"\\Mercury-1.8.dll").c_str()) != 0)
        {
            std::cerr << "\nFailed to download Mercury-1.8.dll.\n";
            return 2;
        }

        if (DownloadFile(PAK_URL_18, (pathAsWstring + L"zzz_LawinServer.pak").c_str()) != 0)
        {
            std::cerr << "\nFailed to download zzz_LawinServer.pak.\n";
            return 2;
        }

        if (DownloadFile(SIG_URL_18, (pathAsWstring + L"zzz_LawinServer.sig").c_str()) != 0)
        {
            std::cerr << "\nFailed to download zzz_LawinServer.sig.\n";
            return 2;
        }
        
        std::cout << "All files downloaded.\n";
    }

    std::cout << "Starting Fortnite... Type anything in the login screen.\n";

    // open fortnite
    STARTUPINFOW startupInfo = { 0 };
    startupInfo.cb = sizeof(STARTUPINFO);
    PROCESS_INFORMATION processInformation = { 0 };

    // args
    std::wstring cmdl(BINARY_PATH_1_8);
    cmdl += L" -skippatchcheck -epicportal -HTTP=WinInet -log";

    CreateProcessW(BINARY_PATH_1_8, &cmdl[0], nullptr, nullptr, FALSE, 0x0, nullptr, nullptr, &startupInfo, &processInformation);

    AssignProcessToJobObject(job, processInformation.hProcess);

    std::wstring dllPath(std::filesystem::current_path().c_str());
    dllPath += L"\\MercuryInjector.dll";

    // reference https://github.com/ZeroMemoryEx/Dll-Injector/blob/master/DLL-Injector/Dll-Injector.cpp#L43
    HANDLE fnHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processInformation.dwProcessId);
    void* location = VirtualAllocEx(fnHandle, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    BOOL write = WriteProcessMemory(fnHandle, location, dllPath.c_str(), wcslen(dllPath.c_str()) * sizeof(wchar_t) + sizeof(wchar_t), 0);

    if (!write)
    {
        std::cerr << "\nDLL failed to inject (WriteProcessMemory failed).\n";

        TerminateProcess(processInformation.hProcess, 0);
        return 3;
    }

    HANDLE thread = CreateRemoteThread(fnHandle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, location, 0, 0);

    if (!thread)
    {
        std::cerr << "\nDLL failed to inject (CreateRemoteThread failed).\n";

        TerminateProcess(processInformation.hProcess, 0);
        return 3;
    }

    WaitForSingleObject(thread, INFINITE);
    VirtualFree(location, 0, MEM_RELEASE);

    CloseHandle(thread);
    CloseHandle(fnHandle);

    WaitForSingleObject(processInformation.hProcess, INFINITE);

    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);

    return 0;
}


int main(int argc, char* argv[])
{
    for (int i = 0; i < argc; i++)
    {
        if (_stricmp(argv[i], "-verbosecurl") == 0)
        {
            verbosecURL = true;
        }
    }

    job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo = { 0 };
    jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jobInfo, sizeof(jobInfo));

    if (std::filesystem::exists(BINARY_PATH_OT) || std::filesystem::exists(BINARY_PATH_OT_FUCKBLK))
    {
        // we only have 1 32bit build lol
        int status = SetupOT();
        if (status != 0)
        {
            Exit();
            return 4;
        }
    }
    else if (std::filesystem::exists(BINARY_PATH_1_8))
    {
        // get cl
        DWORD fileVersionInfoSize = GetFileVersionInfoSizeW(BINARY_PATH_1_8, NULL);
        char* fileVersionInfoBuffer = new char[fileVersionInfoSize];
        GetFileVersionInfoW(BINARY_PATH_1_8, NULL, fileVersionInfoSize, fileVersionInfoBuffer);

        wchar_t* rawVersion;
        UINT discard;
        VerQueryValueW(fileVersionInfoBuffer, L"\\StringFileInfo\\040904b0\\ProductVersion", (LPVOID*)&rawVersion, &discard); // could get language but blehh the exe only has one so i dotn care. hardcode it :P

        std::wstring version(rawVersion + 0x7, 7);

        if (version == PRODUCT_VERSION_1_8)
        {
            int status = Setup18();
            if (status != 0)
            {
                Exit();
                return 4;
            }
        }
        else
        {
            std::wcerr << "\nBinary ProductVersion is wrong (got " << version << ", expected " << PRODUCT_VERSION_1_8 << "). Ensure you're using Fortnite 1.8.\n";
            Exit();
            return 2;
        }
    }
    else
    {
        std::cerr << "\nNo binaries could be found. Ensure the launcher is placed alongside the FortniteGame and Engine folders.\n";
        Exit();
        return 1;
    }

    return 0;
}