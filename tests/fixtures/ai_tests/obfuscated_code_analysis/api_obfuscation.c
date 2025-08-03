
        #include <stdio.h>
        #include <windows.h>
        
        typedef HANDLE (WINAPI *CreateFilePtr)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
        
        int main() {
            HMODULE kernel32 = LoadLibrary("kernel32.dll");
            CreateFilePtr pCreateFile = (CreateFilePtr)GetProcAddress(kernel32, "CreateFileA");
            
            if (pCreateFile) {
                printf("Dynamic API resolution successful\n");
            }
            
            FreeLibrary(kernel32);
            return 0;
        }
        