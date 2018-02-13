#include <windows.h>
#include <stdio.h>

int main(int argc,char *argv[]){

unsigned char buf[0x1000];
DWORD tmp;
void (*sc)(void);
DWORD oldProtect;
char current_work_dir[FILENAME_MAX];

    if (argc > 1) {
        HANDLE file = CreateFileA (argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        ReadFile (file, buf, 0x1000, &tmp, NULL);
        CloseHandle (file);
    }
    else {
        printf("read %d bytes\n",fread(buf,1,0x1000,stdin));
    }
	_getcwd(current_work_dir, sizeof(current_work_dir));
	printf("Current:\n%s\n", current_work_dir);
    VirtualProtect (buf, 0x1000, PAGE_EXECUTE_READWRITE, &oldProtect);
    sc = (void(*)(void)) buf;
    (*sc)();
    printf("execute shellcode\n");

    return 0; 
}
