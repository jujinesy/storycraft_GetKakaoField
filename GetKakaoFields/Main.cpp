#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmdParam, int nCmdShow);

#pragma comment(lib, "ws2_32.lib")
void Start();

DWORD dwKakao = 0;

DWORD Kakao_return_1 = 0;
BYTE jmp[8] = { 0xe9,0x00,0x00,0x00,0x00,0x90,0x90,0x90 };

char* pathFormat = "Path> %S\n";
char* Keyformat = "SQLite op> %s\n\n";

bool bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask) return 0;
	return (*szMask) == NULL;
}

DWORD FindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask)
{
	for (DWORD i = 0; i<dwLen; i++)
		if (bCompare((BYTE*)(dwAddress + i), bMask, szMask)) return (DWORD)(dwAddress + i);
	return 0;
}

BOOL MemoryEdit(VOID *lpMem, VOID *lpSrc, DWORD len)
{
	DWORD lpflOldProtect, flNewProtect = PAGE_READWRITE;
	unsigned char * pDst = (unsigned char *)lpMem,
		*pSrc = (unsigned char *)lpSrc;
	if (VirtualProtect(lpMem, len, flNewProtect, &lpflOldProtect))
	{
		while (len-- > 0) *pDst++ = *pSrc++;
		return(0);
	}
	return(1);
}
DWORD Hook(LPVOID lpFunction)
{
	DWORD dwAddr = Kakao_return_1 - 8;
	DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);

	memcpy(&jmp[1], &dwCalc, 4);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmp, 8, 0);
	return dwAddr;
}

void __declspec(naked) Kakao_hook_1()
{
	__asm
	{
		pushad
		push dword ptr[edi]
		push pathFormat
		call printf
		add esp, 8
		popad

		pushad
		push esi
		push Keyformat
		call printf
		add esp, 8
		popad

		mov byte ptr ss : [ebp - 4] , 9
		cmp dword ptr ss : [ebp - 18] , 0

		jmp[Kakao_return_1]
	}
}
void Start()
{
	DWORD dwSize = 0x1000000;
	DWORD dwAddress = 0;
	do
	{
		dwKakao = (DWORD)GetModuleHandleA("KakaoTalk.exe");
		Sleep(10);
	} while (!dwKakao);
	Sleep(100);
	printf("Kakao: %x\n", dwKakao);
	dwAddress = FindPattern(dwKakao, dwSize, (PBYTE)"\x50\xE8\xFF\xFF\xFF\xFF\xC6\x45\xFC\x09\x83\x7D\xE8\x00", "xx????xxxxxxxx");
	printf("Address: %x\n", dwAddress);
	Kakao_return_1 = dwAddress + 14;
	Hook(Kakao_hook_1);
}
BOOL APIENTRY DllMain(HMODULE hModul, DWORD ul_reason_for_ca, LPVOID lpReserve)
{
	switch (ul_reason_for_ca)
	{
	case DLL_PROCESS_ATTACH:
		AllocConsole();
		freopen("CON", "w", stdout);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Start, NULL, NULL, NULL);

	case DLL_THREAD_ATTACH:

	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmdParam, int nCmdShow)
{
	Start();
	return 0;
}
