#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmdParam, int nCmdShow);

#pragma comment(lib, "ws2_32.lib")
void Start();

DWORD dwKakao = 0;

DWORD Kakao_return_1 = 0;
BYTE jmp[] = { 0xe9,0x00,0x00,0x00,0x00, 0x90 };

char* idFormat = "Id> %d\n";
char* statusFormat = "Status> %hu\n";
char* nameFormat = "Packet> %.10s\n";
char* bodyTypeFormat = "Body type> %hhx\n";
char* bodyLengthFormat = "Body length> %d\n";

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
	DWORD dwAddr = Kakao_return_1 - 6;
	DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);

	memcpy(&jmp[1], &dwCalc, 4);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmp, sizeof(jmp), 0);
	return dwAddr;
}

void PrintBodyHex(char* body, int size) {

	printf("Body>");

	int i;
	for (i = 0; i < size; i++) {
		printf(" %02hhX", (unsigned char) body[i]);
	}

	printf("\n\n");

}

void __declspec(naked) Kakao_hook_1()
{
	__asm
	{
		pushad

		mov ecx, [ebx + 4]
		mov ebx, [ecx]

		pushad
		push[ebx]
		push idFormat
		call printf
		add esp, 8

		push[ebx + 4]
		push statusFormat
		call printf
		add esp, 8

		add ebx, 6
		push ebx
		sub ebx, 6
		push nameFormat
		call printf
		add esp, 8

		push[ebx + 17]
		push bodyTypeFormat
		call printf
		add esp, 8

		push[ebx + 18]
		push bodyLengthFormat
		call printf
		add esp, 8

		push[ebx + 18]
		add ebx, 22
		push ebx
		sub ebx, 22
		call PrintBodyHex
		add esp, 8

		popad

		popad

		mov eax, dword ptr ds : [ebx]
		mov ecx, ebx
		push 1

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
	dwAddress = FindPattern(dwKakao, dwSize, (PBYTE)"\x8B\xCE\xE8\x00\x00\x00\x00\x8B\x03\x8B\xCB\x6A\x01", "xxx????xxxxxx");
	printf("Address: %x\n", dwAddress);
	Kakao_return_1 = dwAddress + 13;
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
