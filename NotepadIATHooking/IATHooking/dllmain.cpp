// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"

void ErrorMessage(const char* msg);
void* FindIID(char* imageBase);
void* FindThunk(const char* dllName, void* originIID);
BOOL SetHookingIAT(void* originITD, void* originFunctionAddr, void* changeFunctionAddr);
typedef BOOL(WINAPI* HookFunc)(_In_ HWND hwnd, _In_ LPCWSTR lpString);
BOOL WINAPI NewWindowTextW(void* oriFunc, _In_ HWND hwnd, _In_ LPCWSTR title);

const char* DLL_TITLE = "IATHooking";
const char* HOOK_DLL_NAME = "kernel32.dll";
const char* HOOK_FUNCTION_NAME = "SetWindowTextW";

HMODULE imagebase = NULL;
IMAGE_IMPORT_DESCRIPTOR* iid = nullptr;
IMAGE_THUNK_DATA* itd;
void* oriFuncAddr;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		imagebase = GetModuleHandleA(NULL);
		if (imagebase == NULL) ErrorMessage("GetModuleHandle");

		iid = (IMAGE_IMPORT_DESCRIPTOR*)FindIID((char*)imagebase);
		if (iid == nullptr) ErrorMessage("FindIID");

		itd = (IMAGE_THUNK_DATA*)FindThunk(HOOK_DLL_NAME, iid);
		if (itd == nullptr) ErrorMessage("FindThunk");

		oriFuncAddr = GetProcAddress(GetModuleHandleA(HOOK_DLL_NAME), HOOK_FUNCTION_NAME);
		if (oriFuncAddr == nullptr) ErrorMessage("GetProcAddress");

		SetHookingIAT(itd, oriFuncAddr, NewWindowTextW);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		SetHookingIAT(itd, NewWindowTextW, oriFuncAddr);
		break;
	}
	return TRUE;
}

void ErrorMessage(const char* msg) {
	MessageBoxA(NULL, msg, DLL_TITLE, NULL);
	ExitProcess(-1);
};

void* FindIID(char* imageBase) {
	IMAGE_DOS_HEADER* idh = nullptr;
	idh = (IMAGE_DOS_HEADER*)imageBase;
	IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)&imageBase[idh->e_lfanew];
	auto firstIIDAddr = inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	return &imageBase[firstIIDAddr];
};

void* FindThunk(const char* dllName, void* originIID) {
	IMAGE_IMPORT_DESCRIPTOR* iid = nullptr;
	IMAGE_THUNK_DATA* itd = nullptr;
	iid = (IMAGE_IMPORT_DESCRIPTOR*)originIID;
	if (iid == nullptr) ErrorMessage("FindThunk");

	while (TRUE) {
		auto result = _stricmp(dllName, (const char*)&imagebase[iid->Name]);
		if (result != 0 || result == 0xfffffffff) {
			iid++;
			continue;
		};
		
		return &imagebase[iid->FirstThunk];
	};
};

BOOL SetHookingIAT(void* originITD,void* originFunctionAddr,void* changeFunctionAddr) {
	IMAGE_THUNK_DATA* itd = (IMAGE_THUNK_DATA*)originITD;
	
	while (TRUE) {
		if (itd->u1.Function != (ULONGLONG)originFunctionAddr) {
			itd++;
			continue;
		};
		break;
	};

	DWORD* oldProtect = nullptr;

	if (!VirtualProtect((LPVOID)&itd->u1.Function, sizeof(ULONGLONG), PAGE_EXECUTE_READWRITE, oldProtect)) ErrorMessage("Virtualprotect");
	itd->u1.Function = (ULONGLONG)changeFunctionAddr;

	if (!VirtualProtect((LPVOID)&itd->u1.Function, sizeof(ULONGLONG), *oldProtect, oldProtect)) ErrorMessage("Virtualprotect");
	return TRUE;
};

BOOL WINAPI NewWindowTextW(void* oriFunc, _In_ HWND hwnd, _In_ LPCWSTR title) {
	MessageBoxW(NULL, title, L"메롱", NULL);
	title = L"BGY";
	
	return ((HookFunc)oriFunc)(hwnd, title);
};