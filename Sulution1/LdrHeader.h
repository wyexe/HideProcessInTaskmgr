#ifndef __HIDEPROCESSINTASKMGR_SULUTION1_LDRHEADER_H__
#define __HIDEPROCESSINTASKMGR_SULUTION1_LDRHEADER_H__

#include <Windows.h>

class CLdrHeader
{
public:
	CLdrHeader() = default;
	~CLdrHeader() = default;

	static BOOL InlindeHook(_In_ LPVOID HookProcPtr, _In_ LPVOID NewProcPtr, _Out_ LPVOID* RealProcPtr);

	static VOID UnInlineHook(_In_ LPVOID HookProcPtr, LPVOID RealProcPtr);
private:
	static BOOL GetPatchSize(_In_ LPVOID HookProcPtr, _In_ DWORD dwSize, _Out_ DWORD* pdwPatchSize);

	static ULONG __fastcall SizeOfCode(_In_ LPVOID Code, UCHAR ** pOpCode);
};


#endif // !__HIDEPROCESSINTASKMGR_SULUTION1_LDRHEADER_H__
