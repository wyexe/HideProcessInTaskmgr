#ifndef __HIDEPROCESSINTASKMGR_SULUTION2_LDRHEADER_H__
#define __HIDEPROCESSINTASKMGR_SULUTION2_LDRHEADER_H__

#include <Windows.h>
#include <string>

class CLdrHeader
{
public:
	CLdrHeader() = default;
	~CLdrHeader() = default;

	static BOOL IATHook(_In_ CONST std::string& szDLLName, _In_ CONST std::string& szProcName, _In_ LPVOID HookProcPtr, _Out_ LPVOID* pRealProcPtr);
private:

};



#endif // !__HIDEPROCESSINTASKMGR_SULUTION2_LDRHEADER_H__
