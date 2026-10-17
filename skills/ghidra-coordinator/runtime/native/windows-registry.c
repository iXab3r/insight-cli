/* MIT; first-party HKCU redirection, loaded only into a newly created owned suspended tool. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "detours.h"
extern "C" __declspec(dllexport) BOOL WINAPI InsightPrepareProcess(HANDLE process,LPCSTR name){return DetourUpdateProcessWithDll(process,&name,1);}
static void store(BYTE *at,DWORD value){at[0]=(BYTE)value;at[1]=(BYTE)(value>>8);at[2]=(BYTE)(value>>16);at[3]=(BYTE)(value>>24);}
extern "C" BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved){
 (void)reserved;if(reason!=DLL_PROCESS_ATTACH)return TRUE;DisableThreadLibraryCalls(instance);if(DetourIsHelperProcess())return TRUE;DetourRestoreAfterWith();
 WCHAR handle[17],nonce[37];DWORD n=GetEnvironmentVariableW(L"INSIGHT_PRIVATE_HKCU_HANDLE",handle,17);
 if(!n)return TRUE;
 if(n>16||GetEnvironmentVariableW(L"INSIGHT_PRIVATE_HKCU_NONCE",nonce,37)!=36)return FALSE;
 WCHAR *path=(WCHAR*)HeapAlloc(GetProcessHeap(),0,4096*sizeof(WCHAR));if(!path)return FALSE;
 DWORD length=GetEnvironmentVariableW(L"INSIGHT_PRIVATE_HKCU_ACK",path,4096);if(!length||length>=4096)return FALSE;
 ULONG_PTR value=0;for(DWORD i=0;i<n;i++){WCHAR c=handle[i];unsigned digit=c>=L'0'&&c<=L'9'?c-L'0':c>=L'A'&&c<=L'F'?c-L'A'+10:16;if(digit>15)return FALSE;value=(value<<4)|digit;}
 LSTATUS error=RegOverridePredefKey(HKEY_CURRENT_USER,(HKEY)value);RegCloseKey((HKEY)value);
 BYTE proof[48];store(proof,0x49484b31);store(proof+4,GetCurrentProcessId());store(proof+8,(DWORD)error);for(DWORD i=0;i<36;i++)proof[12+i]=(BYTE)nonce[i];
 HANDLE file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(file==INVALID_HANDLE_VALUE)return FALSE;
 DWORD written=0;BOOL saved=WriteFile(file,proof,sizeof(proof),&written,NULL)&&written==sizeof(proof)&&FlushFileBuffers(file);CloseHandle(file);HeapFree(GetProcessHeap(),0,path);
 SetEnvironmentVariableW(L"INSIGHT_PRIVATE_HKCU_HANDLE",NULL);SetEnvironmentVariableW(L"INSIGHT_PRIVATE_HKCU_NONCE",NULL);SetEnvironmentVariableW(L"INSIGHT_PRIVATE_HKCU_ACK",NULL);
 return saved&&error==ERROR_SUCCESS;
}
