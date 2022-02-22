
/*****************************************************************************\
**                                                                           **
**  StartRegedit                                                             **
**                                                                           **
**  Licensed under the GNU General Public License v3.0 (the "License").      **
**  You may not use this file except in compliance with the License.         **
**                                                                           **
**  You can obtain a copy of the License at http://gnu.org/licenses/gpl-3.0  **
**                                                                           **
\*****************************************************************************/

#pragma warning(disable : 4706 /*assignment within conditional expression*/ )
#define WINVER 0x501
#include <windows.h>
#include <shellapi.h>
#include <tchar.h>

template<class T> static DECLSPEC_NOINLINE T GetProcAddr(LPCSTR Mod, LPCSTR Exp)
{
	return (T) GetProcAddress(LoadLibraryA(Mod), Exp);
}

template<class T> static T GetProcAddrWithFallback(LPCSTR Mod, LPCSTR Exp, T Fallback)
{
	T p = GetProcAddr<T>(Mod, Exp);
	return p ? p : Fallback;
}

#ifdef _WIN64
static inline bool IsWow64Process() { return false; }
#else
static bool IsWow64Process()
{
	BOOL state, succ = IsWow64Process(GetCurrentProcess(), &state);
	return succ && state;
}
#endif

static UINT WINAPI FallbackGetSystemWow64Directory2W(LPWSTR Buf, UINT Cap, WORD Machine)
{
	if (Machine == IMAGE_FILE_MACHINE_I386)
		return GetSystemWow64DirectoryW(Buf, Cap);
	else
		return 0;
}

#define IsSwitch(a, b) IsSwitchWorker(const_cast<const TCHAR [ARRAYSIZE(a)]>(a), (b), ARRAYSIZE(a) - 1)
static UINT IsSwitchWorker(PCTSTR Switch, PCTSTR String, UINT Len)
{
	bool equal = CompareString(0, NORM_IGNORECASE, Switch, Len, String, Len) - 2 == 0;
	return equal && String[Len] <= ' ' ? Len : 0;
}

EXTERN_C DECLSPEC_NORETURN void __cdecl WinMainCRTStartup()
{
	const UINT cchMaxSysDir = MAX_PATH - 1;
	BOOL native32 = sizeof(void*) < 8 && !IsWow64Process(), allowWinDirFallback = native32;
	UINT ec = 0, cch;
	UINT high = false, lua = false, req32 = false, showCmd = SW_SHOWDEFAULT;
	WORD reqMachine = 0;
	TCHAR buf[cchMaxSysDir + sizeof("\\RegEdit.exe")];

	UINT (WINAPI*GetSystemWow64Directory2)(LPWSTR,UINT,WORD) = \
		GetProcAddrWithFallback("KERNEL32", "GetSystemWow64Directory2W", FallbackGetSystemWow64Directory2W);

	PTSTR p = GetCommandLine();
	if (*p == '\"')
		do ++p; while(*p && *p != '\"');
	else
		while(*p && *p > ' ') ++p;
	if (*p) ++p;

	for (;;)
	{
		while(*p <= ' ' && *p) ++p;

		if (*p == '-' || *p == '/')
		{
			++p;
			if ((cch = IsSwitch(TEXT("NoElevate"), p)) || (cch = IsSwitch(TEXT("AsInvoker"), p)) || (cch = IsSwitch(TEXT("LUA"), p)))
			{
				lua++;
				p += cch;
				continue;
			}
			if ((cch = IsSwitch(TEXT("Elevate"), p)) || (cch = IsSwitch(TEXT("RequireAdministrator"), p)) || (cch = IsSwitch(TEXT("UAC"), p)))
			{
				high++;
				p += cch;
				continue;
			}
			if ((cch = IsSwitch(TEXT("Maximized"), p)) || (cch = IsSwitch(TEXT("Max"), p)))
			{
				showCmd = SW_SHOWMAXIMIZED;
				p += cch;
				continue;
			}
			if ((cch = IsSwitch(TEXT("64"), p)))
			{
				if (native32)
				{
					allowWinDirFallback = false;
					reqMachine = IMAGE_FILE_MACHINE_AMD64;
				}
				p += cch;
				continue;
			}
			if ((cch = IsSwitch(TEXT("32"), p)))
			{
				req32++;
				p += cch;
				continue;
			}
			if ((cch = IsSwitch(TEXT("x86"), p)) || (cch = IsSwitch(TEXT("i386"), p)))
			{
				reqMachine = IMAGE_FILE_MACHINE_I386;
				p += cch;
				continue;
			}
			if ((cch = IsSwitch(TEXT("ARM"), p)) || (cch = IsSwitch(TEXT("ARM32"), p)))
			{
				reqMachine = IMAGE_FILE_MACHINE_ARMNT;
				p += cch;
				continue;
			}
		}

		if (*p)
		{
			static const char msg[] = ""
				"StartRegedit v0.2" "\n" 
				"Copyright (C) Anders Kjersem" "\n"
				"" "\n"
				"Usage: [/NoElevate] [/Maximized] [/32|/x86|/ARM]";
			GetProcAddr<INT(WINAPI*)(HWND,LPCSTR,LPCSTR,UINT)>("USER32", "MessageBoxA")(0, msg, "Help/About", MB_OK|MB_ICONINFORMATION);
			ExitProcess(ERROR_CANCELLED);
		}
		break;
	}

	SetEnvironmentVariableA("__COMPAT_LAYER", lua ? "RunAsInvoker" : NULL);

	if (req32)
	{
#ifdef _WIN64
		if (GetSystemWow64Directory2(buf, cchMaxSysDir, IMAGE_FILE_MACHINE_ARMNT))
			reqMachine = IMAGE_FILE_MACHINE_ARMNT;
		else
#endif
			reqMachine = IMAGE_FILE_MACHINE_I386;
	}

	if (reqMachine)
	{
		cch = GetSystemWow64Directory2(buf, cchMaxSysDir, reqMachine);
		if (!cch && allowWinDirFallback) goto useWinDir;
	}
	else useWinDir:
	{
#ifndef _WIN64
		Wow64EnableWow64FsRedirection(false);
#endif
		cch = GetSystemWindowsDirectory(buf, cchMaxSysDir);
	}

	if (cch >= cchMaxSysDir)
	{
		ec = ERROR_FILENAME_EXCED_RANGE; // Should never happen, the system directory will always fit in MAX_PATH.
	}
	else if (!cch)
	{
		ec = GetLastError();
		if (!ec) ec = ERROR_NOT_SUPPORTED;
	}
	else
	{
		if (buf[cch-1] != '\\') buf[cch++] = '\\';
		lstrcpy(buf+cch, TEXT("RegEdit.exe"));
		LPCTSTR verb = high ? TEXT("RunAs") : NULL;
		LPCTSTR parameters = TEXT("-m");
		HINSTANCE hExec = ShellExecute(NULL, verb, buf, parameters, NULL, showCmd);
		ec = (SIZE_T) hExec > 32 ? ERROR_SUCCESS : GetLastError();
	}

	ExitProcess(ec);
}
