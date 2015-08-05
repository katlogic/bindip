#include "common.h"
#include <stdio.h>

static HKEY registry, ifreg; // Config registry, system interface registry
static char myname[MAX_PATH]; // My exe name, without path
static struct helper { // Linked list of helper pages
	struct helper *next;
	BYTE *bytes; // pointer to current b
	BYTE b[0]; // Helper thunk opcodes
} *helpers;

// Hooked APIs
static int (__stdcall *orig_wsh)(void *d, struct sockaddr_in *a, int *l);
static int (__stdcall *orig_bind)(SOCKET,const struct sockaddr_in *,int);
static int (__stdcall *orig_connect)(SOCKET,const struct sockaddr_in *,int);
static DWORD __stdcall (*orig_cpiw)(DWORD, WCHAR*, WCHAR*, void *, void *, BOOL, DWORD,
void *, WCHAR *, STARTUPINFOW *, PROCESS_INFORMATION *, DWORD);

// Helpers to disable/enable wow64 path translation
#ifndef __amd64__
static int (__stdcall *wow64)(HANDLE, BOOL *);
static BOOL (__stdcall *_wow64_disable)(void **old);
static BOOL (__stdcall *_wow64_enable)(void *old);
__declspec(dllexport)
BOOL wow64_enable(void *a)
{
	if (_wow64_enable)
		return _wow64_enable(a);
	return FALSE;
}
__declspec(dllexport)
BOOL wow64_disable(void **a)
{
	if (_wow64_disable)
		return _wow64_disable(a);
	return FALSE;
}
#else // In 64bit these are always available
#define wow64 IsWow64Process
#define wow64_enable Wow64RevertWow64FsRedirection
#define wow64_disable Wow64DisableWow64FsRedirection
#endif

// aliased imports under different name to avoid header conflicts, see dll.def
__declspec(dllimport) void wshwildcard();
__declspec(dllimport) void wsbind();
__declspec(dllimport) void wsconnect();
__declspec(dllimport) void k32ll();
__declspec(dllimport) DWORD __stdcall ntapc(HANDLE,void*,void*,long,long);

// detour `p` to `dst`, save original to `orig`
// return 0 on failure
static int detour(void *p, void *dst, void **orig)
{
	struct helper *h;
	BYTE *helper;
	BYTE *pp = (BYTE*)p;
	DWORD oldprot;
	int pro, i, j;
	// Rather than full disassembler, we recognize only common prologues
	// First byte is sequence length, 0 is wildcard
	static BYTE prologues[][6] = {
		{ 5, 0x4c, 0x8b, 0xdc, 0x53, 0x56 }, // mov r11, rsp; push rbx; push rsi
		{ 5, 0xff, 0xf3, 0x56, 0x41, 0x54 }, // push rbx; purh rsi; push r12
		{ 5, 0xb8 },      // mov eax, N
		{ 5, 0x48, 0x89 }, // mov [rsp+N], rbx
		{ 2, 0x6a },	  // push 8bit
		{ 5, 0x68 },	  // push 32bit
#ifndef __amd64__
		{ 2, 0x8b, 0xff }, // xor edi, edi
#endif
		{ 0 }
	};
	for (i = 0; prologues[i][0]; i++) {
		for (j = 1; j < 6; j++) {
			if (prologues[i][j] && (prologues[i][j] != pp[j-1]))
				goto skip;
		}
		break;
skip:;
	}

	// Prologue length
	pro = prologues[i][0];
	if (!pro)
		return 0;
	// Unprotect function
	if (!VirtualProtect(pp-5,5+5,PAGE_EXECUTE_READWRITE,&oldprot))
		return 0;

	// Find a helper page near to our jump target
#ifdef __amd64__
	ULONG_PTR cur, high, low = (((ULONG_PTR)p)&0xfffffffffff00000ULL);
	if (low < 0x40000000ULL)
		low = 0;
	else
		low -= 0x40000000ULL;
	high = low + 0xb0000000ULL;
	for (h = helpers; h; h = h->next) {
		if ((((ULONG_PTR)h) >= low) && ((ULONG_PTR)h) < high)
			goto found;
	}
	do {
		h = VirtualAlloc((void*)low,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
		low += 0x100000;
	} while (!h && low < high);
	if (!h) return 0;
	h->next = helpers;
	h->bytes = h->b;
	helpers = h;
found:;
	helper = h->bytes;
	// Now create thunk which jumps to our routine
	DWORD_PTR addr = (DWORD_PTR)dst;
	*helper++ = 0x68; // push qword 0xlow
	(*(DWORD*)helper) = addr;
	helper += 4;
	*helper++ = 0x67;
	*helper++ = 0xc7;
	*helper++ = 0x44;
	*helper++ = 0x24;
	*helper++ = 0x04;
	(*(DWORD*)helper) = addr >>= 32; // mov dword [esp+0x4],0xhigh
	helper += 4;
	*helper++ = 0xc3; // and "return"
#else
	h = helpers;
	helper = h->bytes;
	*helper++ = 0xe9;
	helper += 4;
	*((DWORD*)(helper-4)) = (BYTE*)dst - helper;
#endif
	// Orig is secondary helper - the overwritten instruction and jump back
	// to rest of the function body
	*orig = helper;
	// Copy the opcode into invoke helper
	CopyMemory(helper, p, pro);
	helper += pro;
	// and jump to original
	*helper++ = 0xe9;
	helper += 4;
	*((DWORD*)(helper-4)) = (BYTE*)(p+pro) - helper;
	// save back the helper pointer
	// Finally, patch the function.
	if (pro == 2) {
		// must be hotpatch nops
		if (pp[-5] != 0x90)
			return 0;
		// the jump in nops to helper
		pp[-5] = 0xe9;
		*((DWORD*)(pp-4)) = h->bytes - pp;
		// and finally overwrite the prologue
		pp[0] = 0xeb;
		pp[1] = (BYTE)-7;
	} else if (pro == 5) {
		// Enough room, write jump directly
		pp[0] = 0xe9;
		*((DWORD*)(pp+1)) = h->bytes - (pp+5);
	}
	h->bytes = helper;
	return 1;
}

// Try to get current ip for given exe name
long get_name_config(char *name)
{
	HKEY reg2;
	char ipbuf[64];
	char ifname[512];
	DWORD len = sizeof(ifname);
	DWORD ilen = sizeof(ipbuf);
	if (RegQueryValueEx(registry, name, NULL, NULL, (LPBYTE)ifname, &len))
		return 0;
	ipbuf[0] = 0;
	// Maintain the env so that children processes can look it up
	SetEnvironmentVariable("BINDIP_IF", ifname);
	// Look up ip address of interface then
	RegOpenKeyExA(ifreg, ifname, 0, KEY_READ, &reg2);
	if (RegQueryValueExA(reg2, "DhcpIPAddress", NULL, NULL, (LPBYTE)ipbuf, &ilen)!=ERROR_SUCCESS) {
		ilen = sizeof(ipbuf);
		// Maybe it's static config
		RegQueryValueExA(reg2, "IPAddress", NULL, NULL, (LPBYTE)ipbuf, &ilen);
	}
	RegCloseKey(reg2);
	// We have some result
	if (ipbuf[0])
		return inet_addr(ipbuf);
	return 0;
}

// Return configured ip (cached for frequent access)
static unsigned long cached_ip(unsigned long orig)
{
	static int last_cache = (int)0x80000000;
	static unsigned long cip;
	int now = GetTickCount();

	// If binding to localhost, let it be.
	if ((cip&0xff) == 0x7f)
		return orig;

	// Ping registry every 2 seconds
	if (last_cache < now) {
		char myname2[MAX_PATH];
		last_cache = now + 2000;
		if ((!(cip=get_name_config(myname))) && GetEnvironmentVariable("BINDIP_EXE", myname2, sizeof(myname)))
			cip=get_name_config(myname2);
	}
	return cip?cip:orig;
}

// Force socket address on 'dst'
static const struct sockaddr_in *fill_sin(struct sockaddr_in *dst, const struct sockaddr_in *src)
{
	// Not for us
	if (src->sin_family != AF_INET)
		return src;
	dst->sin_addr.s_addr = cached_ip(dst->sin_addr.s_addr);
	return dst;
}

// bind() hook
static int __stdcall my_bind(SOCKET sk, const struct sockaddr_in *a,int l)
{
	struct sockaddr_in copy = *a;
	return orig_bind(sk,fill_sin(&copy, a),l);
}

// connect() hook
static int __stdcall my_connect(SOCKET sk, const struct sockaddr_in *a,int l)
{
	// Connecting to localhost? In that case bind it first.
	if ((a->sin_family == AF_INET) && ((a->sin_addr.s_addr&0xff)==0x7f)) {
		struct sockaddr_in copy = *a;
		copy.sin_port = 0;
		orig_bind(sk, &copy, l);
	}
	return orig_connect(sk,a,l);
}


// this covers everything not actually using bind
static int __stdcall my_wsh(void *d, struct sockaddr_in *a, int *l)
{
	int ret = orig_wsh(d,a,l);
	if (!ret) fill_sin(a,a);
	return ret;
}

// queue LoadLibraryA apc call, with argument data
static BOOL inject_apc(HANDLE hp, void *data)
{
	return ntapc(hp,(void*)k32ll, data, 0, 0)==0;
}

// rundll32 wrapper for QeueuUserAPC
__declspec(dllexport) BOOL __cdecl apc(HWND hwnd, HINSTANCE hinst, LPSTR cmd, int show)
{
	// Wait for caller to send us process handle
	MSG msg;
	GetMessageA(&msg, NULL, WM_USER, WM_USER);
	return inject_apc((HANDLE)msg.wParam, (void*)msg.lParam);
}

// inject dll32/dll64 into specified process hp/ht
#ifndef __amd64__
#define B64 0
#else
#define B64 1
#endif
static
void inject(HANDLE hp, HANDLE ht, char *dll32, int len32)
{
	SIZE_T wrote;
	BOOL x86, emu = 0;
	void *pmem;
	pmem = VirtualAllocEx(hp, NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pmem) return;
	if (!WriteProcessMemory(hp, pmem, dll32, len32 + strlen(dll32+len32), &wrote))
		return;
#ifndef __amd64__
	if (wow64)
#endif
		wow64(hp, &emu);
	x86 = (!win64())||emu;
	// We're 64bit, but the target process is 32bit, or vice-versa
	if (((B64 && x86) || ((!B64) && (!x86)))) {
		HANDLE hv = NULL;
		void *old = NULL;
		STARTUPINFO si = {0};
		PROCESS_INFORMATION pi = {0};
		si.cb = sizeof(si);
		char exe[MAX_PATH], buf[MAX_PATH];
		wow64_disable(&old);
		SHGetSpecialFolderPathA(NULL, buf, B64?CSIDL_SYSTEMX86:CSIDL_SYSTEM, 0);
		wnsprintf(exe, sizeof exe, "%s\\rundll32.exe %s,apc", buf, B64?dll32:(dll32+len32));
		SetEnvironmentVariableA("BINDIP_CHAINHOOK", NULL); // Do not inject rundll
		CreateProcessA(NULL, exe, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
		WaitForInputIdle(pi.hProcess, INFINITE); // sync with GetMessage
		DuplicateHandle(GetCurrentProcess(), ht, pi.hProcess, &hv, 0, FALSE, DUPLICATE_SAME_ACCESS);
		PostThreadMessage(pi.dwThreadId, WM_USER,(WPARAM)hv, (LPARAM)(pmem+(B64?0:len32)));
		WaitForSingleObject(pi.hProcess, INFINITE);
		DWORD ecode;
		GetExitCodeProcess(pi.hProcess, &ecode);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		wow64_enable(old);
	} else { // It's the same, queue apc directly
		inject_apc(ht, pmem+(x86?0:len32));
	}
}

// hijack CreateProcessInternalW
__declspec(dllimport) void cpiw();
DWORD __stdcall my_cpiw(DWORD unk1, WCHAR *exe, WCHAR *args, void *attr1, void *attr2,
BOOL inh, DWORD flags, void *env, WCHAR *cwd, STARTUPINFOW *si, PROCESS_INFORMATION *pi, DWORD unk2)
{
	// TBD: what about env?
	int dohook;
	DWORD ok, pflags = flags;
	char dlls[MAX_PATH*2];
	int len32=0;
	dohook = GetEnvironmentVariableA("BINDIP_CHAINHOOK", dlls, sizeof(dlls));
	if (dohook) {
		while (dlls[len32] && (dlls[len32++] != ';')) {};
		if (!dlls[len32])
			dohook = 0;
	}
	if (dohook)
		flags |= CREATE_SUSPENDED;
	ok = orig_cpiw(unk1, exe, args, attr1, attr2, inh, flags, env, cwd, si, pi, unk2);
	if (dohook && ok) {
		dlls[len32-1] = 0;
		inject(pi->hProcess, pi->hThread, dlls, len32);
		// Original user didn't want suspend
		if (flags != pflags)
			ResumeThread(pi->hThread);
		dlls[len32-1] = ';';
		// Inject unsets it
		SetEnvironmentVariableA("BINDIP_CHAINHOOK", dlls);
	}
	return ok;
}

// Initialize CreateProcess chain hook
__declspec(dllexport)
void cpiw_init()
{
	static int done;
	if (!done) {
		done = 1;
		detour(cpiw, &my_cpiw, (void**)&orig_cpiw);
	}
}

BOOL __stdcall DllMain(HINSTANCE hinst, DWORD why, LPVOID v)
{
	switch (why) {
	case DLL_PROCESS_ATTACH: {
#ifndef __amd64__
		HMODULE k = GetModuleHandle("KERNEL32");
		wow64 = GetProcAddress(k, "IsWow64Process");
		_wow64_enable = (void*)GetProcAddress(k,"Wow64RevertWow64FsRedirection");
		_wow64_disable = (void*)GetProcAddress(k,"Wow64DisableWow64FsRedirection");
		// In 32 bit we can jump full range, just create single page helper
		helpers = VirtualAlloc((void*)0,4096,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
		if (!helpers) return TRUE;
		helpers->bytes = helpers->b;
#endif
		// Do this once
		GetModuleFileName(NULL, myname, sizeof(myname));
		PathStripPathA(myname);

		if (GetEnvironmentVariableA("BINDIP_CHAINHOOK", NULL, 0)) {
			cpiw_init();
			// No name defined yet, use currently running
			if (!GetEnvironmentVariableA("BINDIP_EXE", NULL, 0))
				SetEnvironmentVariableA("BINDIP_EXE", myname);
		}

		// Only bother if we can access the registry
		if ((!RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\BindIP\\Mapping", 0, KEY_READ, &registry)) &&
			!RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\Interfaces", 0, KEY_READ, &ifreg)) {
			int a =
			detour(wshwildcard, &my_wsh, (void**)&orig_wsh);
			// These two are weak bindings, mainly to deal with 127.0.0.1
			int b =
			detour(wsbind, &my_bind, (void**)&orig_bind);
			int c =
			detour(wsconnect, &my_connect, (void**)&orig_connect);
		}
		break;
	}
	case DLL_PROCESS_DETACH:
		if (registry) RegCloseKey(registry);
		if (ifreg) RegCloseKey(ifreg);
		break;
	}
	return TRUE;
}

