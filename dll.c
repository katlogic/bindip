#include "common.h"

static HKEY registry, ifreg; // Config registry, system interface registry
static BYTE *helpers; // Detour helper routines constructed on the fly
static int (__stdcall *orig_wsh)(void *d, struct sockaddr_in *a, int *l);
static int (__stdcall *orig_bind)(SOCKET,const struct sockaddr_in *,int);

// detour `p` to `dst`, save original to `orig`
// return 0 on failure
static int detour(void *p, void *dst, void **orig)
{
	BYTE *pp = (BYTE*)p;
	BYTE *dhelp = helpers;
	DWORD oldprot;
	int pro;
	if (!VirtualProtect(pp-5,5+5,PAGE_EXECUTE_READWRITE,&oldprot))
		return 0;
	if (pp[0] == 0x48 && pp[1] == 0x89)
		// mov rsp, [rsp+...]
		pro = 5;
	else if ((pp[0] == 0x6a)||(pp[0]==0x8b&&pp[1]==0xff))
		// prologue of 2 bytes
		pro = 2;
	else return 0;
	// And append jump to C
#if __amd64__
	DWORD_PTR addr = (DWORD_PTR)dst;
	*helpers++ = 0x68; // push qword 0xlow
	(*(DWORD*)helpers) = addr;
	helpers += 4;
	*helpers++ = 0x67;
	*helpers++ = 0xc7;
	*helpers++ = 0x44;
	*helpers++ = 0x24;
	*helpers++ = 0x04;
	(*(DWORD*)helpers) = addr >>= 32; // mov dword [esp+0x4],0xhigh
	helpers += 4;
	*helpers++ = 0xc3; // and "return"
#else
	*helpers++ = 0xe9;
	helpers += 4;
	*((DWORD*)(helpers-4)) = (BYTE*)dst - helpers;
#endif
	*orig = helpers;
	// Copy the opcode into invoke helper
	CopyMemory(helpers, p, pro);
	helpers += pro;
	// and jump to original
	*helpers++ = 0xe9;
	helpers += 4;
	*((DWORD*)(helpers-4)) = (BYTE*)(p+pro) - helpers;
	// Finally, patch the function.
	if (pro == 2) {
		// must be hotpatch nops
		if (pp[-5] != 0x90)
			return 0;
		// the jump in nops to helper
		pp[-5] = 0xe9;
		*((DWORD*)(pp-4)) = dhelp - pp;
		// and finally overwrite the prologue
		pp[0] = 0xeb;
		pp[1] = (BYTE)-7;
	} else if (pro == 5) {
		// Enough room, write jump directly
		pp[0] = 0xe9;
		*((DWORD*)(pp+1)) = dhelp - (pp+5);
	}
	return 1;
}

// Return configured ip (cached for frequent access)
static unsigned long cached_ip()
{
	static int last_cache = (int)0x80000000;
	static unsigned long cip;
	int now = GetTickCount();

	// Ping registry every 2 seconds
	if (last_cache < now) {
		char myname[MAX_PATH];
		char ifname[512];
		DWORD len = sizeof(ifname);
		last_cache = now + 2000;
		GetModuleFileName(NULL, myname, sizeof(myname));
		PathStripPathA(myname);
		// Is it configured?
		if (RegQueryValueEx(registry, myname, NULL, NULL, (LPBYTE)ifname, &len)==ERROR_SUCCESS) {
			HKEY reg2;
			char ipbuf[64];
			DWORD ilen = sizeof(ipbuf);
			ipbuf[0] = 0;
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
				cip = inet_addr(ipbuf);
		}
	}
	return cip;
}

// Force socket address on 'dst'
static const struct sockaddr_in *fill_sin(struct sockaddr_in *dst, const struct sockaddr_in *src)
{
	// Not for us
	if (src->sin_family != AF_INET)
		return src;
	dst->sin_addr.s_addr = cached_ip();
	return dst;
}

// bind() hook
static int __stdcall my_bind(SOCKET sk, const struct sockaddr_in *a,int l)
{
	struct sockaddr_in copy = *a;
	return orig_bind(sk,fill_sin(&copy, a),l);
}

// this covers everything not actually using bind
static int __stdcall my_wsh(void *d, struct sockaddr_in *a, int *l)
{
	int ret = orig_wsh(d,a,l);
	if (!ret) fill_sin(a,a);
	return ret;
}

__declspec(dllimport) void wshwildcard();
__declspec(dllimport) void wsbind();

BOOL __stdcall DllMain(HINSTANCE hinst, DWORD why, LPVOID v)
{
	switch (why) {
	case DLL_PROCESS_ATTACH: {
#ifdef __amd64__
		// Scan the address space for place nearby
		DWORD_PTR w = (DWORD_PTR)wshwildcard;
		DWORD_PTR b = (DWORD_PTR)wsbind;
		DWORD_PTR limit, m = w<b?w:b;
		limit = m + 0x80000000;
		m -= 0x70000000;
		m &= 0xfffffffffff00000ULL;
		do {
			helpers = VirtualAlloc((void*)m,4096,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
			m += 0x100000;
		} while (!helpers && m < limit);
		// Without helpers exit early, there is not much we can do
		if (!helpers) return TRUE;
#else
		// In 32 bit we can jump full range
		helpers = VirtualAlloc((void*)0,4096,MEM_COMMIT,PAGE_EXECUTE_READWRITE);
#endif
		detour(wshwildcard, &my_wsh, (void**)&orig_wsh);
		detour(wsbind, &my_bind, (void**)&orig_bind);
		RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\BindIP\\Mapping", 0, KEY_READ, &registry);
		RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\Interfaces", 0, KEY_READ, &ifreg);
		break;
	}
	case DLL_PROCESS_DETACH:
		RegCloseKey(registry);
		RegCloseKey(ifreg);
		break;
	}
	return TRUE;
}

