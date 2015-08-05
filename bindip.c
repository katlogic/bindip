#include "common.h"
#include "resource.h"

static HKEY registry;
static IP_ADAPTER_INFO adapters[256];
#if 0
static BOOL (*wow64_disable)(void **old);
static BOOL (*wow64_enable)(void *old);
#endif

__declspec(dllimport) BOOL wow64_disable(void **old);
__declspec(dllimport) BOOL wow64_enable(void *old);

// add unique list item
static void adduniq(HWND list, char *s)
{
	// dont add duplicate names and empty strings
	if (!s[0]) return;
	if (SendMessage(list, LB_FINDSTRINGEXACT, 0, (LPARAM)s)==LB_ERR)
		SendMessage(list, LB_ADDSTRING, 0, (LPARAM)s);
}

// enumerate running processes and add to the list
static void enumproc(HWND list)
{
	int i,t;
	char subname[MAX_PATH];
	DWORD subsize = sizeof(subname);
	PROCESSENTRY32 lpe;
	lpe.dwSize = sizeof(lpe);
	for (i=0;(t=RegEnumValue(registry, i, subname, &subsize, NULL, NULL, NULL, NULL))==ERROR_SUCCESS;i++,subsize=sizeof(subname))
		adduniq(list, subname);
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	BOOL entry = Process32First(snap, &lpe);
	while (entry) {
		if (PathMatchSpec(lpe.szExeFile, "*.exe"))
			adduniq(list, lpe.szExeFile);
		lpe.dwSize = sizeof(lpe);
		entry = Process32Next(snap, &lpe);
	}
	CloseHandle(snap);
}

// add network interfacess to list
static void enumintf(HWND list)
{
	IP_ADAPTER_INFO *ada;
	adduniq(list, "(default route)");
	for (ada = adapters; ada; ada = ada->Next)
		adduniq(list, ada->Description);
}

// react to user clicks in exe/intf list boxes
// il=1 if clicked on interface list
static void process_selections(HWND parent, HWND exe, HWND intf, int il)
{
	static int sels[16384];
	static TCHAR buf[512], buf2[512];
	IP_ADAPTER_INFO *ada, *curada = NULL;
	long nsel;
	int i, j, curif = -1;
	// Clicked on exelist, go through selected exes
 	nsel = SendMessage(exe, LB_GETSELITEMS, 16384, (LPARAM)sels);
	if (!il) for (i = 0; i < nsel; i++) {
		DWORD len = sizeof(buf2);
		SendMessage(exe, LB_GETTEXT, sels[i], (LPARAM)buf);
		if (RegQueryValueEx(registry, buf,NULL,NULL, (LPBYTE)buf2, &len)!=ERROR_SUCCESS) {
			// undefined key -> no adapter, default route, shortcut
			curif = 0;
			curada = NULL;
			break;
		}
		// and check they have all interfaces in common
		for (j = 1, ada = adapters; ada; ada = ada->Next, j++)
		 if (!strcmp(ada->AdapterName, buf2)) {
			// mismatch in selected group -> reset default route
			if (curif >= 0 && curif != j) {
				curif = 0;
				curada = NULL;
				goto out;
			}
			// otherwise keep as current interface
			curif = j;
			curada = ada;
			break;
		}
	}
out:;
	if (!il) {
		// clicked exe list
		if (curif < 0) curif = 0;
		SendMessage(intf, LB_SETCURSEL, curif, 0);
	} else {
		// clicked interface list
		curif = SendMessage(intf, LB_GETCURSEL,0,0);
		// resolve index to name
		for (i = curif, ada = adapters; ada && i--; ada = ada->Next)
			curada = ada;
	}
	// in curif we have corresponding interface index, 0 if default
	// in curada we have interface, null if default
	// in sels[] we have exes this aplies to
	for (i = 0; i < nsel; i++) {
		SendMessage(exe, LB_GETTEXT, sels[i], (LPARAM)buf);
		if (curif > 0) { // assign new interface
			RegSetValueExA(registry, buf, 0, REG_SZ, (LPBYTE)curada->AdapterName, strlen(curada->AdapterName)+1);
		} else { // no interface, delete it
			RegDeleteValue(registry, buf);
		}
	}
	strcpy(buf, "Default interface");
	strcpy(buf2, "Default source ip");
	if (curif > 0 && curada) {
		BYTE *mac = curada->Address;
		char *pip = curada->IpAddressList.IpAddress.String;
		wnsprintf(buf, sizeof(buf), "%02x-%02x-%02x-%02x-%02x-%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		strcpy(buf2, pip);
	}
	SendMessage(GetDlgItem(parent, IDC_MAC), WM_SETTEXT, 0, (LPARAM)buf);
	SendMessage(GetDlgItem(parent, IDC_IP), WM_SETTEXT, 0, (LPARAM)buf2);
}

static int check_system_dlls(char *buf, int len32)
{
	return !(GetFileAttributesA(buf) == INVALID_FILE_ATTRIBUTES || GetFileAttributesA(buf+len32) == INVALID_FILE_ATTRIBUTES);
}

// locate dlls in system directory
static int get_system_dlls(char *buf)
{
	int len32;
	void *sav=NULL;
	wow64_disable(&sav);
	if (!SHGetSpecialFolderPathA(NULL, buf, CSIDL_SYSTEMX86, 0))
		SHGetSpecialFolderPathA(NULL, buf, CSIDL_SYSTEM, 0);
	strcat(buf, "\\bindip.dll");
	len32 = strlen(buf)+1;
	SHGetSpecialFolderPathA(NULL, buf + len32, CSIDL_SYSTEM, 0);
	strcat(buf + len32, "\\bindip.dll");
	wow64_enable(sav);
	return len32;
}

// locate dlls in all places
static int locate_dlls(char *buf, int sys)
{
	char tbuf[MAX_PATH];
	int i,len32 = 0;
	void *sav=NULL;
	wow64_disable(&sav);
	if (sys) {
		len32 = get_system_dlls(buf);
		if (check_system_dlls(buf, len32))
			goto out;
	}
	for (i = 0; i < 3; i++) {
		switch(i) {
			case 0:
				ExpandEnvironmentStringsA("%PROGRAMFILES(X86)%\\BindIP", tbuf, sizeof(tbuf));
				break;
			case 1:
				ExpandEnvironmentStringsA("%PROGRAMFILES%\\BindIP", tbuf, sizeof(tbuf));
				break;
			case 2:
				GetModuleFileNameA(NULL, tbuf, sizeof(tbuf));
				PathRemoveFileSpecA(tbuf);
				break;
		}
		len32 = wnsprintf(buf, 2048, "%s\\bindip.dll", tbuf)+1;
		wnsprintf(buf + len32, 2048, "%s\\64\\bindip.dll", tbuf);
		if (GetFileAttributesA(buf) != INVALID_FILE_ATTRIBUTES || GetFileAttributesA(buf+len32) != INVALID_FILE_ATTRIBUTES)
			goto out;
	}
out:;
	wow64_enable(sav);
	return len32;
}

// configure global filter winsock
static int dll_config(int enable, int complain)
{
	HKEY reg;
	char buf[MAX_PATH*2], buf2[MAX_PATH*2];
	static char const orig[] = "%SystemRoot%\\System32\\wshtcpip.dll";
	DWORD buf2len, buflen = sizeof buf;
	int e;
	void *sav=NULL;
	if ((e=RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\Winsock", 0, KEY_ALL_ACCESS, &reg))) {
		if (complain)
			MessageBoxA(NULL, "Can't open registry for writing, run BindIP as admin (right click, 'Run as administrator')", serre(e), MB_ICONERROR|MB_OK);
		return 0;
	}
	wow64_disable(&sav);
	if (RegQueryValueExA(reg, "HelperDllName", 0, NULL, (BYTE*)buf, &buflen)) {
		enable = 0;
		goto out;
	}
	if (!strcmp(buf+buflen-11, "bindip.dll")) {
		if (enable) {
			enable = 1;
			goto out;
		}
		// request to disable
		buflen=sizeof(orig);
		if (RegSetValueExA(reg, "HelperDllName", 0, REG_EXPAND_SZ, (BYTE*)orig, buflen)) {
			enable = 1; // Failed to disable..
		} else { // Disabled, delete dlls too
			buflen = get_system_dlls(buf);
			DeleteFile(buf);
			DeleteFile(buf+buflen);
		}
	} else if (enable == 1) {
		enable = 0;
		// request to enable
		buflen = get_system_dlls(buf);
		if (!check_system_dlls(buf, buflen)) {
			buf2len = locate_dlls(buf2, 0);
			CopyFile(buf2+buf2len, buf+buflen, FALSE);
			CopyFile(buf2, buf, FALSE);
			// Re-check that the files are ok now
			if (!check_system_dlls(buf, buflen))
				goto out;
		}
		enable = !RegSetValueExA(reg, "HelperDllName", 0, REG_EXPAND_SZ, (BYTE*)buf+buflen, strlen(buf+buflen)+1);
	} else enable = 0; // Otherwise disabled
out:
	RegCloseKey(reg);
	wow64_enable(sav);
	return enable;
}

// configure shell button registry
// -1 - just query status
static int shell_config(int enable)
{
	HKEY reg, reg2;
	RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Classes\\exefile\\shell", 0, KEY_ALL_ACCESS, &reg);
	if (enable == -1) {
		if (RegQueryValue(reg, "Open with BindIP", NULL, NULL)==ERROR_SUCCESS)
			enable = 1;
		else
			enable = 0;
	} else if (enable == 1) {
		char myname[MAX_PATH];
		char pbuf[MAX_PATH];
		GetModuleFileName(NULL, myname, sizeof(myname));
		RegCreateKeyExA(reg, "Open with BindIP\\command", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &reg2, NULL);
		enable = !RegSetValueExA(reg2, NULL, 0, REG_SZ, (BYTE*)pbuf,wnsprintf(pbuf, sizeof(pbuf), "\"%s\" \"%%1\"", myname)+1);
		RegCloseKey(reg2);
	}
	if (enable == 0)
		SHDeleteKeyA(reg, "Open with BindIP");
	RegCloseKey(reg);
	return enable;
}


// dialog handler
static INT_PTR CALLBACK dialog_wproc(HWND dlg, UINT msg, WPARAM w, LPARAM l)
{
	HWND exe = GetDlgItem(dlg, IDC_EXELIST);
	HWND intf = GetDlgItem(dlg, IDC_INTLIST);
	int il = 0;
	switch (msg) {
	case WM_INITDIALOG:
		enumproc(exe);
		enumintf(intf);
	
		Button_SetCheck(GetDlgItem(dlg, IDC_SHELL), shell_config(-1));
		Button_SetCheck(GetDlgItem(dlg, IDC_APPINIT), dll_config(-1,0));
		SetFocus(exe);
		SendMessage(exe, LB_SETSEL, TRUE, 0);
		process_selections(dlg,exe,intf, 0);
		return TRUE;
	case WM_CLOSE:
		EndDialog(dlg, 0);
		return TRUE;
	case WM_COMMAND: switch (LOWORD(w)) {
	case IDC_REFRESH:
		enumproc(exe);
		return TRUE;
	case IDC_DONE:
		EndDialog(dlg, 0);
		return TRUE;
	case IDC_INTLIST:
		il = 1;
	case IDC_EXELIST:
		if (HIWORD(w) == LBN_SELCHANGE)
			process_selections(dlg, exe,intf,il);
		return TRUE;
	case IDC_ADD: {
		char filebuf[MAX_PATH];
		filebuf[0] = 0;
		OPENFILENAME ofn = {
			.lStructSize = sizeof(OPENFILENAME),
			.hwndOwner = dlg,
			.lpstrFile = filebuf,
			.nMaxFile = sizeof(filebuf),
			.lpstrFilter = "EXE\0*.exe\0COM\0*.com\0SCR\0*.scr\0",
		};
		if (GetOpenFileName(&ofn)) {
			PathStripPathA(filebuf);
			adduniq(exe, filebuf);
			SendMessage(exe, LB_SETSEL, FALSE, (LPARAM)-1);
			SendMessage(exe, LB_SETSEL, TRUE, SendMessage(exe, LB_FINDSTRINGEXACT, 0, (LPARAM)filebuf));
			SetFocus(exe);
			process_selections(dlg,exe,intf, 0);
		}
		return TRUE;
	}
	case IDC_SHELL:
		Button_SetCheck(GetDlgItem(dlg, IDC_SHELL), shell_config(Button_GetCheck(GetDlgItem(dlg, IDC_SHELL))));
		return TRUE;
	case IDC_URL:
		ShellExecute(NULL, "open", "http://lua.cz/bindip/1", NULL, NULL, SW_SHOWNORMAL);
		return TRUE;
	case IDC_APPINIT:
		Button_SetCheck(GetDlgItem(dlg, IDC_APPINIT), dll_config(Button_GetCheck(GetDlgItem(dlg, IDC_APPINIT)),1));
		return TRUE;

	} // WM_COMMAND
	} // msg
	return FALSE;
}

__declspec(dllimport) char *inject(HANDLE hp, HANDLE ht, char *dll32, int len32);
__declspec(dllimport) void cpiw_init();
static void run_preloaded(WCHAR *cmd)
{
	DWORD ecode = 0;
	char dlls[MAX_PATH*2];
	STARTUPINFOW si = {0};
	PROCESS_INFORMATION pi = {0};
	int len32 = locate_dlls(dlls, 0);

	if (len32) {
		// Triggers our patched CreateProcessInternal
		dlls[len32-1] = ';';
		SetEnvironmentVariable("BINDIP_CHAINHOOK", dlls);
		cpiw_init(); // Patch createprocess
	}

	si.cb = sizeof(si);
	// Pass console handles
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	// Spawn
	if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		MessageBoxA(NULL, serr(), "CreateProcess", MB_ICONERROR|MB_OK);
		goto err;
	}

	if (WaitForInputIdle(pi.hProcess, INFINITE) == WAIT_FAILED) {
		// Console process, setup break handler
		WaitForSingleObject(pi.hProcess, INFINITE);
		GetExitCodeProcess(pi.hProcess, &ecode);
	} else {
		// GUI app, close console
		FreeConsole();
	}
err:;
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	ExitProcess(ecode);
}


void winMain()
{
	// Skip over exe name
	WCHAR *cmd = GetCommandLineW();
	int quot = *cmd++ == L'"';
	while (*cmd && (quot || (cmd[0]>L' ')))
		if (*cmd++ == L'"')
			quot ^= 1;
	while (*cmd && *cmd<= L' ')
		cmd++;

	// Request to launch specified program
	//static WCHAR fake[MAX_PATH] = L"nc.exe -h";
	//cmd = fake;
	if (*cmd) {
		run_preloaded(cmd);
	} else {
		ULONG len = sizeof(adapters);
		DWORD disp;
		// Otherwise gui
		FreeConsole();
		RegCreateKeyEx(HKEY_CURRENT_USER, "Software\\BindIP\\Mapping", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &registry, &disp);
		if (disp == REG_CREATED_NEW_KEY) {
			// Run for the first time - enable shell, delete system dlls if possible
			shell_config(1);
			dll_config(0, 0);
		} else if (shell_config(-1)) // Shell enabled, re-enable again to update exe path in registry
			shell_config(1);
		GetAdaptersInfo(adapters, &len);
		// And fire up dialog
		DialogBox(NULL, MAKEINTRESOURCE(IDD_FORMVIEW), NULL, dialog_wproc);
		RegCloseKey(registry);
	}
	ExitProcess(0);
}

