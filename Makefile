# You need mingw64 to compile this

# Change to wherever your system dlls are
WIN32PATH=/c/Windows/SysWOW64
WIN64PATH=/c/Windows/system32

all: bindip.exe bindip32.dll bindip64.dll
release:
	strip *.exe *.dll
	mkdir -p bindip
	cp bindip.exe bindip32.dll bindip64.dll bindip
	zip -r bindip.zip bindip
	candle bindip.wxs -out bindip.wixobj
	light bindip.wixobj -out bindip.msi

CFLAGS=-Wall -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -fno-asynchronous-unwind-tables
LDFLAGS=-Wl,--enable-stdcall-fixup -lws2_32 -lADVAPI32 -lkernel32 -lUSER32 -lComdlg32 -lIPHLPAPI -lshlwapi -lSHELL32 -lWSHTCPIP -Wl,--allow-multiple-definition -lmsvcrt
bindip.exe: bindip.c dialog.rc resource.h common.h
	windres.exe -F pe-i386 dialog.rc dialog.o
	$(CC) -Os -m32 -nostdlib $(CFLAGS) -o bindip.exe -L$(WIN32PATH) $(LDFLAGS) bindip.c dialog.o -Wl,-e_winMain
# -Wl,-subsystem,windows
bindip32.dll: dll.c common.h
	$(CC) -Os -shared -m32 -nostdlib $(CFLAGS) -o bindip32.dll -L$(WIN32PATH) $(LDFLAGS) dll.c -Wl,-e_DllMain dll.def
bindip64.dll: dll.c common.h
	$(CC) -Os -shared -nostdlib $(CFLAGS) -o bindip64.dll -L$(WIN64PATH) $(LDFLAGS) dll.c -Wl,-eDllMain dll.def
clean:
	rm *.o *.dll *.exe
