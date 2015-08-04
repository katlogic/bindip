# You need mingw64 to compile this

# Change to wherever your system dlls are
WIN32PATH=/c/Windows/SysWOW64
WIN64PATH=/c/Windows/system32

all: bindip.exe bindip.dll 64/bindip.dll
release: zip msi
bindip: bindip.exe bindip.dll 64/bindip.dll
	mkdir -p bindip
	strip *.exe *.dll 64/*.dll
	cp -vaf bindip.exe bindip.dll 64 bindip
zip: bindip
	zip -r bindip.zip bindip
msi: bindip
	candle bindip.wxs -out bindip.wixobj
	light bindip.wixobj -out bindip.msi

CFLAGS=-Wall -Wno-unused -fno-stack-check -fno-stack-protector -mno-stack-arg-probe -fno-asynchronous-unwind-tables
LDFLAGS=-Wl,--enable-stdcall-fixup -lws2_32 -lADVAPI32 -lkernel32 -lUSER32 -lComdlg32 -lIPHLPAPI -lshlwapi -lSHELL32 -lWSHTCPIP -Wl,--allow-multiple-definition -lmsvcrt
bindip.exe: bindip.dll bindip.c dialog.rc resource.h common.h
	windres.exe -F pe-i386 dialog.rc dialog.o
	$(CC) -Os -m32 -nostdlib $(CFLAGS) -o bindip.exe -L$(WIN32PATH) $(LDFLAGS) bindip.dll bindip.c dialog.o -Wl,-e_winMain
# -Wl,-subsystem,windows
bindip.dll: dll.c common.h
	$(CC) -Os -shared -m32 -nostdlib $(CFLAGS) -o bindip.dll -L$(WIN32PATH) $(LDFLAGS) dll.c -Wl,-e_DllMain dll.def
64/bindip.dll: dll.c common.h
	mkdir -p 64
	$(CC) -Os -shared -nostdlib $(CFLAGS) -o 64/bindip.dll -L$(WIN64PATH) $(LDFLAGS) dll.c -Wl,-eDllMain dll.def
clean:
	rm -rf *.o *.dll 64 bindip.exe *.wixobj bindip *.zip
