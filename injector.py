import ctypes
import psutil
import os
import sys
import time
from ctypes import wintypes

if len(sys.argv) != 3:
    print("Usage: python injector.py <process_name.exe> <path_to_dll>")
    sys.exit(1)

TARGET_PROCESS = sys.argv[1]
DLL_PATH = os.path.abspath(sys.argv[2])

if not os.path.exists(DLL_PATH):
    print(f"[!] DLL not found: {DLL_PATH}")
    sys.exit(1)

print(f"[*] Looking for process: {TARGET_PROCESS}")
pid = None
for proc in psutil.process_iter(['pid', 'name']):
    if proc.info['name'] and proc.info['name'].lower() == TARGET_PROCESS.lower():
        pid = proc.info['pid']
        break

if not pid:
    print(f"[!] {TARGET_PROCESS} not running!")
    sys.exit(1)

print(f"[+] Found {TARGET_PROCESS} with PID {pid}")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

# Set up function prototypes
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE

k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.VirtualAllocEx.restype = wintypes.LPVOID

k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wintypes.BOOL

k32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID]
k32.CreateRemoteThread.restype = wintypes.HANDLE

k32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]
k32.GetModuleHandleA.restype = wintypes.HMODULE

k32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
k32.GetProcAddress.restype = wintypes.LPVOID

# Get address of LoadLibraryA
h_kernel32 = k32.GetModuleHandleA(b"kernel32.dll")
LoadLibraryA_addr = k32.GetProcAddress(h_kernel32, b"LoadLibraryA")

# Open target process
h_process = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not h_process:
    print("[!] Could not open process")
    sys.exit(1)

# Allocate memory in target
dll_path_bytes = DLL_PATH.encode('ascii') + b'\x00'
dll_path_len = len(dll_path_bytes)

arg_address = k32.VirtualAllocEx(h_process, None, dll_path_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
if not arg_address:
    print("[!] Failed to allocate memory in target process")
    sys.exit(1)

written = ctypes.c_size_t(0)
success = k32.WriteProcessMemory(h_process, arg_address, dll_path_bytes, dll_path_len, ctypes.byref(written))
if not success or written.value != dll_path_len:
    print("[!] Failed to write DLL path")
    sys.exit(1)

# Inject!
h_thread = k32.CreateRemoteThread(h_process, None, 0, LoadLibraryA_addr, arg_address, 0, None)
if not h_thread:
    print("[!] Injection failed")
    sys.exit(1)

print("[✅] DLL injected successfully!")
