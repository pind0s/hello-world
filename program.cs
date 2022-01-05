using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;


class Native // @note: es3n1n: fuck c#, why i cannot DllImport fn inside of a namespace
{
    public struct MODULEENTRY32W
    {
        public Int32 dwSize;
        public uint th32ModuleID;
        public uint th32ProcessID;
        public uint GlblcntUsage;
        public uint ProccntUsage;
        public IntPtr modBaseAddr;
        public uint modBaseSize;
        public IntPtr hModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szModule;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExePath;

        public static Int32 Size
        {
            get { return Marshal.SizeOf(typeof(MODULEENTRY32W)); }
        }
    }

    public delegate bool CallbackDelegate(IntPtr hWnd, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool EnumThreadWindows(int dwThreadId, CallbackDelegate callback, IntPtr lParam);

    [DllImport("user32")]
    public static extern bool EnumChildWindows(IntPtr window, CallbackDelegate callback, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr hWnd, uint Msg, int wParam, int lParam);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll")]
    public static extern bool Module32First(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("kernel32.dll")]
    public static extern bool Module32Next(IntPtr hSnapshot, ref MODULEENTRY32W lpme);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);


    public static class Impl // @note: es3n1n: class means namespace :P
    {
        public static string GetWindowClassName(IntPtr hWnd)
        {
            StringBuilder str = new StringBuilder(256);
            GetClassName(hWnd, str, 256);
            return str.ToString();
        }

        public static IntPtr GetWindowByClass(ProcessThreadCollection threads, string cls)
        {
            IntPtr ret = IntPtr.Zero;

            foreach (ProcessThread th in threads)
            {
                EnumThreadWindows(th.Id, (hWnd, lParam) =>
                {
                    bool cb_ret = GetWindowClassName(hWnd) != cls; // @note: es3n1n: false - stop // true - continue

                    if (!cb_ret)
                        ret = hWnd;

                    return cb_ret;
                }, IntPtr.Zero);
            }

            return ret;
        }

        public static IntPtr GetChildWindowByClass(IntPtr hWnd, string cls)
        {
            IntPtr ret = IntPtr.Zero;

            EnumChildWindows(hWnd, (child_hwnd, lParam) => // @todo: es3n1n: one global callback (pass data ptr in lParam)
            {
                bool cb_ret = GetWindowClassName(child_hwnd) != cls; // @note: es3n1n: false - stop // true - continue

                if (!cb_ret)
                    ret = child_hwnd;

                return cb_ret;
            }, IntPtr.Zero);

            return ret;
        }
    }
}

class Remote
{
    public static IntPtr GetModuleHandle(Int32 pid, string mod)
    {
        IntPtr ret = IntPtr.Zero;

        IntPtr snapshot = Native.CreateToolhelp32Snapshot(0x00000008 /*SNAPMODULE*/ | 0x00000010 /*SNAPMODULE32*/, Convert.ToUInt32(pid));

        Native.MODULEENTRY32W entry = new Native.MODULEENTRY32W();
        entry.dwSize = Native.MODULEENTRY32W.Size;

        if (!Native.Module32First(snapshot, ref entry))
            return ret;

        do
        {
            if (entry.szModule != mod)
                continue;
            ret = entry.modBaseAddr;
            break;
        } while (Native.Module32Next(snapshot, ref entry));

        return ret;
    }

    public static Int64 GetProcAddress(Int32 pid, string mod, string export) // @note: es3n1n: LIFEHACK: SHUT THE FUCK UP
    {
        var pmod = Native.GetModuleHandle(mod);
        var va = Native.GetProcAddress(pmod, export);
        var rva = va.ToInt64() - pmod.ToInt64();
        var remote_pmod = /*Remote.*/GetModuleHandle(pid, mod).ToInt64();
        return remote_pmod + rva; // @note: es3n1n: i'm a fucking genius
    }
}

class Program
{
    private static List<UInt32> Payload = new List<UInt32> { 0x7f7, 0x7da, 0x7d3, 0x7d3, 0x7d0, 0x793, 0x79f, 0x7e8, 0x7d0, 0x7cd, 0x7d3, 0x7db, 0x79e };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static char GetChar(UInt32 i) => Convert.ToChar(Payload[Convert.ToInt32(i)] ^ (i ^ 0x1488) ^ 0x1337 ^ i);

    private static List<byte> Shellcode = new List<byte>
    {
        0x48, 0x83, 0xEC, 0x28,                                            // sub     rsp, 28h
        0x45, 0x33, 0xC9,                                                  // xor     r9d, r9d        ; uType
        0x49, 0xB8, 0x00, 0x00, 0x53, 0x98, 0x91, 0x01, 0x00, 0x00,        // mov     r8, 19198530000h ; lpCaption
        0x48, 0xBA, 0x00, 0x00, 0x53, 0x98, 0x91, 0x01, 0x00, 0x00,        // mov     rdx, 19198530000h ; lpText
        0x33, 0xC9,                                                        // xor     ecx, ecx        ; hWnd
        0xFF, 0x15, 0x0A, 0x00, 0x00, 0x00,                                // call cs:MessageBoxA
        0xB8, 0x01, 0x00, 0x00, 0x00,                                      // mov eax, 1
        0x48, 0x83, 0xC4, 0x28,                                            // add rsp, 28h
        0xC3,                                                              // retn
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                    // ptr to MessageBoxA
    };

    static void Main(string[] args)
    {
        var proc = Process.Start("C:\\Windows\\system32\\notepad.exe");
        var notepad_win = Native.Impl.GetWindowByClass(proc.Threads, "Notepad");
        var edit_win = Native.Impl.GetChildWindowByClass(notepad_win, "Edit");

        for (UInt32 i = 0; i < Payload.Count; i++)
            Native.PostMessage(edit_win, 0x0102, GetChar(i), 0);

        var allocated = Native.VirtualAllocEx(proc.Handle, IntPtr.Zero, Convert.ToUInt32(0xFF0), 0x1000 /* MEM_COMMIT */, 0x40 /* ERW */);

        int dummy = 0;
        var str_ptr = allocated + Shellcode.Count + 16;
        for (int i = 0; i < Payload.Count; i++)
            Native.WriteProcessMemory(proc.Handle, str_ptr + i, BitConverter.GetBytes(GetChar(Convert.ToUInt32(i))), 1, ref dummy);

        Native.WriteProcessMemory(proc.Handle, allocated, Shellcode.ToArray(), Shellcode.Count, ref dummy);
        Native.WriteProcessMemory(proc.Handle, allocated + 9, BitConverter.GetBytes(str_ptr.ToInt64()), sizeof(Int64), ref dummy);
        Native.WriteProcessMemory(proc.Handle, allocated + 19, BitConverter.GetBytes(str_ptr.ToInt64()), sizeof(Int64), ref dummy);

        while (Remote.GetModuleHandle(proc.Id, "USER32.dll") == IntPtr.Zero)
            Thread.Sleep(500);
        var mbox_addr = Remote.GetProcAddress(proc.Id, "USER32.dll", "MessageBoxA");
        Native.WriteProcessMemory(proc.Handle, allocated + (Shellcode.Count - 8), BitConverter.GetBytes(mbox_addr), sizeof(Int64), ref dummy);

        Native.CreateRemoteThread(proc.Handle, IntPtr.Zero, 0, allocated, IntPtr.Zero, 0, IntPtr.Zero);
    }
}
