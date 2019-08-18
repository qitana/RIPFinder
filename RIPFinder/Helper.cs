using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace RIPFinder
{
    static class Helper
    {
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, IntPtr nSize, ref IntPtr lpNumberOfBytesRead);

        public static byte[] GetByteArray(Process process, IntPtr address, int length)
        {
            var data = new byte[length];
            IntPtr zero = IntPtr.Zero;
            IntPtr nSize = new IntPtr(data.Length);
            Helper.ReadProcessMemory(process.Handle, address, data, nSize, ref zero);
            return data;
        }


    }
}
