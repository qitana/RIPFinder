using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;


namespace RIPFinder
{
    public class BinFile
    {
        //private string fileName;
        private FileStream fs;

        public BinFile(string fileName)
        {
            //this.fileName = fileName;
            fs = new FileStream(fileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
        }


        public List<IntPtr> SigScan(string pattern, int offset, bool rip_addressing)
        {
            List<IntPtr> matches_list = new List<IntPtr>();

            if (pattern == null || pattern.Length % 2 != 0)
            {
                return matches_list;
            }

            // Build a byte array from the pattern string. "??" is a wildcard
            // represented as null in the array.
            byte?[] pattern_array = new byte?[pattern.Length / 2];
            for (int i = 0; i < pattern.Length / 2; i++)
            {
                string text = pattern.Substring(i * 2, 2);
                if (text == "??")
                {
                    pattern_array[i] = null;
                }
                else
                {
                    pattern_array[i] = new byte?(Convert.ToByte(text, 16));
                }
            }

            // Read this many bytes at a time. This needs to be a 32bit number as BitConverter pulls
            // from a 32bit offset into the array that we read from the process.
            const int kMaxReadSize = 65536;

            int module_memory_size = checked((int)fs.Length);
            int process_start_addr = 0;
            int process_end_addr = process_start_addr + module_memory_size;

            int read_start_addr = process_start_addr;
            byte[] read_buffer = new byte[kMaxReadSize];
            while (read_start_addr < process_end_addr)
            {
                // Determine how much to read without going off the end of the process.
                int bytes_left = process_end_addr - read_start_addr;
                int read_size = Math.Min(bytes_left, kMaxReadSize);
                int num_bytes_read = 0;

                fs.Seek(read_start_addr, SeekOrigin.Begin);
                if ((num_bytes_read = fs.Read(read_buffer, 0, read_size)) > 0)
                {
                    int max_search_offset = num_bytes_read - pattern_array.Length - Math.Max(0, offset);
                    // With RIP we will read a 4byte pointer at the |offset|, else we read an 8byte pointer. Either
                    // way we can't find a pattern such that the pointer we want to read is off the end of the buffer.
                    if (rip_addressing)
                        max_search_offset -= 4;  //  + 1L; ?
                    else
                        max_search_offset -= 8;

                    for (int search_offset = 0; search_offset < max_search_offset; ++search_offset)
                    {
                        bool found_pattern = true;
                        for (int pattern_i = 0; pattern_i < pattern_array.Length; pattern_i++)
                        {
                            // Wildcard always matches, otherwise compare to the read_buffer.
                            byte? pattern_byte = pattern_array[pattern_i];
                            if (pattern_byte.HasValue &&
                                pattern_byte.Value != read_buffer[search_offset + pattern_i])
                            {
                                found_pattern = false;
                                break;
                            }
                        }
                        if (found_pattern)
                        {
                            IntPtr pointer;
                            if (rip_addressing)
                            {
                                Int32 rip_ptr_offset = BitConverter.ToInt32(read_buffer, search_offset + pattern_array.Length + offset);
                                Int64 pattern_start_game_addr = read_start_addr + search_offset;
                                Int64 pointer_offset_from_pattern_start = pattern_array.Length + offset;
                                Int64 rip_ptr_base = pattern_start_game_addr + pointer_offset_from_pattern_start + 4;
                                // In RIP addressing, the pointer from the executable is 32bits which we stored as |rip_ptr_offset|. The pointer
                                // is then added to the address of the byte following the pointer, making it relative to that address, which we
                                // stored as |rip_ptr_base|.
                                pointer = new IntPtr((Int64)rip_ptr_offset + rip_ptr_base);
                            }
                            else
                            {
                                // In normal addressing, the 64bits found with the pattern are the absolute pointer.
                                pointer = new IntPtr(BitConverter.ToInt64(read_buffer, search_offset + pattern_array.Length + offset));
                            }
                            matches_list.Add(pointer);

                        }
                    }
                }

                read_start_addr = read_start_addr + kMaxReadSize;

            }

            return matches_list;

        }

    }
}
