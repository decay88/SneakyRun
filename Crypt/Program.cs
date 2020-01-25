﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;


namespace Aes_Example
{
    class AesExample
    {
        static readonly byte[] myIV = new byte[] { 40, 58, 32, 174, 187, 91, 201, 68, 81, 201, 230, 98, 222, 237, 26, 145 };
        static readonly byte[] myKey = new byte[] { 141, 46, 84, 223, 171, 106, 191, 231, 223, 254, 202, 22, 25, 216, 114, 211, 134, 201, 239, 179, 80, 64, 238, 106, 174, 7, 173, 31, 14, 142, 140, 179 };

        public static void Main()
        {
            /*
            byte [] original = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };

            byte[] encrypted = Encrypt(original);
            byte[] roundtrip = Decrypt(encrypted);
            */
            byte[] W32Mimi = File.ReadAllBytes(@"..\..\..\mimikatz_trunk\Win32\mimikatz.exe");
            byte[] W32PowKatz = File.ReadAllBytes(@"..\..\..\mimikatz_trunk\Win32\powerkatz.dll");
            byte[] x64Mimi = File.ReadAllBytes(@"..\..\..\mimikatz_trunk\x64\mimikatz.exe");
            byte[] x64PowKatz = File.ReadAllBytes(@"..\..\..\mimikatz_trunk\x64\powerkatz.dll");

            File.WriteAllBytes(@"..\..\..\mimikatz_trunk\Win32mimikatz.enc", Encrypt(W32Mimi));
            File.WriteAllBytes(@"..\..\..\mimikatz_trunk\Win32powerkatz.enc", Encrypt(W32PowKatz));
            File.WriteAllBytes(@"..\..\..\mimikatz_trunk\x64mimikatz.enc", Encrypt(x64Mimi));
            File.WriteAllBytes(@"..\..\..\mimikatz_trunk\x64powerkatz.enc", Encrypt(x64PowKatz));


        }


        private static byte[] PerformCryptography(ICryptoTransform cryptoTransform, byte[] data)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                    return memoryStream.ToArray();
                }
            }
        }

        public static byte[] Encrypt(byte[] data)
        {
            Aes _algorithm = Aes.Create();

            using (var encryptor = _algorithm.CreateEncryptor(myKey, myIV))
            {
                return PerformCryptography(encryptor, data);
            }
            
        }

        public static byte[] Decrypt(byte[] data)
        {
            Aes _algorithm = Aes.Create();
            using (var decryptor = _algorithm.CreateDecryptor(myKey, myIV))
            {
                return PerformCryptography(decryptor, data);
            }
            
        }
        static string PBytes(byte[] byteArray)
        {
            var sb = new StringBuilder("new byte[] { ");
            for (var i = 0; i < byteArray.Length; i++)
            {
                var b = byteArray[i];
                sb.Append(b);
                if (i < byteArray.Length - 1)
                {
                    sb.Append(", ");
                }
            }
            sb.Append(" }");
            return sb.ToString();
        }
    }
}