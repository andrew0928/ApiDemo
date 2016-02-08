using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Globalization;

namespace Andrew.ApiDemo.SDK.Security
{
    public static class HashUtil
    {
        private static HashAlgorithm CreateHash()
        {
            return HashAlgorithm.Create("MD5");
        }

        public static byte[] ComputeHash(byte[] data, byte[] salt)
        {
            if (data == null) return null;
            if (data.Length == 0) return null;

            byte[] bufferWithSalt = null;

            if (salt == null || salt.Length == 0)
            {
                bufferWithSalt = data;
            }
            else
            {
                MemoryStream ms = new MemoryStream(data.Length + salt.Length);
                ms.Write(data, 0, data.Length);
                ms.Write(salt, 0, salt.Length);

                bufferWithSalt = ms.ToArray();
                ms.Close();
            }

            return CreateHash().ComputeHash(bufferWithSalt);
        }

        public static string ComputeHash(string data, string salt)
        {
            return BufferToText(ComputeHash(TextToBuffer(data), TextToBuffer(salt)));
        }



        public static bool CompareHash(byte[] data, byte[] hash, byte[] salt)
        {
            if (data != null && data.Length == 0) data = null;
            if (hash != null && hash.Length == 0) hash = null;
            if (data == null && hash == null) return true;



            byte[] temp = ComputeHash(data, salt);

            if (temp.Length != hash.Length) return false;

            for (int pos = 0; pos < temp.Length; pos++)
            {
                if (temp[pos] != hash[pos]) return false;
            }

            return true;
        }

        public static bool CompareHash(string data, string hash, string salt)
        {
            return CompareHash(
                TextToBuffer(data),
                TextToBuffer(hash),
                TextToBuffer(salt));
        }









        public static byte[] TextToBuffer(string data)
        {
            if (data == null) return null;
            if (data.Length == 0) return null;

            MemoryStream ms = new MemoryStream();
            for (int pos = 0; pos < data.Length; pos += 2)
            {
                ms.WriteByte(byte.Parse(data.Substring(pos, 2), NumberStyles.HexNumber));
            }
            return ms.ToArray();
        }

        public static string BufferToText(byte[] data)
        {
            if (data == null) return null;
            if (data.Length == 0) return null;


            StringBuilder sb = new StringBuilder();
            foreach (byte b in data)
            {
                sb.AppendFormat("{0:X2}", b);
            }
            return sb.ToString();
        }
    }
}
