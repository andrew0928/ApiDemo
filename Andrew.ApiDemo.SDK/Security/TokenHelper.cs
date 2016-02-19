using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Andrew.ApiDemo.SDK.Security
{
    public static class TokenHelper
    {

        public static void Init(string siteID, string keyDIR)
        {
            // ToDo: 改成使用 key container

            if (string.IsNullOrEmpty(keyDIR) == true || Directory.Exists(keyDIR) == false)
            {
                keyDIR = @"D:\KEYDIR";
                if (Directory.Exists(keyDIR) == false) Directory.CreateDirectory(keyDIR);
            }

            Dictionary<string, RSACryptoServiceProvider> _tempKeyStoreDict = new Dictionary<string, RSACryptoServiceProvider>();
            foreach (string file in Directory.GetFiles(keyDIR, "*.xml", SearchOption.TopDirectoryOnly))
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(File.ReadAllText(file));

                _tempKeyStoreDict.Add(
                    Path.GetFileNameWithoutExtension(file),
                    rsa);
            }

            if (_tempKeyStoreDict.ContainsKey(siteID) == false) throw new ArgumentException("siteID(" + siteID + ") not found");
            if (_tempKeyStoreDict[siteID].PublicOnly == true) throw new ArgumentException("must include private key");

            _CurrentSiteID = siteID;
            _KeyStoreDict = _tempKeyStoreDict;
        }

        private static string _CurrentSiteID = null;
        private static Dictionary<string, RSACryptoServiceProvider> _KeyStoreDict = null;
        private static HashAlgorithm _HALG = new SHA256CryptoServiceProvider();

        /// <summary>
        /// PUBLIC SALT: 公開的 KEY，所有 PLANET 只要共用同一個 DLL 都一樣。可以用來驗證 TOKEN 的資料是否被破壞過。
        /// </summary>
        private static readonly byte[] _PublicHashSalt = new byte[] {
            0x95, 0x27, 0x95, 0x27, 0x95, 0x27, 0x95, 0x27 // 9527 repeat 4 times
        };

        private const char _HashSplitChar = '|';



        public static T CreateToken<T>() where T : TokenData, new()
        {
            T token = new T();

            token.SiteID = _CurrentSiteID;
            token.TypeName = typeof(T).FullName;

            return token;
        }

        public static T DecodeToken<T>(string siteID, string tokenText) where T : TokenData, new()
        {
            bool isSafe;
            bool isSecure;
            bool isValidate;
            T token = TryDecodeToken<T>(siteID, tokenText, out isSafe, out isSecure, out isValidate);

            if (isSafe == false) throw new TokenNotSafeException();

            if (isSecure == false) throw new TokenNotSecureException();

            if (isValidate == false) throw new TokenNotValidateException();

            return token;
        }
        public static T TryDecodeToken<T>(string siteID, string tokenText, out bool isSafe, out bool isSecure, out bool isValidate) where T : TokenData, new()
        {
            string[] parts = tokenText.Split(_HashSplitChar);

            byte[] data_buffer = Convert.FromBase64String(parts[0]);
            byte[] hash_buffer = Convert.FromBase64String(parts[1]);
            byte[] sign_buffer = Convert.FromBase64String(parts[2]);

            isSafe = VerifyHash(
                data_buffer,
                _PublicHashSalt,
                hash_buffer);

            isSecure = _KeyStoreDict[siteID].VerifyData(
                data_buffer,
                _HALG,
                sign_buffer);


            T token = null;
            {
                MemoryStream ms = new MemoryStream(data_buffer, false);
                using (BsonReader br = new BsonReader(ms))
                {
                    JsonSerializer js = new JsonSerializer();
                    token = js.Deserialize<T>(br);
                }
                isValidate = token.IsValidate();
            }

            return token;
        }

        public static string EncodeToken(TokenData token)
        {
            byte[] data_buffer = null;
            {
                MemoryStream dataMS = new MemoryStream();
                using (BsonWriter bw = new BsonWriter(dataMS))
                {
                    JsonSerializer js = new JsonSerializer();
                    token.TypeName = token.GetType().FullName;
                    js.Serialize(bw, token);
                }
                data_buffer = dataMS.ToArray();
            }

            byte[] hash_buffer = null;
            {
                hash_buffer = ComputeHash(data_buffer, _PublicHashSalt);
            }

            byte[] sign_buffer = null;
            {
                sign_buffer = _KeyStoreDict[_CurrentSiteID].SignData(
                    data_buffer,
                    _HALG);
            }

            return string.Format(
                @"{1}{0}{2}{0}{3}",
                _HashSplitChar,
                Convert.ToBase64String(data_buffer),
                Convert.ToBase64String(hash_buffer),
                Convert.ToBase64String(sign_buffer));
        }

        private static byte[] ComputeHash(byte[] data, byte[] salt)
        {
            byte[] hash;
            MemoryStream hashMS = new MemoryStream();
            hashMS.Write(data, 0, data.Length);
            hashMS.Write(salt, 0, salt.Length);
            hashMS.Seek(0, SeekOrigin.Begin);
            hash = _HALG.ComputeHash(hashMS);
            hashMS.Close();
            return hash;
        }

        private static bool VerifyHash(byte[] data, byte[] salt, byte[] hash)
        {
            if (hash == null) return false;
            if (hash.Length == 0) return false;

            byte[] hash_origin = ComputeHash(data, salt);

            if (hash_origin == null) return false;
            if (hash_origin.Length != hash.Length) return false;
            for (int i = 0; i < hash.Length; i++)
            {
                if (hash[i] != hash_origin[i]) return false;
            }

            return true;
        }

    }
}
