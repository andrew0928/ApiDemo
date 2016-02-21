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

        private static string _CurrentSiteID = null;
        private static RSACryptoServiceProvider _CurrentRSACSP = null;
        private static Dictionary<string, RSACryptoServiceProvider> _PublicKeyStoreDict = null;
        private static HashAlgorithm _HALG = new SHA256CryptoServiceProvider();

        /// <summary>
        /// 初始化，呼叫其他 static method 前必須先正確的執行初始化動作。
        /// siteID 的 KeyXML 必須包含 private info
        /// </summary>
        /// <param name="siteID">目前環境的 Site ID</param>
        /// <param name="keyDIR">存放 KEY xml 的磁碟目錄</param>
        public static void Init(string siteID, string siteKeyFile, string keyDIR)
        {
            // ToDo: 改成使用 key container
            if (string.IsNullOrEmpty(keyDIR) == true || Directory.Exists(keyDIR) == false)
            {
                keyDIR = @"D:\KEYDIR";
                if (Directory.Exists(keyDIR) == false) Directory.CreateDirectory(keyDIR);
            }

            Dictionary<string, string> _xmldict = new Dictionary<string, string>();
            foreach (string file in Directory.GetFiles(keyDIR, "*.xml", SearchOption.TopDirectoryOnly))
            {
                _xmldict.Add(
                    Path.GetFileNameWithoutExtension(file),
                    File.ReadAllText(file));
            }

            Init(
                siteID, 
                (File.Exists(siteKeyFile))?(File.ReadAllText(siteKeyFile)):(null),
                _xmldict);
        }

        /// <summary>
        /// 初始化，呼叫其他 static method 前必須先正確的執行初始化動作。
        /// siteID 的 KeyXML 必須包含 private info
        /// </summary>
        /// <param name="siteID">目前環境的 Site ID</param>
        /// <param name="keyXmlDict">包含所有 site 的 key xml dictionary</param>
        public static void Init(string siteID, string siteKeyXml, Dictionary<string, string> keyXmlDict)
        {
            Dictionary<string, RSACryptoServiceProvider> _tempKeyStoreDict = new Dictionary<string, RSACryptoServiceProvider>();
            foreach(string site in keyXmlDict.Keys)
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(keyXmlDict[site]);
                _tempKeyStoreDict.Add(site, rsa);
            }

            //if (_tempKeyStoreDict.ContainsKey(siteID) == false) throw new ArgumentException("siteID(" + siteID + ") not found");
            //if (_tempKeyStoreDict[siteID].PublicOnly == true) throw new ArgumentException("must include private key");

            _CurrentSiteID = siteID;
            if (string.IsNullOrEmpty(siteKeyXml) == false)
            {
                _CurrentRSACSP = new RSACryptoServiceProvider();
                _CurrentRSACSP.FromXmlString(siteKeyXml);
            }
            _PublicKeyStoreDict = _tempKeyStoreDict;
        }



        ///// <summary>
        ///// PUBLIC SALT: 公開的 KEY，所有 PLANET 只要共用同一個 DLL 都一樣。可以用來驗證 TOKEN 的資料是否被破壞過。
        ///// </summary>
        //private static readonly byte[] _PublicHashSalt = new byte[] {
        //    0x95, 0x27, 0x95, 0x27, 0x95, 0x27, 0x95, 0x27 // 9527 repeat 4 times
        //};

        /// <summary>
        /// TokenData 編碼用的分隔字元
        /// </summary>
        private const char _SplitChar = '|';


        /// <summary>
        /// 建立新的 TokenData 物件
        /// </summary>
        /// <typeparam name="T">TokenData 型別，必須是 TokenData 的衍生類別</typeparam>
        /// <returns></returns>
        public static T CreateToken<T>() where T : TokenData, new()
        {
            T token = new T();

            token.SiteID = _CurrentSiteID;
            token.TypeName = typeof(T).FullName;

            return token;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="tokenText"></param>
        /// <returns></returns>
        public static T DecodeToken<T>(string tokenText) where T : TokenData, new()
        {
            bool isSecure;
            bool isValidate;
            T token = TryDecodeToken<T>(tokenText, out isSecure, out isValidate);

            if (isSecure == false) throw new TokenNotSecureException();

            if (isValidate == false) throw new TokenNotValidateException();

            return token;
        }


        /// <summary>
        /// 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="tokenText"></param>
        /// <param name="isSecure"></param>
        /// <param name="isValidate"></param>
        /// <returns></returns>
        public static T TryDecodeToken<T>(string tokenText, out bool isSecure, out bool isValidate) where T : TokenData, new()
        {
            string[] parts = tokenText.Split(_SplitChar);

            if (parts == null || parts.Length != 2) throw new TokenFormatException();

            byte[] data_buffer = Convert.FromBase64String(parts[0]);
            byte[] sign_buffer = Convert.FromBase64String(parts[1]);

            // 還原 token 物件，將資料反序列化還原為 object, 同時驗證 token 的授權是否合法
            T token = null;
            //string siteID = null;
            {
                MemoryStream ms = new MemoryStream(data_buffer, false);
                using (BsonReader br = new BsonReader(ms))
                {
                    JsonSerializer js = new JsonSerializer();
                    token = js.Deserialize<T>(br);

                    if (token == null) throw new TokenFormatException();
                }
                isValidate = token.IsValidate();
            }

            // 檢查 signature, 確認 token 的安全性，確保資料沒有被偽造
            if (_PublicKeyStoreDict.ContainsKey(token.SiteID) == false) throw new TokenSiteNotExistException();

            isSecure = _PublicKeyStoreDict[token.SiteID].VerifyData(
                data_buffer,
                _HALG,
                sign_buffer);

            return token;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static string EncodeToken(TokenData token)
        {
            // TokenData 經過序列化之後的 binary data (使用 BSON format)
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
            
            // data_buffer 的簽章
            byte[] sign_buffer = null;
            {
                //sign_buffer = _PublicKeyStoreDict[_CurrentSiteID].SignData(
                sign_buffer = _CurrentRSACSP.SignData(
                    data_buffer,
                    _HALG);
            }

            // 打包 data_buffer, sign_buffer
            return string.Format(
                @"{1}{0}{2}",
                _SplitChar,
                Convert.ToBase64String(data_buffer),
                Convert.ToBase64String(sign_buffer));
        }



    }
}
