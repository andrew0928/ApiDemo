using System;
using System.Collections.Generic;
using System.Text;
using System.Collections.Specialized;
using System.Reflection;
using System.IO;
using System.Globalization;
using System.Security.Cryptography;
//using System.Web;
using System.Configuration;
using System.Runtime.Caching;

namespace Andrew.ApiDemo.SDK.Security
{


    /// <summary>
    /// token format: {serialized date}|{hash data with salt}|{signature with site key}
    /// </summary>
    public abstract class TokenBase
    {
        private const char HASH_SPLIT_CHAR = 'Z';

        private static string _SITEID = null;
        private static Dictionary<string, RSACryptoServiceProvider> _KEY_STORE = new Dictionary<string, RSACryptoServiceProvider>();

        static TokenBase()
        {
            //// init key 
            //string keyDIR = ConfigurationManager.AppSettings["Andrew.ApiDemo.SDK.Security.KeyDirPath"];
        }

        public static void InitKeyDIR(string keyDIR, string siteID)
        {
            // ToDo: 改成使用 key container
            _SITEID = siteID;

            if (string.IsNullOrEmpty(keyDIR) == true || Directory.Exists(keyDIR) == false)
            {
                keyDIR = @"D:\KEYDIR";
                if (Directory.Exists(keyDIR) == false) Directory.CreateDirectory(keyDIR);
            }

            foreach (string file in Directory.GetFiles(keyDIR, "*.xml", SearchOption.TopDirectoryOnly))
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.FromXmlString(File.ReadAllText(file));

                _KEY_STORE.Add(
                    Path.GetFileNameWithoutExtension(file),
                    rsa);
            }

        }



        /// <summary>
        /// PUBLIC SALT: 公開的 KEY，所有 PLANET 只要共用同一個 DLL 都一樣。可以用來驗證 TOKEN 的資料是否被破壞過。
        /// </summary>
        private static readonly byte[] PUBLIC_HASH_SALT = new byte[] {
            0x95, 0x27, 0x95, 0x27, 0x95, 0x27, 0x95, 0x27 // 9527 repeat 4 times
        };

        ///// <summary>
        ///// PRIVATE SALT: 私有的 KEY，每個 PLANET 都不一樣。可以用來驗證這個 TOKEN 是否為目前 SERVER 所發出去的。
        ///// 私有的 KEY 可在 local config 的: /configuration/appsettings/Andrew.ApiDemo.SDK.Security.PrivateHashSalt 設定
        ///// 若無，則會用 LIB 預設值代替。
        ///// </summary>
        //private static byte[] PRIVATE_HASH_SALT
        //{
        //    get
        //    {
        //        if (_CURRENT_PRIVATE_HASH_SALT == null)
        //        {
        //            string SALTTEXT = ConfigurationManager.AppSettings["Andrew.ApiDemo.SDK.Security.PrivateHashSalt"];
        //            if (string.IsNullOrEmpty(SALTTEXT) == false)
        //            {
        //                _CURRENT_PRIVATE_HASH_SALT = Convert.FromBase64String(SALTTEXT);
        //            }
        //            else
        //            {
        //                _CURRENT_PRIVATE_HASH_SALT = new byte[] { 0x02, 0x28, 0x82, 0x52, 0x52 }; // default private salt: 02 28825252
        //            }
        //        }
        //        return _CURRENT_PRIVATE_HASH_SALT;
        //    }
        //}
        //private static byte[] _CURRENT_PRIVATE_HASH_SALT = null;


        //[Obsolete]
        //[TokenData]
        //protected int TypeHash = 0;
        


        //[TokenData]
        protected byte[] TypeFullNameHash = null;


        /// <summary>
        /// 判定 TOKEN 是否安全? (SAFE)
        /// 
        /// TOKEN 安全的定義: TOKEN 是透過 OrcaSDK.dll 所產生出來的，產生後未經過第三者的破壞或是篡改 DATA 的內容。
        /// 
        /// 需注意的風險: TOKEN 可能被其它擁有 OrcaSDK 的協力廠商假造。
        /// 
        /// 判定 TOKEN 是否為目前的 SERVER 所發出? 若不是，則不可 100% 信賴。因為只能保證 TOKEN 從某個 SERVER 發出後，沒經過第三者破壞，但是無法確定發出 TOKEN 的 SERVER 是否為可信賴的 SERVER
        /// </summary>
        public bool IsSafe
        {
            get;
            private set;
        }

        /// <summary>
        /// 判定 TOKEN 是否可被信任? (SECURE)
        /// 
        /// TOKEN 可被信任的定義: TOKEN 必需是 SAFE (安全) 的，同時 TOKEN 也必需是由目前 SERVER 所發出的。
        /// </summary>
        public bool IsSecure
        {
            get;
            private set;
        }

        /// <summary>
        /// 判定 TOKEN 是否通過驗證? (VALIDATE)
        /// 
        /// 不同的 TOKEN 也許會有個別的驗證邏輯。例如有些 TOKEN 會有 ExpireDate 要求，有些 TOKEN 則需要驗證 IP address 等等。
        /// 這部分可由 TOKEN 的開發人員自行定義。
        /// </summary>
        public abstract bool IsValidate
        {
            get;
        }

        protected TokenBase()
        {
            //this.TypeHash = this.GetTypeHashCode();
            this.TypeFullNameHash = this.GetTypeFullNameHashBytes();
            this.IsSafe = true;
            this.IsSecure = true;
        }

        protected TokenBase(string siteID, string tokenText)
        {
            this.SetEncodeText(siteID, tokenText);
        }

        private int GetTypeHashCode()
        {
            return this.GetType().Name.GetHashCode();
        }

        private byte[] GetTypeFullNameHashBytes()
        {
            return ComputeHash(
                            Encoding.Unicode.GetBytes(this.GetType().FullName),
                            null);
        }
        private bool CompareBytes(byte[] b1, byte[] b2)
        {
            if (b1 == null && b2 == null) return true;
            if (b1 == null) return false;
            if (b2 == null) return false;
            if (b1.Length != b2.Length) return false;

            for (int index = 0; index < b1.Length; index++)
            {
                if (b1[index] != b2[index]) return false;
            }

            return true;
        }



        #region token serialization part

        private byte[] SerializeTokenData()
        {
            MemoryStream storage = new MemoryStream();
            BinaryWriter writer = new BinaryWriter(storage, Encoding.Unicode);
            foreach (MemberInfo member in this.MatchMembers)
            {
                
                switch (this.GetMemberDataType(member).FullName)
                {
                    case "System.String":
                        string tempString = this.GetMemberData<string>(member);
                        if (tempString == null)
                        {
                            writer.Write((byte)0x00);
                        }
                        else
                        {
                            writer.Write((byte)0x01);
                            writer.Write(this.GetMemberData<string>(member));
                        }
                        break;

                    case "System.DateTime":
                        writer.Write(this.GetMemberData<DateTime>(member).ToBinary());
                        break;

                    case "System.TimeSpan":
                        writer.Write(this.GetMemberData<TimeSpan>(member).TotalMilliseconds);
                        break;

                    case "System.Int32":
                        writer.Write(this.GetMemberData<System.Int32>(member));
                        break;

                    case "System.Int64":
                        writer.Write(this.GetMemberData<System.Int64>(member));
                        break;

                    case "System.Boolean":
                        writer.Write(this.GetMemberData<System.Boolean>(member));
                        break;

                    case "System.Guid":
                        writer.Write(this.GetMemberData<System.Guid>(member).ToByteArray());
                        break;

                    case "System.Byte[]":
                        byte[] tempBuffer = this.GetMemberData<byte[]>(member);
                        if (tempBuffer == null)
                        {
                            writer.Write(-1);
                        }
                        else
                        {
                            writer.Write(tempBuffer.Length);
                            writer.Write(tempBuffer);
                        }
                        break;

                    default:
                        throw new NotSupportedException("TokenData Type not supported. Support Type: DateTime, TimeSpan, String, Int32, Int64, Boolean");
                }
            }
            
            writer.Flush();
            storage.Flush();
            byte[] buffer = storage.ToArray();
            writer.Close();
            storage.Close();

            return buffer;
        }

        private void DeserializeTokenData(byte[] buffer)
        {
            MemoryStream storage = new MemoryStream(buffer, false);
            BinaryReader reader = new BinaryReader(storage, Encoding.Unicode);

            foreach (MemberInfo member in this.MatchMembers)
            {

                switch (this.GetMemberDataType(member).FullName)
                {
                    case "System.String":
                        byte tempByteValue = reader.ReadByte();
                        if (tempByteValue == 0x00)
                        {
                            this.SetMemberData(
                                member,
                                null);
                        }
                        else if (tempByteValue == 0x01)
                        {
                            this.SetMemberData(
                                member,
                                reader.ReadString());
                        }
                        else
                        {
                            throw new FormatException("can not deserialize token data: " + member.Name);
                        }
                        break;

                    case "System.DateTime":
                        this.SetMemberData(
                            member,
                            DateTime.FromBinary(reader.ReadInt64()));
                        break;

                    case "System.TimeSpan":
                        this.SetMemberData(
                            member,
                            TimeSpan.FromMilliseconds(reader.ReadDouble()));
                        break;

                    case "System.Int32":
                        this.SetMemberData(
                            member,
                            reader.ReadInt32());
                        break;

                    case "System.Int64":
                        this.SetMemberData(
                            member,
                            reader.ReadInt64());
                        break;

                    case "System.Boolean":
                        this.SetMemberData(
                            member,
                            reader.ReadBoolean());
                        break;

                    case "System.Guid":
                        this.SetMemberData(
                            member,
                            new Guid(reader.ReadBytes(16)));
                        break;

                    case "System.Byte[]":
                        int bufferSize = reader.ReadInt32();
                        byte[] tempBuffer = (bufferSize == -1) ? (null) : (reader.ReadBytes(bufferSize));
                        this.SetMemberData(
                            member,
                            tempBuffer);
                        break;

                    default:
                        throw new NotSupportedException("TokenData Type not supported. Support Type: DateTime, TimeSpan, String, Int32, Int64, Boolean");
                }
            }
            reader.Close();
            storage.Close();
        }

        #endregion


        /// <summary>
        /// 
        /// </summary>
        /// <exception cref="TokenNotValidateException">Token驗證失敗</exception>
        /// <returns></returns>
        private string GetEncodeText()
        {
            if (this.IsSafe == false) throw new InvalidOperationException();

            byte[] buffer = this.SerializeTokenData();
            return
                BufferToText(buffer) +
                HASH_SPLIT_CHAR +   //  分段
                BufferToText(ComputeHash(buffer, PUBLIC_HASH_SALT)) +
                HASH_SPLIT_CHAR +   //  分段
                //BufferToText(ComputeHash(buffer, PRIVATE_HASH_SALT));
                BufferToText(_KEY_STORE[_SITEID].SignData(buffer, _HALG));
        }

        public string TokenText
        {
            get
            {
                return this.GetEncodeText();
            }
        }

        

        /// <summary>
        /// 
        /// </summary>
        /// <param name="text"></param>
        /// <param name="validateHash"></param>
        /// <exception cref="FormatException">Token驗證失敗</exception>
        private void SetEncodeText(string siteID, string text)
        {
            byte[] buffer = null;
            {
                //
                //  check hash
                //
                if (text.Contains(HASH_SPLIT_CHAR.ToString()) == false) throw new FormatException("Token format not correct.");

                string[] segments = text.Split(HASH_SPLIT_CHAR);
                if (segments.Length != 3) throw new FormatException("Token format not correct.");

                buffer = TextToBuffer(segments[0]);
                byte[] hash_with_public_salt = TextToBuffer(segments[1]);
                byte[] signature = TextToBuffer(segments[2]);

                if (CompareHash(buffer, hash_with_public_salt, PUBLIC_HASH_SALT) == false)
                {
                    throw new FormatException("Token hash(public) not validate.");
                }

                this.IsSafe = CompareHash(buffer, hash_with_public_salt, PUBLIC_HASH_SALT);

                this.IsSecure = this.IsSafe && //CompareHash(buffer, hash_with_private_salt, PRIVATE_HASH_SALT);
                    _KEY_STORE[siteID].VerifyData(buffer, _HALG, signature);
            }
            this.DeserializeTokenData(buffer);
        }



        private class MemberInfoComparer : IComparer<MemberInfo>
        {
            public int Compare(MemberInfo x, MemberInfo y)
            {
                return string.Compare(x.Name, y.Name);
            }
        }

        private IEnumerable<MemberInfo> MatchMembers
        {
            get
            {
                List<MemberInfo> members = null;
                string cacheKey = string.Format("TokenDataList::{0}", this.GetType().FullName);
                //members = HttpRuntime.Cache[cacheKey] as List<MemberInfo>;
                members = MemoryCache.Default.Get(cacheKey) as List<MemberInfo>;

                if (members == null)
                {
                    members = new List<MemberInfo>();

                    foreach (MemberInfo member in this.GetType().GetMembers(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
                    {
                        object[] atts = member.GetCustomAttributes(typeof(TokenDataAttribute), true);
                        if (atts == null || atts.Length != 1) continue;

                        members.Add(member);
                    }

                    members.Sort(new MemberInfoComparer());

                    MemoryCache.Default.Add(
                        cacheKey,
                        members,
                        null);
                }

                return members;
            }
        }












        private Type GetMemberDataType(MemberInfo member)
        {
            if (member.MemberType == MemberTypes.Field)
            {
                return (member as FieldInfo).FieldType;
            }
            else if (member.MemberType == MemberTypes.Property)
            {
                return (member as PropertyInfo).PropertyType;
            }
            else
            {
                throw new NotSupportedException("only support Field / Property");
            }
        }

        private void SetMemberData(MemberInfo member, object data)
        {
            if (member.MemberType == MemberTypes.Field)
            {
                (member as FieldInfo).SetValue(this, data);
            }
            else if (member.MemberType == MemberTypes.Property)
            {
                (member as PropertyInfo).SetValue(this, data, null);
            }
            else
            {
                throw new NotSupportedException("Only support Field / Property");
            }
        }

        private TData GetMemberData<TData>(MemberInfo member)
        {
            if (member.MemberType == MemberTypes.Field)
            {
                return (TData)(member as FieldInfo).GetValue(this);
            }
            else if (member.MemberType == MemberTypes.Property)
            {
                return (TData)(member as PropertyInfo).GetValue(this, null);
            }
            else
            {
                throw new NotSupportedException("Only support Field / Property");
            }
        }









        public static TToken GetToken<TToken>(string siteID, string tokenText) where TToken : TokenBase, new()
        {
            return GetToken<TToken>(siteID, tokenText, false);
        }

        public static TToken GetToken<TToken>(string siteID, string tokenText, bool safe) where TToken : TokenBase, new()
        {
            TToken token = new TToken();
            token.SetEncodeText(siteID, tokenText);
            if (safe && token.IsSafe == false) throw new TokenNotSafeException();
            return token;
        }

        public static bool IsTokenSafe<TToken>(string siteID, string tokenText) where TToken : TokenBase, new()
        {
            return GetToken<TToken>(siteID, tokenText).IsSafe;
        }

        public static bool IsTokenSecure<TToken>(string siteID, string tokenText) where TToken : TokenBase, new()
        {
            return GetToken<TToken>(siteID, tokenText).IsSecure;
        }

        public static bool IsTokenValidate<TToken>(string siteID, string tokenText) where TToken : TokenBase, new()
        {
            return GetToken<TToken>(siteID, tokenText).IsValidate;
        }







        #region Hash Util

        public static HashAlgorithm GetHash()
        {
            //return HashAlgorithm.Create("MD5");
            //return new SHA256CryptoServiceProvider();
            return _HALG;
        }
        private static readonly HashAlgorithm _HALG = new SHA256CryptoServiceProvider();


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

            return GetHash().ComputeHash(bufferWithSalt);
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


        #endregion

    }
}
