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
    [JsonObject(MemberSerialization = MemberSerialization.OptIn)]
    public class TokenData
    {
        internal TokenData()
        {

        }

        [JsonProperty]
        public string SiteID { get; internal set; }

        [JsonProperty]
        public string TypeName { get; internal set; }

        public virtual bool IsValidate()
        {
            if (this.GetType().FullName != this.TypeName) return false;
            return true;
        }

















    }
}
