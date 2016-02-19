using Andrew.ApiDemo.SDK.Security;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Andrew.ApiDemo.SDK
{
    public class SiteLicenseToken : TokenData
    {
        [JsonProperty]
        public string SiteTitle;

        [JsonProperty]
        public bool EnableAPI;

        [JsonProperty]
        public DateTime LicenseStartDate;

        [JsonProperty]
        public DateTime LicenseEndDate;

        public override bool IsValidate()
        {
            if (this.LicenseStartDate > DateTime.Now) return false;
            if (this.LicenseEndDate < DateTime.Now) return false;
            return base.IsValidate();
        }
    }
}
