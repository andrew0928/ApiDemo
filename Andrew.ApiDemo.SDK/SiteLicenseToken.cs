using Andrew.ApiDemo.SDK.Security;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Andrew.ApiDemo.SDK
{
    /// <summary>
    /// 網站啟用功能的授權資料
    /// </summary>
    public class SiteLicenseToken : TokenData
    {
        /// <summary>
        /// 該網站的註冊 TITLE
        /// </summary>
        [JsonProperty]
        public string SiteTitle;

        /// <summary>
        /// 是否啟用該網站的 API access
        /// </summary>
        [JsonProperty]
        public bool EnableAPI;

        /// <summary>
        /// 網站授權: 啟用時間
        /// </summary>
        [JsonProperty]
        public DateTime LicenseStartDate;

        /// <summary>
        /// 網站授權: 停用時間
        /// </summary>
        [JsonProperty]
        public DateTime LicenseEndDate;

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public override bool IsValidate()
        {
            if (this.LicenseStartDate > DateTime.Now) return false;
            if (this.LicenseEndDate < DateTime.Now) return false;
            return base.IsValidate();
        }
    }
}
