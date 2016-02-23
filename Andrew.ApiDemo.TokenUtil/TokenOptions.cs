using Andrew.ApiDemo.SDK;
using Andrew.ApiDemo.SDK.Security;
using CommandLine;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Andrew.ApiDemo.TokenUtil
{
    [Verb("token", HelpText = "Token utility")]
    public class TokenOptions
    {






        public static int RunAndReturnExitCode(TokenOptions opts)
        {
            // 初始化存放所有金鑰的 KEYSTORE，同時設定這個網站本身的 SITEID
            TokenHelper.Init(
                "GLOBAL", 
                @"D:\KEYDIR\_PRIVATE\GLOBAL.xml", 
                @"D:\KEYDIR");

            // 建立空的 SiteLicenseToken 物件
            SiteLicenseToken slt = TokenHelper.CreateToken<SiteLicenseToken>();

            string plaintext = null;

            // 填入設定值
            slt.SiteTitle = "SITE #1";
            slt.EnableAPI = true;
            slt.LicenseStartDate = new DateTime(2000, 1, 1);
            slt.LicenseEndDate = new DateTime(2099, 12, 31);

            // 編碼，將原始資料及數位簽章，打包成單一字串。可以用任何形式發佈出去
            plaintext = TokenHelper.EncodeToken(slt);


            // 本文 + 簽章
            plaintext = @"nwAAAAJTaXRlVGl0bGUACAAAAFNJVEUgIzEACEVuYWJsZUFQSQABCUxpY2Vuc2VTdGFydERhdGUAADgYadwAAAAJTGljZW5zZUVuZERhdGUAAAjmJbsDAAACU2l0ZUlEAAcAAABHTE9CQUwAAlR5cGVOYW1lACQAAABBbmRyZXcuQXBpRGVtby5TREsuU2l0ZUxpY2Vuc2VUb2tlbgAA|0ofhHMSEHQGZMOafFQxF6zfQchnThv+iPc7PrFZMrL89dkxvYvkYjHhUYLgHNOVz3RGXMxAMQVnwZjrHRNz5GLkaLs19wl1HWCt9kOdWQI/zkvS129IZntdoM4hnN9F/aeVnsDtSS82lx+ESTIh2Wcp5wVwowkzI3l82D3dZwCo=";

            try
            {
                // 驗證簽章。若驗證失敗則會丟出 TokenException
                SiteLicenseToken token = TokenHelper.DecodeToken<SiteLicenseToken>(plaintext);

                // 成功通過驗證，直接取出設定值
                Console.WriteLine("SiteID:        {0}", token.SiteID);
                Console.WriteLine("Site Title:    {0}", token.SiteTitle);
                Console.WriteLine("Enable API:    {0}", token.EnableAPI);
                Console.WriteLine("License Since: {0}", token.LicenseStartDate);
                Console.WriteLine("License Until: {0}", token.LicenseEndDate);
            }
            catch(TokenException)
            {
                // 驗證失敗
            }

            Console.WriteLine("");

            Console.WriteLine("Encoded Text:  {0}", plaintext);

            Stopwatch timer = new Stopwatch();
            timer.Start();
            for(int i = 0; i < 100000; i++)
            {
                TokenHelper.DecodeToken<SiteLicenseToken>(plaintext);
            }
            Console.WriteLine("Total Time: {0} msec.", timer.ElapsedMilliseconds);



            return 0;
        }
    }
}
