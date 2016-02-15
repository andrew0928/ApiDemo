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
            TokenData.Init("GLOBAL", @"D:\KEYDIR");

            SiteLicenseToken slt = new SiteLicenseToken();
            slt.SiteID = "S1";
            slt.SiteTitle = "SITE #1";
            slt.EnableAPI = true;
            slt.LicenseStartDate = new DateTime(2000, 1, 1);
            slt.LicenseEndDate = new DateTime(2099, 12, 31);

            string tt = TokenData.EncodeToken(slt);

            SiteLicenseToken slt2 = TokenData.DecodeToken<SiteLicenseToken>("GLOBAL", tt);

            //Console.WriteLine("Safe Check:    {0}", slt2.IsSafe);
            //Console.WriteLine("Secure Check:  {0}", slt2.IsSecure);
            //Console.WriteLine("Valid Check:   {0}", slt2.IsValidate);

            //Console.WriteLine("");

            Console.WriteLine("SiteID:        {0}", slt2.SiteID);
            Console.WriteLine("Site Title:    {0}", slt2.SiteTitle);
            Console.WriteLine("Enable API:    {0}", slt2.EnableAPI);
            Console.WriteLine("License Since: {0}", slt2.LicenseStartDate);
            Console.WriteLine("License Until: {0}", slt2.LicenseEndDate);

            Console.WriteLine("");

            Console.WriteLine("Encoded Text:  {0}", tt);

            Stopwatch timer = new Stopwatch();
            timer.Start();
            for(int i = 0; i < 100000; i++)
            {
                TokenData.DecodeToken<SiteLicenseToken>("GLOBAL", tt);
            }
            Console.WriteLine("Total Time: {0} msec.", timer.ElapsedMilliseconds);



            return 0;
        }
    }
}
