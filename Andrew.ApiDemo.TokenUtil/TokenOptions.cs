using Andrew.ApiDemo.SDK.Security;
using CommandLine;
using System;
using System.Collections.Generic;
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
            TokenBase.InitKeyDIR(@"D:\KEYDIR");

            return 0;
        }
    }
}
