using Andrew.ApiDemo.SDK;
using CommandLine;
using System.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Andrew.ApiDemo.TokenUtil
{
    public class Program
    {
        public static int Main(string[] args)
        {
            return Parser.Default.ParseArguments<KeyOptions, TokenOptions>(args).MapResult(
                (KeyOptions opts) => KeyOptions.RunAndReturnExitCode(opts),
                (TokenOptions opts) => TokenOptions.RunAndReturnExitCode(opts),
                errs => 1);
        }
        
    }


}
