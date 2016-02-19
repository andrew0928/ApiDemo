using CommandLine;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Andrew.ApiDemo.TokenUtil
{
    [Verb("key", HelpText = "RSA key pair generator")]
    public class KeyOptions
    {
        //[Option(
        //    HelpText = "Prints all messages to standard output.")]
        //public bool Verbose { get; set; }


        [Option('n', "name", Required = true)]
        public string Name { get; set; }

        [Option('o', "output", Default = @"D:\KEYDIR\")]
        public string KeyDir { get; set; }

        [Option("private_output", Default = @"D:\KEYDIR\_PRIVATE\")]
        public string PrivateKeyDir { get; set; }



        public static int RunAndReturnExitCode(KeyOptions opts)
        {
            if (Directory.Exists(opts.KeyDir) == false) Directory.CreateDirectory(opts.KeyDir);
            if (Directory.Exists(opts.PrivateKeyDir) == false) Directory.CreateDirectory(opts.PrivateKeyDir);

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            //File.WriteAllText(
            //    Path.Combine(opts.KeyDir, opts.Name + "-public.xml"),
            //    rsa.ToXmlString(false));
            //File.WriteAllText(
            //    Path.Combine(opts.KeyDir, opts.Name + "-private.xml"),
            //    rsa.ToXmlString(true));

            File.WriteAllText(
                Path.Combine(opts.KeyDir, opts.Name + ".xml"),
                rsa.ToXmlString(false));

            File.WriteAllText(
                Path.Combine(opts.PrivateKeyDir, opts.Name + ".xml"),
                rsa.ToXmlString(true));

            return 0;
        }
    }

}
