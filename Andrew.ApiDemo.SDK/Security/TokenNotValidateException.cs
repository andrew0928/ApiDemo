using System;
using System.Collections.Generic;
using System.Text;

namespace Andrew.ApiDemo.SDK.Security
{
    public class TokenNotValidateException : Exception
    {
        public TokenNotValidateException()
            : base()
        {
        }

        public TokenNotValidateException(string message)
            : base(message)
        {
        }

        public TokenNotValidateException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
