using System;
using System.Collections.Generic;
using System.Text;

namespace Andrew.ApiDemo.SDK.Security
{
    public class TokenException : Exception { }

    public class TokenNotValidateException : TokenException { }

    public class TokenSiteNotExistException : TokenException { }
    
    public class TokenFormatException : TokenException { }

    public class TokenNotSecureException : TokenException { }
}
