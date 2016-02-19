using System;
using System.Collections.Generic;
using System.Text;

namespace Andrew.ApiDemo.SDK.Security
{
    public class TokenException : Exception { }

    public class TokenNotValidateException : TokenException { }
    
    public class TokenNotSafeException : TokenException { }

    public class TokenNotSecureException : TokenException { }
}
