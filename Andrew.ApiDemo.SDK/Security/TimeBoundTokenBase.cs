using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Andrew.ApiDemo.SDK.Security
{
    public abstract class TimeBoundTokenBase : TokenBase
    {
        [TokenData]
        public DateTime ExpireDate;

        public TimeBoundTokenBase()
            : this(TimeSpan.FromDays(1.0))
        {
        }

        public TimeBoundTokenBase(TimeSpan expireDuration)
            : base()
        {
            this.ExpireDate = DateTime.Now.Add(expireDuration);
        }

        public TimeBoundTokenBase(string token)
            : base(token)
        {
        }

        public override bool IsValidate
        {
            get { return this.ExpireDate > DateTime.Now; }
        }
    }
}
