using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApp_OpenIDConnect_DotNet.Settings;

namespace WebApp_OpenIDConnect_DotNet.Models.Settings
{
    public class AuthenticationCustomerOptions : ConfigOptionsBase<AuthenticationCustomerOptions>
    {
        public string Authority { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string PolicyPrefix { get; set; }

        public string Policy { get; set; }

        public string TenantId { get; set; }
        protected override string SectionName => "Auth-Customer";
    }
}
