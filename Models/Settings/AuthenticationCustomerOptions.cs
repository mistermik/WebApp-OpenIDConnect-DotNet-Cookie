using System.Collections.Generic;
using WebApp_OpenIDConnect_DotNet.Settings;

namespace WebApp_OpenIDConnect_DotNet.Models.Settings
{
    public class AuthenticationCustomerOptions : ConfigOptionsBase<AuthenticationCustomerOptions>
    {
        //public string Authority { get; set; }

        //public string ClientId { get; set; }

        //public string ClientSecret { get; set; }

        public string PolicyPrefix { get; set; }
        public IDictionary<string, string> PolicyList { get; set; }

        //public string Policy { get; set; }

        //public string TenantId { get; set; }
        public override string SectionName => "ConfigurationPage";
        public string ConfigListSectionName => "ConfigurationPage:PolicyList";
    }
}
