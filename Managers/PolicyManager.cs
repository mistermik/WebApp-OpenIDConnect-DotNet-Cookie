using Microsoft.Extensions.Configuration;
using System.Collections.Generic;
using System.Linq;
using WebApp_OpenIDConnect_DotNet.Models.Settings;

namespace WebApp_OpenIDConnect_DotNet.Managers
{
    public class PolicyManager
    {
        private readonly AuthenticationCustomerOptions _authOptions;

        public IDictionary<string, string> PolicyList => _authOptions.PolicyList;

        public PolicyManager(IConfiguration configuration)
        {
            _authOptions = AuthenticationCustomerOptions.Construct(configuration);

            _authOptions.PolicyList = new Dictionary<string, string>();
            configuration.GetSection(_authOptions.ConfigListSectionName).GetChildren().ToList()
                .ForEach(v => _authOptions.PolicyList.Add(v.Key, $"{_authOptions.PolicyPrefix}{v.Value}"));
        }        
    }
}

