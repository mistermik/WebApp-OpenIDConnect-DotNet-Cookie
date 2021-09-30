using static WebApp_OpenIDConnect_DotNet.Constants;

namespace WebApp_OpenIDConnect_DotNet.Controllers
{
    using System.Linq;
    using Microsoft.AspNetCore.Mvc;
    using ViewModels;
    using Managers;
    using WebApp_OpenIDConnect_DotNet.Extensions;
    using Microsoft.Extensions.Configuration;

    public class ConfigurationController : BaseController
    {


        private readonly PolicyManager _policyManager;
        public ConfigurationController(IConfiguration configuration)
        {
            _policyManager = new PolicyManager(configuration);
        }

        public IActionResult Index()
        {
            return View(GetConfigurationViewModel());
        }

        private ConfigurationViewModel GetConfigurationViewModel()
        {
            var configurationViewModel = new ConfigurationViewModel();
            var defaultSusiPolicy = Request.Cookies[DemoCookies.DefaultSigninPolicyKey];
            if (!string.IsNullOrEmpty(defaultSusiPolicy))
            {
                configurationViewModel.DefaultSUSIPolicy = defaultSusiPolicy.ToBase64Decode();
            }
            configurationViewModel.PolicyList = _policyManager.PolicyList;
            return configurationViewModel;
        }

        public IActionResult Configure(ConfigurationViewModel configurationViewModel)
        {
            //if (Request.Form.Any(x => x.Key == "setDefalut_action"))
            //{
            //    RemoveCookie(DemoCookies.DefaultSigninPolicyKey);
            //}
            //else 
            if (Request.Form.Any(x => x.Key == "update_action"))
            {
                CreateCookie(DemoCookies.DefaultSigninPolicyKey, configurationViewModel.DefaultSUSIPolicy.ToBase64Encode());

            }

            ViewBag.Success = true;

            return RedirectToAction("Index");
        }

    }

    namespace WebApp_OpenIDConnect_DotNet.Extensions
    {
        using System;
        using System.Text;

        public static class StringExtension
        {
            public static string ToBase64Encode(this string source)
            {
                var plainTextBytes = Encoding.UTF8.GetBytes(source ?? string.Empty);
                return Convert.ToBase64String(plainTextBytes);
            }

            public static string ToBase64Decode(this string source)
            {
                var data = Convert.FromBase64String(source ?? string.Empty);
                return Encoding.UTF8.GetString(data);
            }
        }
    }
}
