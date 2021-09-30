using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using WebApp_OpenIDConnect_DotNet.Controllers.WebApp_OpenIDConnect_DotNet.Extensions;
using static WebApp_OpenIDConnect_DotNet.Constants;

namespace WebApp_OpenIDConnect_DotNet.Controllers
{
    [AllowAnonymous]
    [Area("MicrosoftIdentity")]
    [Route("[area]/[controller]/[action]")]
    public class MyAccountController : Controller
    {

        [HttpGet("{scheme?}")]
        public IActionResult SignIn([FromRoute] string scheme)
        {
            var defaultSusiPolicy = Request.Cookies[DemoCookies.DefaultSigninPolicyKey];
            scheme ??= OpenIdConnectDefaults.AuthenticationScheme;
            var redirectUrl = Url.Content("~/");
            var properties = new Microsoft.AspNetCore.Authentication.AuthenticationProperties { RedirectUri = redirectUrl };
            //properties.Items["policy"] = "B2C_1_SignIn";
            properties.Items["policy"] = defaultSusiPolicy.ToBase64Decode(); ;
            return Challenge(properties, scheme);
        }

    }
}