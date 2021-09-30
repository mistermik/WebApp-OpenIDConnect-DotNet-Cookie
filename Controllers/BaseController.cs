namespace WebApp_OpenIDConnect_DotNet.Controllers
{
    using System;
    using Managers;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Filters;
    using Microsoft.Net.Http.Headers;

    public class BaseController : Controller
    {


        public void CreateCookie(string key, string value)
        {
            var option = new CookieOptions();
            option.Expires = DateTime.Now.AddDays(7);
            option.Path = "/";
            option.Domain = null;
            option.IsEssential = true;

            Response.Cookies.Append(key, value ?? string.Empty, option);

        }

        public void RemoveCookie(string key)
        {
            var option = new CookieOptions();
            option.Expires = DateTime.Now.AddDays(7);
            option.Path = "/";
            option.Domain = null;
            option.IsEssential = true;

            option.Expires = DateTime.Now.AddDays(-1);

            Response.Cookies.Append(key, string.Empty, option);
        }
    }
}
