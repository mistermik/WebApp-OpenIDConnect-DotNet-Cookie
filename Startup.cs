// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using WebApp_OpenIDConnect_DotNet.Managers;
using Microsoft.IdentityModel.Tokens;
using WebApp_OpenIDConnect_DotNet.Models.Settings;
using WebApp_OpenIDConnect_DotNet.IdentityModel.Protocols;
using System;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading;

namespace WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
                // Handling SameSite cookie according to https://docs.microsoft.com/en-us/aspnet/core/security/samesite?view=aspnetcore-3.1
                options.HandleSameSiteCookieCompatibility();
            });

            // Configuration to sign-in users with Azure AD B2C
            //services.AddMicrosoftIdentityWebAppAuthentication(Configuration, "AzureAdB2C");
            services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApp(options =>
                {
                    Configuration.Bind("AzureAdB2C", options);
                });
                

            services.AddControllersWithViews()
                .AddMicrosoftIdentityUI();

            services.AddRazorPages();

            //Configuring appsettings section AzureAdB2C, into IOptions
            services.AddOptions();
            services.Configure<OpenIdConnectOptions>(Configuration.GetSection("AzureAdB2C"));
        }

        private void ConfigureAuthentication(IConfiguration configuration, IServiceCollection services)
        {
            var authenticationBuilder = services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            });

            var manager = new PolicyManager(configuration);
            services.AddSingleton(manager);

            ConfigureCookieAuthentication(authenticationBuilder);
            ConfigureCustomerAuthentication(configuration, services, authenticationBuilder, manager);
        }

        private void ConfigureCookieAuthentication(AuthenticationBuilder authenticationBuilder)
        {
            authenticationBuilder.AddCookie();
        }

          private void ConfigureCustomerAuthentication(
          IConfiguration configuration,
          IServiceCollection services,
          AuthenticationBuilder authenticationBuilder,
          PolicyManager manager)
        {
            var authenticationOptions = AuthenticationCustomerOptions.Construct(configuration);

            var policyList = manager.CustomerPolicySetupList;

            authenticationBuilder.AddOpenIdConnect(Constants.AuthenticationSchemes.CustomerAuth, options =>
            {
                options.Authority = authenticationOptions.Authority;
                options.CallbackPath = new PathString("/b2c-signin-callback");
                options.ClientId = authenticationOptions.ClientId;
                options.ClientSecret = authenticationOptions.ClientSecret;
                options.CorrelationCookie.Expiration = TimeSpan.FromHours(3);

                options.ConfigurationManager = new PolicyConfigurationManager(
                    authenticationOptions.Authority,
                    policyList);

                options.Events = CreateB2COpenIdConnectEvents(manager);
                options.Scope.Remove("profile");
                options.SignedOutCallbackPath = new PathString("/b2c-signout-callback");

                options.TokenValidationParameters = new TokenValidationParameters { NameClaimType = Constants.ClaimTypes.Name };
            });
        }

        private OpenIdConnectEvents CreateB2COpenIdConnectEvents(PolicyManager policyManager)
        {
            return new OpenIdConnectEvents
            {
                OnRemoteFailure = context =>
                {
                    if (context.Failure.Message == "Correlation failed.")
                    {
                        //// [ log error ]
                        context.HandleResponse();
                        //// redirect to some help page or handle it as you wish
                        context.Response.Redirect("/");
                    }

                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = context =>
                {
                    if (context.Exception.Message.StartsWith("IDX21323"))
                    {
                        context.Response.Redirect("/Account/TimeoutError");
                        context.HandleResponse();
                    }
                    else
                    {
                        context.Fail(context.Exception);
                    }

                    return Task.CompletedTask;
                },
                OnMessageReceived = context =>
                {
                    if (context.ProtocolMessage.Parameters.Any(x => x.Key == "response"))
                    {
                        var jsonResponse = JsonConvert.DeserializeObject<Constants.JsonResponse>(context.ProtocolMessage.Parameters["response"]);

                        if (jsonResponse != null && !string.IsNullOrEmpty(jsonResponse.response) && jsonResponse.response.Contains("B2C_V1_90001"))
                        {
                            context.Response.Redirect("/Account/AgeGatingError");
                            context.HandleResponse();
                            return Task.CompletedTask;
                        }
                    }

                    if (!string.IsNullOrEmpty(context.ProtocolMessage.Error) && !string.IsNullOrEmpty(context.ProtocolMessage.ErrorDescription))
                    {
                        if (context.ProtocolMessage.ErrorDescription.StartsWith("AADB2C90091"))
                        {
                            var policy = context.Properties.Items[Constants.AuthenticationProperties.Policy];

                            if (policy == policyManager.PasswordReset ||
                                policy == policyManager.SignUpOrSignInWithPersonalAccountLocalEmailAndSocial)
                            {
                                var command =
                                    $"{Constants.AuthenticationSchemes.CustomerAuth}:{policyManager.SignUpOrSignInWithPersonalAccountLocalEmailAndSocial}";

                                var uiLocale = string.Empty;

                                if (context.Properties.Items.Any(x => x.Key == Constants.AuthenticationProperties.UILocales))
                                {
                                    uiLocale = context.Properties.Items[Constants.AuthenticationProperties.UILocales];
                                }

                                context.Response.Redirect($"/Account/LogInFor?command={command}&uiLocale={uiLocale}");
                                context.HandleResponse();
                            }
                            else
                            {
                                context.Response.Redirect("/");
                                context.HandleResponse();
                            }
                        }
                        else if (context.ProtocolMessage.ErrorDescription.StartsWith("AADB2C90118"))
                        {
                            var uiLocale = string.Empty;

                            if (context.Properties.Items.Any(x => x.Key == Constants.AuthenticationProperties.UILocales))
                            {
                                uiLocale = context.Properties.Items[Constants.AuthenticationProperties.UILocales];
                            }

                            context.Response.Redirect($"/Account/ResetPassword?uiLocale={uiLocale}");
                            context.HandleResponse();
                        }
                        else if (context.ProtocolMessage.ErrorDescription.StartsWith("AADB2C99001"))
                        {
                            context.Response.Redirect($"/Account/LinkError??ReturnUrl={context.Properties.RedirectUri}");
                            context.HandleResponse();
                        }
                        else if (context.ProtocolMessage.ErrorDescription.StartsWith("AADB2C99002"))
                        {
                            context.Response.Redirect("/Account/LogOut");
                            context.HandleResponse();
                        }
                        else if (context.ProtocolMessage.ErrorDescription.StartsWith("AADB2C90157"))
                        {
                            context.Response.Redirect("/Account/RetryExceededError");
                            context.HandleResponse();
                        }
                        else if (context.ProtocolMessage.ErrorDescription.StartsWith("AADB2C90037"))
                        {
                            context.Response.Redirect("/Account/AgeGatingError");
                            context.HandleResponse();
                        }
                        else if (context.ProtocolMessage.ErrorDescription.StartsWith("AADB2C90273"))
                        {
                            context.Response.Redirect("/");
                            context.HandleResponse();
                        }
                    }

                    return Task.CompletedTask;
                },
                OnRedirectToIdentityProvider = async context =>
                {
                    var policy = context.Properties.Items.ContainsKey(Constants.AuthenticationProperties.Policy)
                        ? context.Properties.Items[Constants.AuthenticationProperties.Policy]
                        : policyManager.SignUpOrSignInWithPersonalAccountLocalEmailAndSocial;
                    var configuration = await GetB2COpenIdConnectConfigurationAsync(context, policy);
                    context.ProtocolMessage.IssuerAddress = configuration.AuthorizationEndpoint;

                    if (context.Properties.Items.ContainsKey(Constants.AuthenticationProperties.UILocales))
                    {
                        context.ProtocolMessage.SetParameter("ui_locales", context.Properties.Items[Constants.AuthenticationProperties.UILocales]);
                    }

                    if (context.Properties.Items.ContainsKey(Constants.AuthenticationProperties.BgImage))
                    {
                        context.ProtocolMessage.SetParameter(Constants.AuthenticationProperties.BgImage,
                            context.Properties.Items[Constants.AuthenticationProperties.BgImage]);
                    }

                    if (context.Properties.Items.ContainsKey(Constants.AuthenticationProperties.LogoImage))
                    {
                        context.ProtocolMessage.SetParameter(Constants.AuthenticationProperties.LogoImage,
                            context.Properties.Items[Constants.AuthenticationProperties.LogoImage]);
                    }

                    if (context.Properties.Items.ContainsKey(Constants.AuthenticationProperties.IdTokenHint))
                    {
                        context.ProtocolMessage.SetParameter(Constants.AuthenticationProperties.IdTokenHint,
                            context.Properties.Items[Constants.AuthenticationProperties.IdTokenHint]);
                    }

                    var policyClaims = new List<Claim>();

                    if (context.Properties.Items.ContainsKey(Constants.AuthenticationProperties.InvitedEmail))
                    {
                        policyClaims.Add(new Claim(Constants.AuthenticationProperties.InvitedEmail,
                            context.Properties.Items[Constants.AuthenticationProperties.InvitedEmail]));
                    }

                    if (context.Properties.Items.ContainsKey(Constants.AuthenticationProperties.InvitedAccountId))
                    {
                        policyClaims.Add(new Claim(Constants.AuthenticationProperties.InvitedAccountId,
                            context.Properties.Items[Constants.AuthenticationProperties.InvitedAccountId]));
                    }

                    if (context.Properties.Items.ContainsKey(Constants.AuthenticationProperties.InvitedGroupId))
                    {
                        policyClaims.Add(new Claim(Constants.AuthenticationProperties.InvitedGroupId,
                            context.Properties.Items[Constants.AuthenticationProperties.InvitedGroupId]));
                    }

                    if (policyClaims.Any())
                    {
                        TimeSpan policyTokenLifetime;

                        // Get the lifetime of the JSON Web Token (JWT) from the authentication session...
                        if (!context.Properties.Items.ContainsKey("policy_token_lifetime") ||
                            !TimeSpan.TryParse(context.Properties.Items["policy_token_lifetime"], out policyTokenLifetime))
                        {
                            // ... Or set it to a default time of 5 minutes.
                            policyTokenLifetime = new TimeSpan(0, 0, 5, 0);
                        }

                        var selfIssuedToken = CreateSelfIssuedToken(
                            configuration.Issuer,
                            context.ProtocolMessage.RedirectUri,
                            policyTokenLifetime,
                            context.Options.ClientSecret,
                            policyClaims);

                        context.ProtocolMessage.Parameters.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
                        context.ProtocolMessage.Parameters.Add("client_assertion", selfIssuedToken);
                    }
                },
                OnRedirectToIdentityProviderForSignOut = async context =>
                {
                    var policy = context.Properties.Items.ContainsKey(Constants.AuthenticationProperties.Policy)
                        ? context.Properties.Items[Constants.AuthenticationProperties.Policy]
                        : policyManager.SignUpOrSignInWithPersonalAccountLocalEmailAndSocial;
                    var configuration = await GetB2COpenIdConnectConfigurationAsync(context, policy);
                    context.ProtocolMessage.IssuerAddress = configuration.EndSessionEndpoint;
                },
                OnTokenValidated = context =>
                {
                    var requestedPolicy = context.Properties.Items[Constants.AuthenticationProperties.Policy];
                    var issuedPolicy = context.Principal.FindFirstValue(Constants.ClaimTypes.TrustFrameworkPolicy);

                    if (!string.Equals(issuedPolicy, requestedPolicy, StringComparison.OrdinalIgnoreCase))
                    {
                        context.Fail($"Access denied: The issued policy '{issuedPolicy}' is different to the requested policy '{requestedPolicy}'.");
                        return Task.CompletedTask;
                    }

                    string roleClaimValue;
                    var identityProvider = context.Principal.FindFirstValue(Constants.ClaimTypes.IdentityProvider);

                    if (identityProvider != null && identityProvider.StartsWith("https://sts.windows.net/"))
                    {
                        var businessCustomerRole = context.Principal.FindFirstValue(Constants.ClaimTypes.BusinessCustomerRole);

                        if (businessCustomerRole == "Manager")
                        {
                            roleClaimValue = Constants.Roles.BusinessCustomerManager;
                        }
                        else
                        {
                            roleClaimValue = Constants.Roles.BusinessCustomerStocker;
                        }
                    }
                    else
                    {
                        roleClaimValue = Constants.Roles.IndividualCustomer;
                    }

                    var claims = new List<Claim> { new Claim(ClaimTypes.Role, roleClaimValue) };

                    var identity = new ClaimsIdentity(claims);
                    context.Principal.AddIdentity(identity);
                    return Task.CompletedTask;
                }
            };
        }


        internal string CreateSelfIssuedToken(
    string issuer,
    string audience,
    TimeSpan expiration,
    string signingSecret,
    ICollection<Claim> claims)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var nowUtc = DateTime.UtcNow;
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingSecret));
            var signingCredentials = new SigningCredentials(key, "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256");

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = audience,
                Expires = nowUtc.Add(expiration),
                IssuedAt = nowUtc,
                Issuer = issuer,
                NotBefore = nowUtc,
                SigningCredentials = signingCredentials,
                Subject = new ClaimsIdentity(claims)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private Task<OpenIdConnectConfiguration> GetB2COpenIdConnectConfigurationAsync(RedirectContext context, string policy)
        {
            var configurationManager = (PolicyConfigurationManager)context.Options.ConfigurationManager;
            return configurationManager.GetConfigurationForPolicyAsync(policy, CancellationToken.None);
        }

               
        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Configuration}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }
    }
}