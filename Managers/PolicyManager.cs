using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebApp_OpenIDConnect_DotNet.Models.Settings;

namespace WebApp_OpenIDConnect_DotNet.Managers
{
    using System.Configuration;
    public class PolicyManager
{
        private readonly string _prefix;

        public PolicyManager(IConfiguration configuration)
        {
            var authOptions = AuthenticationCustomerOptions.Construct(configuration);
            _prefix = "B2C_1A_"; // authOptions.PolicyPrefix;
        }

        public string PasswordReset => $"{_prefix}password_reset";
        public List<string> CustomerPolicySetupList => new List<string>
        {
            SignInWithPersonalAccountLocalPhoneWithOtp,
            SignUpOrSignInWithPersonalAccountLocalEmail,
            SignUpOrSignInWithPersonalAccountLocalEmailAndSocial,
            SignUpOrSignInWithPersonalAccountLocalPhoneAndSocial,
            SignUpOrSignInWithPersonalAccountLocalUsernameAndSocial,
            SignUpOrSignInWithPersonalAccountLocalUsernameAndSocialWithPreAgeGating,
            SignUpOrSignInWithPersonalAccountLocalUsernameAndSocialWithTotpMfa,
        };
        public Dictionary<string, string> PolicyList =>
        new Dictionary<string, string>
        {
                {"Local Only", SignUpOrSignInWithPersonalAccountLocalEmail},
                {"Local & Social", SignUpOrSignInWithPersonalAccountLocalEmailAndSocial},
                {"Social & Username - Inline Age Gating", SignUpOrSignInWithPersonalAccountLocalUsernameAndSocial},
                {"Social & Username - With Pre Age Gating", SignUpOrSignInWithPersonalAccountLocalUsernameAndSocialWithPreAgeGating},
                {"Social & Phone", SignUpOrSignInWithPersonalAccountLocalPhoneAndSocial},
                {"Phone based OTP", SignInWithPersonalAccountLocalPhoneWithOtp},
                {"Social & Username - TOTP MFA", SignUpOrSignInWithPersonalAccountLocalUsernameAndSocialWithTotpMfa}

            //{"Phone based OTP", SignUpWithPersonalAccountLocalPhoneWithOtp},
            //{"", SignUpOrSignInWithPersonalAccountLocalEmailSkipProgressiveProfile},
            //{"", SignUpOrSignInWithPersonalAccountLocalUsernameAndSocialSendInvitation},
        };

        public string SignUpOrSignInWithPersonalAccountLocalEmail => $"{_prefix}sign_up_sign_in_personal_local_email";
        public string SignUpOrSignInWithPersonalAccountLocalEmailAndSocial => $"{_prefix}sign_up_sign_in_personal_local_email_and_social";
        public string SignUpOrSignInWithPersonalAccountLocalUsernameAndSocial => $"{_prefix}sign_up_sign_in_personal_local_username_and_social";
        public string SignUpOrSignInWithPersonalAccountLocalUsernameAndSocialWithPreAgeGating =>
            $"{_prefix}sign_up_sign_in_personal_local_username_and_social_with_pre_age_gating";
        public string SignUpOrSignInWithPersonalAccountLocalPhoneAndSocial => $"{_prefix}sign_up_sign_in_personal_local_phone_and_social";
        public string SignInWithPersonalAccountLocalPhoneWithOtp => $"{_prefix}sign_up_sign_in_personal_local_phone_withOtp";
        public string SignUpOrSignInWithPersonalAccountLocalUsernameAndSocialWithTotpMfa =>
            $"{_prefix}sign_up_sign_in_personal_local_email_and_social_totp";

    }
}

