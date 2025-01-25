// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Common;

public enum MfaMethod
{
    None,

    // OTP
    GoogleAuthenticator,
    MicrosoftAuthenticator,
    YubikeyOtp,

    // OTP-like
    U2F,
    Fido2,
    WebAuthn,

    // OOB
    Duo,
    LastPassAuthenticator,
    SalesforceAuthenticator,
}

public static class MfaMethodExtensions
{
    public static string GetName(this MfaMethod method) =>
        method switch
        {
            MfaMethod.None => "None",
            MfaMethod.GoogleAuthenticator => "Google Authenticator",
            MfaMethod.MicrosoftAuthenticator => "Microsoft Authenticator",
            MfaMethod.YubikeyOtp => "Yubikey OTP",
            MfaMethod.U2F => "U2F",
            MfaMethod.WebAuthn => "WebAuthn",
            MfaMethod.LastPassAuthenticator => "LastPass Authenticator",
            MfaMethod.SalesforceAuthenticator => "Salesforce Authenticator",
            MfaMethod.Duo => "Duo",
            _ => "Unknown",
        };
}
