// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.


using System.ComponentModel;
using Newtonsoft.Json;

namespace PasswordManagerAccess.ZohoVault.Response
{
    internal class ResponseEnvelope<T>
    {
        [JsonProperty("operation", Required = Required.Always)]
        public readonly Operation<T> Operation;

        public T Payload => Operation.Details;
    }

    internal class OperationStatus
    {
        [JsonProperty("name", Required = Required.Always)]
        public readonly string Name;

        [JsonProperty("result", Required = Required.Always)]
        public readonly Result Result;
    }

    internal class Operation<T> : OperationStatus
    {
        [JsonProperty("details")]
        public readonly T Details;
    }

    internal class Result
    {
        [JsonProperty("status", Required = Required.Always)]
        public readonly string Status;

        [JsonProperty("message", Required = Required.Always)]
        public readonly string Message;

        [JsonProperty("error_code")]
        public readonly string ErrorCode;
    }

    internal class AuthInfo
    {
        [JsonProperty("LOGIN", Required = Required.Always)]
        public readonly string KdfMethod;

        [JsonProperty("ITERATION", Required = Required.Always)]
        public readonly int Iterations;

        [JsonProperty("PASSPHRASE", Required = Required.Always)]
        public readonly string Passphrase;

        [JsonProperty("SALT", Required = Required.Always)]
        public readonly string Salt;
    }

    internal class Vault
    {
        [JsonProperty("SECRETS", Required = Required.Always)]
        public readonly Secret[] Secrets;

        [JsonProperty("PRIVATEKEY", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string PrivateKey;

        [JsonProperty("SHARINGKEY", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string SharingKey;
    }

    internal struct Secret
    {
        [JsonProperty("SECRETID", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("SECRETNAME")]
        public readonly string Name;

        [JsonProperty("SECRETURL")]
        public readonly string Url;

        [JsonProperty("SECURENOTE")]
        public readonly string Note;

        [JsonProperty("SECRETDATA")]
        public readonly string Data;

        [JsonProperty("ISSHARED")]
        public readonly string IsShared;
    }

    internal struct SecretData
    {
        [JsonProperty("username")]
        public readonly string Username;

        [JsonProperty("password")]
        public readonly string Password;
    }

    internal class Status
    {
        [JsonProperty("status_code", Required = Required.Always)]
        public readonly int StatusCode;

        [JsonProperty("code")]
        public readonly string Code;

        [JsonProperty("message")]
        public readonly string Message;

        [JsonProperty("errors")]
        public readonly StatusError[] Errors;
    }

    internal readonly struct StatusError
    {
        [JsonProperty("code", Required = Required.Always)]
        public readonly string Code;

        [JsonProperty("message")]
        public readonly string Message;
    }

    internal class Lookup : Status
    {
        [JsonProperty("lookup")]
        public readonly LookupResult Result;

        [JsonProperty("data")]
        public readonly LookupRedirect Redirect;
    }

    internal class LookupResult
    {
        [JsonProperty("loginid", Required = Required.Always)]
        public readonly string Username;

        [JsonProperty("identifier", Required = Required.Always)]
        public readonly string UserId;

        [JsonProperty("digest", Required = Required.Always)]
        public readonly string Digest;

        [JsonProperty("href", Required = Required.Always)]
        public readonly string Href;

        [JsonProperty("dc")]
        public readonly string DataCenter;
    }

    internal class LookupRedirect
    {
        [JsonProperty("redirect_uri", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string RedirectUrl;

        [JsonProperty("dc", DefaultValueHandling = DefaultValueHandling.Populate)]
        [DefaultValue("")]
        public readonly string DataCenter;
    }

    internal class LogIn : Status
    {
        [JsonProperty("passwordauth")]
        public readonly LogInResult Result;
    }

    internal class LogInResult
    {
        [JsonProperty("code")]
        public readonly string Code;

        [JsonProperty("token")]
        public readonly string MfaToken;

        [JsonProperty("modes")]
        public readonly MfaMethods MfaMethods;
    }

    internal class MfaMethods
    {
        [JsonProperty("allowed_modes", Required = Required.Always)]
        public readonly string[] AllowedMethods;

        [JsonProperty("totp")]
        public readonly MfaTotp Totp;

        [JsonProperty("yubikey")]
        public readonly MfaYubikey Yubikey;
    }

    internal class MfaTotp { }

    internal class MfaYubikey
    {
        [JsonProperty("yub-name")]
        public readonly string Name;
    }

    internal class Totp : Status
    {
        [JsonProperty("totpsecauth")]
        public readonly TotpResult Result;
    }

    internal class TotpResult
    {
        [JsonProperty("status")]
        public readonly string Status;
    }

    internal class TrustMfa : Status
    {
        [JsonProperty("trustmfa")]
        public readonly TrustMfaResult Result;
    }

    internal class TrustMfaResult
    {
        [JsonProperty("code")]
        public readonly string Code;

        [JsonProperty("redirect_uri")]
        public readonly string RedirectUrl;
    }

    internal record SingleSecret(
        [JsonProperty("secretid")] string Id,
        [JsonProperty("secretname")] string Name,
        [JsonProperty("secreturl")] string Url,
        [JsonProperty("notes")] string Notes,
        [JsonProperty("secretData")] string Data,
        [JsonProperty("isshared")] string IsShared,
        [JsonProperty("istrashed")] bool IsTrashed
    );
}
