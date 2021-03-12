// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json;

namespace PasswordManagerAccess.TrueKey.Response
{
    internal class Status
    {
        [JsonProperty("responseResult", Required = Required.Always)]
        public readonly Result Result;
    }

    internal struct Result
    {
        [JsonProperty("isSuccess", Required = Required.Always)]
        public readonly bool IsSuccess;

        [JsonProperty("errorCode")]
        public readonly string ErrorCode;

        [JsonProperty("errorDescription")]
        public readonly string ErrorDescription;
    }

    internal class RegisterNewDevice: Status
    {
        [JsonProperty("clientToken", Required = Required.Always)]
        public readonly string ClientToken;

        [JsonProperty("tkDeviceId", Required = Required.Always)]
        public readonly string DeviceId;
    }

    internal class AuthStep1: Status
    {
        [JsonProperty("oAuthTransId", Required = Required.Always)]
        public readonly string TransactionId;
    }

    internal class AuthStep2: Status
    {
        [JsonProperty("oAuthTransId", Required = Required.Always)]
        public readonly string TransactionId;

        [JsonProperty("riskAnalysisInfo", Required = Required.Always)]
        public readonly RiskAnalysisInfo Info;

        [JsonProperty("idToken")]
        public string OAuthToken;
    }

    internal struct RiskAnalysisInfo
    {
        [JsonProperty("nextStep", Required = Required.Always)]
        public readonly int NextStep;

        [JsonProperty("nextStepData", Required = Required.Always)]
        public readonly NextStepData Data;

        [JsonProperty("altNextStep", Required = Required.Always)]
        public readonly long AltNextStep;

        [JsonProperty("bcaNextStep", Required = Required.Always)]
        public readonly long BcaNextStep;

        [JsonProperty("bcaNextStepData", Required = Required.AllowNull)]
        public readonly object BcaNextStepData;
    }

    internal struct NextStepData
    {
        [JsonProperty("oobDevices")]
        public readonly OobDevice[] OobDevices;

        [JsonProperty("verificationEmail")]
        public readonly string VerificationEmail;
    }

    internal struct OobDevice
    {
        [JsonProperty("deviceId", Required = Required.Always)]
        public readonly string Id;

        [JsonProperty("deviceName", Required = Required.Always)]
        public readonly string Name;
    }

    internal class Vault
    {
        [JsonProperty("customer", Required = Required.Always)]
        public readonly Customer Customer;

        [JsonProperty("assets", Required = Required.Always)]
        public readonly Account[] Accounts;
    }

    internal struct Customer
    {
        [JsonProperty("salt", Required = Required.Always)]
        public readonly string Salt;

        [JsonProperty("k_kek", Required = Required.Always)]
        public readonly string Kek;
    }

    internal struct Account
    {
        [JsonProperty("id", Required = Required.Always)]
        public readonly int Id;

        [JsonProperty("name")]
        public readonly string Name;

        [JsonProperty("login")]
        public readonly string Username;

        [JsonProperty("password_k")]
        public readonly string EncryptedPassword;

        [JsonProperty("url")]
        public readonly string Url;

        [JsonProperty("memo_k")]
        public readonly string EncryptedNote;
    }

    internal class AuthCheck: Status
    {
        [JsonProperty("nextStep", Required = Required.Always)]
        public readonly int NextStep;

        [JsonProperty("idToken")]
        public string OAuthToken;
    }
}
