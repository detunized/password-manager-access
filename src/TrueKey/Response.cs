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
        [JsonProperty("oobDevices", Required = Required.Always)]
        public readonly OobDevice[] OobDevices;

        [JsonProperty("verificationEmail", Required = Required.Always)]
        public readonly string VerificationEmail;

        [JsonProperty("bcaResyncToken", Required = Required.AllowNull)]
        public readonly object BcaResyncToken;
    }

    internal struct OobDevice
    {
        [JsonProperty("deviceId", Required = Required.Always)]
        public string Id { get; set; }

        [JsonProperty("deviceName", Required = Required.Always)]
        public string Name { get; set; }
    }
}
