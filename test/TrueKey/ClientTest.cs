// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Net.Http;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class ClientTest: TestBase
    {
        [Fact]
        public void OpenVault_returns_accounts_with_new_device()
        {
            var flow = new RestFlow()
                .Post(GetFixture("register-new-device-response"))
                .Post(GetFixture("auth-step1-response"))
                .Post(GetFixture("auth-step2-response"))
                .Post(GetFixture("auth-check-success-response"))
                .Post(GetFixture("save-device-response"))
                .Get(GetFixture("get-vault-response"));

            var accounts = Client.OpenVault(Username, Password123, new CheckUi(), new NullStorage(), flow);
            Assert.NotEmpty(accounts);
        }

        [Fact]
        public void RegisterNewDevice_returns_device_info()
        {
            var result = Client.RegisterNewDevice("truekey-sharp",
                                                  SetupPostWithFixture("register-new-device-response"));

            Assert.StartsWith("AQCmAwEA", result.Token);
            Assert.StartsWith("d871347b", result.Id);
        }

        [Fact]
        public void RegisterNewDevice_throws_on_common_errors()
        {
            VerifyCommonErrorsWithPost(flow => Client.RegisterNewDevice("truekey-sharp", flow));
        }

        [Fact]
        public void AuthStep1_returns_transaction_id()
        {
            var result = Client.AuthStep1(ClientInfo, SetupPostWithFixture("auth-step1-response"));

            Assert.Equal("6cdfcd43-065c-43a1-aa7a-017de98eefd0", result);
        }

        [Fact]
        public void AuthStep1_throws_on_common_errors()
        {
            VerifyCommonErrorsWithPost(flow => Client.AuthStep1(ClientInfo, flow));
        }

        [Fact]
        public void AuthStep2_returns_two_factor_settings()
        {
            // TODO: Test with specifically crafted broken/unsupported responses
            //       The parsing logic is not trivial and it needs in-depth testing.

            var result = Client.AuthStep2(ClientInfo,
                                          "password",
                                          "transaction-id",
                                          SetupPostWithFixture("auth-step2-response"));

            Assert.Equal(TwoFactorAuth.Step.WaitForOob, result.InitialStep);
            Assert.Equal("ae830c59-634b-437c-95b6-58158e85ffae", result.TransactionId);
            Assert.Equal("username@example.com", result.Email);
            Assert.Equal("", result.OAuthToken);

            Assert.Single(result.Devices);
            Assert.Equal("LGE Nexus 5", result.Devices[0].Name);
            Assert.StartsWith("MTU5NjAwMjI3MQP04dNsmSNQ2L", result.Devices[0].Id);
        }

        [Fact]
        public void AuthStep2_throws_on_common_errors()
        {
            VerifyCommonErrorsWithPost(flow => Client.AuthStep2(ClientInfo, "password", "transaction-id", flow));
        }

        [Fact]
        public void SaveDeviceAsTrusted_works()
        {
            // TODO: Write a better test
            Client.SaveDeviceAsTrusted(ClientInfo,
                                       "transaction-id",
                                       "oauth-token",
                                       SetupPost("{'ResponseResult': {'IsSuccess': true}}"));
        }

        [Fact]
        public void SaveDeviceAsTrusted_throws_on_common_errors()
        {
            VerifyCommonErrorsWithPost(
                flow => Client.SaveDeviceAsTrusted(ClientInfo, "transaction-id", "oauth-token", flow));
        }

        [Fact]
        public void AuthCheck_returns_oauth_token()
        {
            var result = Client.AuthCheck(ClientInfo,
                                          "transaction-id",
                                          SetupPostWithFixture("auth-check-success-response"));

            Assert.StartsWith("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI", result);
        }

        [Fact]
        public void AuthCheck_throws_on_pending()
        {
            var flow = SetupPostWithFixture("auth-check-pending-response");
            Exceptions.AssertThrowsInternalError(() => Client.AuthCheck(ClientInfo, "transaction-id", flow));
        }

        [Fact]
        public void AuthCheck_throws_on_common_errors()
        {
            VerifyCommonErrorsWithPost(flow => Client.AuthCheck(ClientInfo, "transaction-id", flow));
        }

        [Fact]
        public void GetVault_returns_encrypted_vault()
        {
            var vault = Client.GetVault("oauth-token", SetupGetWithFixture("get-vault-response"));

            Assert.Equal(MasterKeySalt, vault.MasterKeySalt);
            Assert.Equal(EncryptedMasterKey, vault.EncryptedMasterKey);

            var accounts = vault.EncryptedAccounts;
            Assert.Equal(2, accounts.Length);

            Assert.Equal(50934080, accounts[0].Id);
            Assert.Equal("Google", accounts[0].Name);
            Assert.Equal("dude@gmail.com", accounts[0].Username);
            Assert.Equal("AAR24UbLgkHUhsSXB2mndMISE7U5qn+WA3znhgdXex0br6y5".Decode64(), accounts[0].EncryptedPassword);
            Assert.Equal("https://accounts.google.com/ServiceLogin", accounts[0].Url);
            Assert.Equal("AAS2l1XcabgdPTM3CuUZDbT5txJu1ou0gOQ=".Decode64(), accounts[0].EncryptedNote);

            Assert.Equal(60789074, accounts[1].Id);
            Assert.Equal("facebook", accounts[1].Name);
            Assert.Equal("mark", accounts[1].Username);
            Assert.Equal("AAShzvG+qXE7bT8MhAbbXelu/huVjuUMDC8IsLw4Lw==".Decode64(), accounts[1].EncryptedPassword);
            Assert.Equal("http://facebook.com", accounts[1].Url);
            Assert.Equal("".Decode64(), accounts[1].EncryptedNote);
        }

        [Fact]
        public void GetVault_throws_common_errors()
        {
            VerifyCommonErrorsWithGet(flow => Client.GetVault("oauth-token", flow));
        }

        //
        // Helpers
        //

        private static void VerifyCommonErrorsWithGet(Action<RestFlow> f)
        {
            VerifyNetworkErrorWithGet(f);
            VerifyJsonErrorWithGet(f);
        }

        private void VerifyCommonErrorsWithPost(Action<RestFlow> f)
        {
            VerifyNetworkErrorWithPost(f);
            VerifyJsonErrorWithPost(f);
        }

        private static void VerifyNetworkErrorWithGet(Action<RestFlow> f)
        {
            var flow = new RestFlow().Get(new HttpRequestException("Oops"));
            VerifyNetworkError(flow, f);
        }

        private static void VerifyNetworkErrorWithPost(Action<RestFlow> f)
        {
            var flow = new RestFlow().Post(new HttpRequestException("Oops"));
            VerifyNetworkError(flow, f);
        }

        private static void VerifyNetworkError(RestFlow flow, Action<RestFlow> f)
        {
            Exceptions.AssertThrowsNetworkError(() => f(flow), "Network error");
        }

        private static void VerifyJsonErrorWithGet(Action<RestFlow> f)
        {
            VerifyJsonError(SetupGet("} invalid json {"), f);
        }

        private static void VerifyJsonErrorWithPost(Action<RestFlow> f)
        {
            VerifyJsonError(SetupPost("} invalid json {"), f);
        }

        private static void VerifyJsonError(RestFlow flow, Action<RestFlow> f)
        {
            var e = Exceptions.AssertThrowsInternalError(() => f(flow));
            Assert.IsAssignableFrom<JsonException>(e.InnerException);
        }

        private static RestFlow SetupGet(string response)
        {
            return new RestFlow().Get(response);
        }

        private RestFlow SetupGetWithFixture(string name)
        {
            return SetupGet(GetFixture(name));
        }

        private static RestFlow SetupPost(string response)
        {
            return new RestFlow().Post(response);
        }

        private RestFlow SetupPostWithFixture(string name)
        {
            return SetupPost(GetFixture(name));
        }

        // The Ui that always says "Check"
        private class CheckUi : Ui
        {
            public override Answer AskToWaitForEmail(string email, Answer[] validAnswers) => Answer.Check;
            public override Answer AskToWaitForOob(string name, string email, Answer[] validAnswers) => Answer.Check;
            public override Answer AskToChooseOob(string[] names, string email, Answer[] validAnswers) => Answer.Email;
        }

        //
        // Data
        //

        private const string Username = "username@example.com";
        private const string Password123 = "Password123";
        private const string DeviceName = "truekey-sharp";

        private const string ClientToken = "AQCmAwEAAh4AAAAAWMajHQAAGU9DUkEtMTpIT1RQLVNIQTI1Ni" +
                                           "0wOlFBMDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                                           "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
                                           "AAAAAAAAAAAAAAAAAAAAAAAAAAIOiRfItpCTOkvq0ZfV2+GgvP" +
                                           "83aF9SrTBfOuabZfcQr9AAAAAAgAIBwWTZpUTIn493Us/Jwczr" +
                                           "K6O0+LH8FRidFaZkJ2AlTu";

        private const string DeviceId = "d871347bd0a3e7af61f60f511bc7de5e944c5c778705649d4aa8d" +
                                        "c77bcd21489412894";

        // TODO: Remove copy paste
        private const string MasterKeySaltHex = "845864cf3692189757f5f276b37c2981bdceefea04905" +
                                                "699685ad0541c4f9092";
        private const string EncryptedMasterKeyBase64 = "AARZxaQ5EeiK9GlqAkz+BzTwb1cO+b8yMN+SC" +
                                                        "t3bzQJO+Fyf4TnlA83Mbl1KrMI09iOd9VQJJl" +
                                                        "u4ivWMwCYhMB6Mw3LOoyS/2UjqmCnxAUqo6MT" +
                                                        "SnptgjlWO";


        private static readonly byte[] MasterKeySalt = MasterKeySaltHex.DecodeHex();
        private static readonly byte[] EncryptedMasterKey = EncryptedMasterKeyBase64.Decode64();

        private static readonly Client.DeviceInfo DeviceInfo = new Client.DeviceInfo(
            token: ClientToken,
            id: DeviceId);

        private static readonly Util.OtpInfo OtpInfo = new Util.OtpInfo(
            version: 3,
            otpAlgorithm: 1,
            otpLength: 0,
            hashAlgorithm: 2,
            timeStep: 30,
            startTime: 0,
            suite: "OCRA-1:HOTP-SHA256-0:QA08".ToBytes(),
            hmacSeed: "6JF8i2kJM6S+rRl9Xb4aC8/zdoX1KtMF865ptl9xCv0=".Decode64(),
            iptmk: "HBZNmlRMifj3dSz8nBzOsro7T4sfwVGJ0VpmQnYCVO4=".Decode64());

        private static readonly Client.ClientInfo ClientInfo = new Client.ClientInfo(
            username: Username,
            name: DeviceName,
            deviceInfo: DeviceInfo,
            otpInfo: OtpInfo);
    }
}
