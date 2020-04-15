// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using Moq;
using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class RemoteTest: TestBase
    {
        [Fact]
        public void RegisetNewDevice_returns_device_info()
        {
            var client = SetupPostWithFixture("register-new-device-response");
            var result = Remote.RegisetNewDevice("truekey-sharp", client.Object);

            Assert.StartsWith("AQCmAwEA", result.Token);
            Assert.StartsWith("d871347b", result.Id);
        }

        [Fact]
        public void RegisetNewDevice_throws_on_common_errors()
        {
            VerifyAllCommonErrorsWithPost(http => Remote.RegisetNewDevice("truekey-sharp", http));
        }

        [Fact]
        public void AuthStep1_returns_transaction_id()
        {
            var client = SetupPostWithFixture("auth-step1-response");
            var result = Remote.AuthStep1(ClientInfo, client.Object);

            Assert.Equal("6cdfcd43-065c-43a1-aa7a-017de98eefd0", result);
        }

        [Fact]
        public void AuthStep1_throws_on_common_errors()
        {
            VerifyAllCommonErrorsWithPost(http => Remote.AuthStep1(ClientInfo, http));
        }

        [Fact]
        public void AuthStep2_returns_two_factor_settings()
        {
            // TODO: Test with specifically crafted broken/unsupported responses
            //       The parsing logic is not trivial and it needs in-depth testing.

            var client = SetupPostWithFixture("auth-step2-response");
            var result = Remote.AuthStep2(ClientInfo, "password", "transaction-id", client.Object);

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
            VerifyAllCommonErrorsWithPost(
                http => Remote.AuthStep2(ClientInfo, "password", "transaction-id", http));
        }

        [Fact]
        public void SaveDeviceAsTrusted_works()
        {
            // TODO: Write a better test
            var client = SetupPost("{\"ResponseResult\" :{\"IsSuccess\": true}}");
            Remote.SaveDeviceAsTrusted(ClientInfo, "transaction-id", "oauth-token", client.Object);
        }

        [Fact]
        public void SaveDeviceAsTrusted_throws_on_common_errors()
        {
            VerifyMostCommonErrorsWithPost(http => Remote.SaveDeviceAsTrusted(ClientInfo,
                                                                              "transaction-id",
                                                                              "oauth-token",
                                                                              http));
        }

        [Fact]
        public void AuthCheck_returns_oauth_token()
        {
            var client = SetupPostWithFixture("auth-check-success-response");
            var result = Remote.AuthCheck(ClientInfo, "transaction-id", client.Object);

            Assert.StartsWith("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI", result);
        }

        [Fact]
        public void AuthCheck_throws_on_pending()
        {
            var client = SetupPostWithFixture("auth-check-pending-response");

            Assert.Throws<FetchException>(() => Remote.AuthCheck(ClientInfo, "transaction-id", client.Object));
        }

        [Fact]
        public void AuthCheck_throws_on_common_errors()
        {
            VerifyAllCommonErrorsWithPost(http => Remote.AuthCheck(ClientInfo, "transaction-id", http));
        }

        [Fact]
        public void GetVault_returns_encrypted_vault()
        {
            var client = SetupGetWithFixture("get-vault-response");
            var vault = Remote.GetVault("oauth-token", client.Object);

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
            VerifyCommonErrorsWithGet(http => Remote.GetVault("oauth-token", http));
        }

        //
        // Data
        //

        private const string Username = "username@example.com";
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

        private static readonly Remote.DeviceInfo DeviceInfo = new Remote.DeviceInfo(
            token: ClientToken,
            id: DeviceId);

        private static readonly Crypto.OtpInfo OtpInfo = new Crypto.OtpInfo(
            version: 3,
            otpAlgorithm: 1,
            otpLength: 0,
            hashAlgorithm: 2,
            timeStep: 30,
            startTime: 0,
            suite: "OCRA-1:HOTP-SHA256-0:QA08".ToBytes(),
            hmacSeed: "6JF8i2kJM6S+rRl9Xb4aC8/zdoX1KtMF865ptl9xCv0=".Decode64(),
            iptmk: "HBZNmlRMifj3dSz8nBzOsro7T4sfwVGJ0VpmQnYCVO4=".Decode64());

        private static readonly Remote.ClientInfo ClientInfo = new Remote.ClientInfo(
            username: Username,
            name: DeviceName,
            deviceInfo: DeviceInfo,
            otpInfo: OtpInfo);

        //
        // Helpers
        //

        private static void VerifyCommonErrorsWithGet(Action<IHttpClient> f)
        {
            VerifyNetworkErrorWithGet(f);
            VerifyJsonErrorWithGet(f);
            VerifyUnsupportedFormatWithGet(f);
        }

        private void VerifyAllCommonErrorsWithPost(Action<IHttpClient> f)
        {
            VerifyMostCommonErrorsWithPost(f);
            VerifyUnsupportedFormatWithPost(f);
        }

        private void VerifyMostCommonErrorsWithPost(Action<IHttpClient> f)
        {
            VerifyNetworkErrorWithPost(f);
            VerifyJsonErrorWithPost(f);
            VerifyReturnedErrorWithPost(f);
        }

        private static void VerifyNetworkErrorWithGet(Action<IHttpClient> f)
        {
            VerifyNetworkError(SetupGetWithFailure(), f);
        }

        private static void VerifyNetworkErrorWithPost(Action<IHttpClient> f)
        {
            VerifyNetworkError(SetupPostWithFailure(), f);
        }

        private static void VerifyNetworkError(Mock<IHttpClient> http, Action<IHttpClient> f)
        {
            VerifyError(FetchException.FailureReason.NetworkError, http, f);
        }

        private static void VerifyJsonErrorWithGet(Action<IHttpClient> f)
        {
            VerifyJsonError(SetupGet("} invalid json {"), f);
        }

        private static void VerifyJsonErrorWithPost(Action<IHttpClient> f)
        {
            VerifyJsonError(SetupPost("} invalid json {"), f);
        }

        private static void VerifyJsonError(Mock<IHttpClient> http, Action<IHttpClient> f)
        {
            VerifyError(FetchException.FailureReason.InvalidResponse, http, f);
        }

        private void VerifyReturnedErrorWithPost(Action<IHttpClient> f)
        {
            VerifyReturnedError(SetupPostWithFixture("post-response-with-error"), f);
        }

        private static void VerifyReturnedError(Mock<IHttpClient> http, Action<IHttpClient> f)
        {
            VerifyError(FetchException.FailureReason.RespondedWithError, http, f);
        }

        private static void VerifyUnsupportedFormatWithGet(Action<IHttpClient> f)
        {
            VerifyUnsupportedFormat(SetupGet("{}"), f);
            VerifyUnsupportedFormat(SetupGet("{\"customer\": {}}"), f);
            VerifyUnsupportedFormat(SetupGet("{\"customer\": {}, \"assets\": {}}"), f);
        }

        private static void VerifyUnsupportedFormatWithPost(Action<IHttpClient> f)
        {
            VerifyUnsupportedFormat(SetupPost("{}"), f);
            VerifyUnsupportedFormat(SetupPost("{\"ResponseResult\" :{}}"), f);
            VerifyUnsupportedFormat(SetupPost("{\"ResponseResult\" :{\"IsSuccess\": true}}"), f);
        }

        private static void VerifyUnsupportedFormat(Mock<IHttpClient> http, Action<IHttpClient> f)
        {
            VerifyError(FetchException.FailureReason.InvalidResponse, http, f);
        }

        private static void VerifyError(FetchException.FailureReason reason,
                                        Mock<IHttpClient> http,
                                        Action<IHttpClient> f)
        {
            Assert.Throws<FetchException>(() => f(http.Object));
        }

        private static Mock<IHttpClient> SetupGet(string response)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Get(It.IsAny<string>(),
                                  It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        private Mock<IHttpClient> SetupGetWithFixture(string name)
        {
            return SetupGet(GetFixture(name));
        }

        private static Mock<IHttpClient> SetupPost(string response)
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<Dictionary<string, object>>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Returns(response);
            return mock;
        }

        private Mock<IHttpClient> SetupPostWithFixture(string name)
        {
            return SetupPost(GetFixture(name));
        }

        private static Mock<IHttpClient> SetupGetWithFailure()
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Get(It.IsAny<string>(),
                                  It.IsAny<Dictionary<string, string>>()))
                .Throws<WebException>();
            return mock;
        }

        private static Mock<IHttpClient> SetupPostWithFailure()
        {
            var mock = new Mock<IHttpClient>();
            mock.Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<Dictionary<string, object>>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Throws<WebException>();
            return mock;
        }
    }
}
