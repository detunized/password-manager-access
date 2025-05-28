// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using FluentAssertions;
using FluentAssertions.Execution;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.OpenSsl;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.OnePassword;
using PasswordManagerAccess.OnePassword.Ui;
using Xunit;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class ClientTest : TestBase
    {
        [Fact]
        public void ParseServiceAccountToken_returns_parsed_token()
        {
            var parsed = Client.ParseServiceAccountToken(TestData.ServiceAccountAccessToken);

            Assert.Equal("3joey3mfq7yws@1passwordserviceaccounts.com", parsed.Username);
            Assert.Null(parsed.Password);
            Assert.Equal("A3-Y6T9TL-NYJW82-344C5-GTHJQ-YWGD6-NWC2J", parsed.AccountKey);
            Assert.Equal("lastpassruby-team.1password.com", parsed.Domain);
            Assert.Equal("qv557zvdo2kbta4z6x3t2shuby", parsed.DeviceUuid);
            Assert.Equal("40cda13824f823d28b8bc34ee0c35581ea5195e09e599e4992d33b3fa8179525", parsed.SrpX);
            Assert.Equal("5FsPUVlIqJwvn5OBdqXbB1zWYG3CVJ6fmWxlZ8zchjk", parsed.Key.Key.ToUrlSafeBase64NoPadding());
        }

        [Theory]
        [InlineData("")]
        [InlineData("blah-blah-blah")]
        [InlineData("ops_")]
        [InlineData("e30")]
        [InlineData("ops_e30")]
        public void ParseServiceAccountToken_throws_on_invalid_token(string token)
        {
            Exceptions.AssertThrowsInternalError(() => Client.ParseServiceAccountToken(token), "Invalid service account token");
        }

        [Fact]
        public void ListAllVaults_returns_vaults()
        {
            var flow = new RestFlow().Get(EncryptFixture("get-account-info-response")).Get(EncryptFixture("get-keysets-response"));
            var vaults = Client.ListAllVaults(Credentials, new Keychain(), TestData.SessionKey, flow);

            Assert.NotEmpty(vaults);
        }

        [Fact]
        public void StartNewSession_returns_session_on_ok()
        {
            var flow = new RestFlow().Get(GetFixture("start-new-session-response"));
            var (sessionId, srpInfo) = Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow);

            Assert.Equal(TestData.SessionId, sessionId);
            Assert.Equal(TestData.SrpInfo.SrpMethod, srpInfo.SrpMethod);
            Assert.Equal(TestData.SrpInfo.KeyMethod, srpInfo.KeyMethod);
            Assert.Equal(TestData.SrpInfo.Iterations, srpInfo.Iterations);
            Assert.Equal(TestData.SrpInfo.Salt, srpInfo.Salt);
        }

        [Fact]
        public void StartNewSession_makes_GET_request_to_specific_url()
        {
            var flow = new RestFlow().Get(GetFixture("start-new-session-response")).ExpectUrl("1password.com/api/v2/auth").ToRestClient(ApiUrl);

            Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow);
        }

        [Fact]
        public void StartNewSession_throws_on_unknown_status()
        {
            var flow = new RestFlow().Get("{'status': 'unknown', 'sessionID': 'blah'}");

            Exceptions.AssertThrowsInternalError(
                () => Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow),
                "Failed to start a new session, unsupported response status"
            );
        }

        [Fact]
        public void StartNewSession_throws_on_network_error()
        {
            var error = new HttpRequestException("Network error");
            var flow = new RestFlow().Get(error);

            var e = Exceptions.AssertThrowsNetworkError(() => Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow), "Network error");
            Assert.Same(error, e.InnerException);
        }

        [Fact]
        public void StartNewSession_throws_on_invalid_json()
        {
            var flow = new RestFlow().Get("{'reason': 'deprecated'}", HttpStatusCode.Forbidden);

            Exceptions.AssertThrowsInternalError(
                () => Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow),
                "The server responded with the failure reason: 'deprecated'"
            );
        }

        [Fact]
        public void StartNewSession_reports_failure_reason()
        {
            var flow = new RestFlow().Get("} invalid json {");

            Exceptions.AssertThrowsInternalError(
                () => Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow),
                "Invalid or unexpected response"
            );
        }

        [Fact]
        public void RegisterDevice_works()
        {
            var flow = new RestFlow().Post("{'success': 1}");

            Client.RegisterDevice(TestData.DeviceUuid, TestData.AppInfo, flow);
        }

        [Fact]
        public void RegisterDevice_makes_POST_request_to_specific_url()
        {
            var flow = new RestFlow().Post("{'success': 1}").ExpectUrl("1password.com/api/v1/device").ToRestClient(ApiUrl);

            Client.RegisterDevice(TestData.DeviceUuid, TestData.AppInfo, flow);
        }

        [Fact]
        public void RegisterDevice_throws_on_error()
        {
            var flow = new RestFlow().Post("{'success': 0}");

            Exceptions.AssertThrowsInternalError(
                () => Client.RegisterDevice(TestData.DeviceUuid, TestData.AppInfo, flow),
                "Failed to register the device"
            );
        }

        [Fact]
        public void ReauthorizeDevice_works()
        {
            var flow = new RestFlow().Put("{'success': 1}");

            Client.ReauthorizeDevice(TestData.DeviceUuid, TestData.AppInfo, flow);
        }

        [Fact]
        public void ReauthorizeDevice_makes_PUT_request_to_specific_url()
        {
            var flow = new RestFlow().Put("{'success': 1}").ExpectUrl("1password.com/api/v1/device").ToRestClient(ApiUrl);

            Client.ReauthorizeDevice(TestData.DeviceUuid, TestData.AppInfo, flow);
        }

        [Fact]
        public void ReauthorizeDevice_throws_on_error()
        {
            var flow = new RestFlow().Put("{'success': 0}");

            Exceptions.AssertThrowsInternalError(
                () => Client.ReauthorizeDevice(TestData.DeviceUuid, TestData.AppInfo, flow),
                "Failed to reauthorize the device"
            );
        }

        [Fact]
        public void VerifySessionKey_returns_success()
        {
            var flow = new RestFlow().Post(EncryptFixture("verify-key-response"));
            var result = Client.VerifySessionKey(TestData.Credentials, TestData.AppInfo, TestData.SessionKey, flow);

            Assert.Equal(Client.VerifyStatus.Success, result.Status);
        }

        [Fact]
        public void VerifySessionKey_makes_POST_request_to_specific_url()
        {
            var flow = new RestFlow().Post(EncryptFixture("verify-key-response")).ExpectUrl("1password.com/api/v2/auth/verify").ToRestClient(ApiUrl);

            Client.VerifySessionKey(TestData.Credentials, TestData.AppInfo, TestData.SessionKey, flow);
        }

        [Fact]
        public void VerifySessionKey_returns_factors()
        {
            var flow = new RestFlow().Post(EncryptFixture("verify-key-response-mfa"));
            var result = Client.VerifySessionKey(TestData.Credentials, TestData.AppInfo, TestData.SessionKey, flow);

            Assert.Equal(3, result.Factors.Length);
        }

        [Fact]
        public void VerifySessionKey_throws_BadCredentials_on_auth_error()
        {
            var flow = new RestFlow().Post(EncryptFixture("no-auth-response"));

            Exceptions.AssertThrowsBadCredentials(
                () => Client.VerifySessionKey(TestData.Credentials, TestData.AppInfo, TestData.SessionKey, flow),
                "Username, password or account key"
            );
        }

        [Fact]
        public void GetSecondFactors_returns_factors()
        {
            var expected = new[]
            {
                Client.SecondFactorKind.GoogleAuthenticator,
                Client.SecondFactorKind.RememberMeToken,
                Client.SecondFactorKind.Duo,
            };
            var mfa = JsonConvert.DeserializeObject<R.MfaInfo>(
                "{" + "'duo': {'enabled': true}, " + "'totp': {'enabled': true}, " + "'dsecret': {'enabled': true}" + "}"
            );
            var factors = Client.GetSecondFactors(mfa).Select(x => x.Kind).ToArray();

            Assert.Equal(expected, factors);
        }

        [Fact]
        public void GetSecondFactors_ignores_missing_factors()
        {
            var expected = new[] { Client.SecondFactorKind.GoogleAuthenticator };
            var mfa = JsonConvert.DeserializeObject<R.MfaInfo>("{'totp': {'enabled': true}}");
            var factors = Client.GetSecondFactors(mfa).Select(x => x.Kind).ToArray();

            Assert.Equal(expected, factors);
        }

        [Fact]
        public void GetSecondFactors_ignores_disabled_factors()
        {
            var expected = new[] { Client.SecondFactorKind.GoogleAuthenticator };
            var mfa = JsonConvert.DeserializeObject<R.MfaInfo>(
                "{" + "'duo': {'enabled': false}, " + "'totp': {'enabled': true}, " + "'dsecret': {'enabled': false}" + "}"
            );
            var factors = Client.GetSecondFactors(mfa).Select(x => x.Kind).ToArray();

            Assert.Equal(expected, factors);
        }

        [Fact]
        public void PerformSecondFactorAuthentication_throws_on_canceled_mfa()
        {
            var flow = new RestFlow();

            Exceptions.AssertThrowsCanceledMultiFactor(
                () => Client.PerformSecondFactorAuthentication(GoogleAuthFactors, Credentials, TestData.SessionKey, new CancelingUi(), null, flow),
                "Second factor step is canceled by the user"
            );
        }

        [Fact]
        public void ChooseInteractiveSecondFactor_returns_high_priority_factor()
        {
            var factors = new[]
            {
                new Client.SecondFactor(Client.SecondFactorKind.GoogleAuthenticator),
                new Client.SecondFactor(Client.SecondFactorKind.Duo),
            };
            var chosen = Client.ChooseInteractiveSecondFactor(factors);

            Assert.Equal(Client.SecondFactorKind.Duo, chosen.Kind);
        }

        [Fact]
        public void ChooseInteractiveSecondFactor_throws_on_empty_factors()
        {
            Exceptions.AssertThrowsInternalError(
                () => Client.ChooseInteractiveSecondFactor(new Client.SecondFactor[0]),
                "The list of 2FA methods is empty"
            );
        }

        [Fact]
        public void ChooseInteractiveSecondFactor_throws_on_missing_factors()
        {
            var factors = new[] { new Client.SecondFactor(Client.SecondFactorKind.RememberMeToken) };

            Exceptions.AssertThrowsInternalError(() => Client.ChooseInteractiveSecondFactor(factors), "doesn't contain any supported methods");
        }

        [Fact]
        public void SubmitSecondFactorCode_returns_remember_me_token()
        {
            var flow = new RestFlow().Post(EncryptFixture("mfa-response"));
            var token = Client.SubmitSecondFactorResult(Client.SecondFactorKind.GoogleAuthenticator, GoogleAuthMfaResult, TestData.SessionKey, flow);

            Assert.Equal("gUhBItRHUI7vAc04TJNUkA", token);
        }

        [Fact]
        public void SubmitSecondFactorCode_makes_POST_request_to_specific_url()
        {
            var flow = new RestFlow().Post(EncryptFixture("mfa-response")).ExpectUrl("1password.com/api/v1/auth/mfa").ToRestClient(ApiUrl);

            Client.SubmitSecondFactorResult(Client.SecondFactorKind.GoogleAuthenticator, GoogleAuthMfaResult, TestData.SessionKey, flow);
        }

        [Fact]
        public void SubmitSecondFactorCode_throws_BadMultiFactor_on_auth_error()
        {
            var flow = new RestFlow().Post(EncryptFixture("no-auth-response"));

            Exceptions.AssertThrowsBadMultiFactor(
                () => Client.SubmitSecondFactorResult(Client.SecondFactorKind.GoogleAuthenticator, GoogleAuthMfaResult, TestData.SessionKey, flow),
                "Incorrect second factor code"
            );
        }

        [Fact]
        public void GetAccountInfo_works()
        {
            var flow = new RestFlow().Get(EncryptFixture("get-account-info-response"));

            Client.GetAccountInfo(TestData.SessionKey, flow);
        }

        [Fact]
        public void GetAccountInfo_makes_GET_request_to_specific_url()
        {
            var flow = new RestFlow().Get(EncryptFixture("get-account-info-response")).ExpectUrl("1password.com/api/v1/account").ToRestClient(ApiUrl);

            Client.GetAccountInfo(TestData.SessionKey, flow);
        }

        [Fact]
        public void GetKeysets_works()
        {
            var flow = new RestFlow().Get(EncryptFixture("get-keysets-response"));

            Client.GetKeysets(TestData.SessionKey, flow);
        }

        [Fact]
        public void GetKeysets_makes_GET_request_to_specific_url()
        {
            var flow = new RestFlow()
                .Get(EncryptFixture("get-keysets-response"))
                .ExpectUrl("1password.com/api/v1/account/keysets")
                .ToRestClient(ApiUrl);

            Client.GetKeysets(TestData.SessionKey, flow);
        }

        [Fact]
        public void GetVaultAccounts_returns_accounts()
        {
            var flow = new RestFlow().Get(EncryptFixture("get-vault-accounts-ru74-response"));
            var keychain = new Keychain(
                new AesKey("x4ouqoqyhcnqojrgubso4hsdga", "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex())
            );

            var (accounts, _) = Client.GetVaultItems("ru74fjxlkipzzctorwj4icrj2a", keychain, TestData.SessionKey, flow);

            Assert.NotEmpty(accounts);
        }

        [Fact]
        public void GetVaultAccounts_returns_ssh_keys()
        {
            // Arrange
            var flow = new RestFlow().Get(EncryptFixture("get-vault-accounts-ixsi-response"));
            var keychain = new Keychain(
                new AesKey("i32wahdpkpvhog37mtsnqzy4bm", "91bbd5df47ba0de2437a8ed1fbb9064cc9d3ad78ea472516fb5192263ec46e7d".DecodeHex())
            );

            // Act
            var (_, sshKeys) = Client.GetVaultItems("ixsi7ub55tanrwgvbyvn7cjpha", keychain, TestData.SessionKey, flow);

            // Assert
            sshKeys.Should().HaveCount(4);
            sshKeys.Should().ContainSingle(x => x.Name == "ssh-key-1");

            var key = sshKeys.First(x => x.Name == "ssh-key-1");
            key.Description.Should().Be("SHA256:QB4tVGscKvicUwhQh/ozOCg7JUUj8h56zL3PIPuPGQs");
            key.Note.Should().Be("blah-blah notes");
            key.PrivateKey.Should().StartWith("-----BEGIN PRIVATE KEY-----\nMIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDaUFtI3U5Zq4gQ");
            key.PublicKey.Should().StartWith("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDaUFtI3");
            key.Fingerprint.Should().Be("SHA256:QB4tVGscKvicUwhQh/ozOCg7JUUj8h56zL3PIPuPGQs");
            key.KeyType.Should().Be("rsa-4096");
        }

        [Fact]
        public void GetVaultAccounts_returns_converts_ssh_keys()
        {
            // Arrange
            var flow = new RestFlow().Get(EncryptFixture("get-vault-accounts-saiw-response"));
            var keychain = new Keychain(
                new AesKey("3hhlvfccmm4253ou43jfrgty3m", "b357079312198b155764b4e6aa7709df357cf3779973d7451abda5f15d90379c".DecodeHex())
            );

            // Act
            var (_, sshKeys) = Client.GetVaultItems("3hhlvfccmm4253ou43jfrgty3m", keychain, TestData.SessionKey, flow);

            // Assert
            foreach (var sshKey in sshKeys)
            {
                // Use BouncyCastle to parse and compare the key parameters
                switch (sshKey.KeyType)
                {
                    case "rsa-2048":
                    case "rsa-3072":
                    case "rsa-4096":
                    {
                        var openSshKey = sshKey.GetPrivateKey(SshKeyFormat.OpenSsh);
                        openSshKey.Should().StartWith("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG");

                        var pkcs8Key = sshKey.GetPrivateKey(SshKeyFormat.Pkcs8);
                        pkcs8Key.Should().StartWith("-----BEGIN PRIVATE KEY-----\nMII");

                        var pkcs1Key = sshKey.GetPrivateKey(SshKeyFormat.Pkcs1);
                        pkcs1Key.Should().StartWith("-----BEGIN RSA PRIVATE KEY-----\nMII");

                        var openSsh = ParseOpenSshPrivateKey(openSshKey);

                        var pkcs8 = ParsePkcs8PrivateKey(pkcs8Key);
                        pkcs8.Should().BeOfType<RsaPrivateCrtKeyParameters>();

                        var pkcs1 = ParsePkcs1PrivateKey(pkcs1Key);
                        pkcs1.Should().BeOfType<RsaPrivateCrtKeyParameters>();

                        var rsaSsh = (RsaPrivateCrtKeyParameters)openSsh;
                        var rsa8 = (RsaPrivateCrtKeyParameters)pkcs8;
                        var rsa1 = (RsaPrivateCrtKeyParameters)pkcs1;

                        rsaSsh.Modulus.Should().Be(rsa8.Modulus);
                        rsaSsh.Modulus.Should().Be(rsa1.Modulus);

                        rsaSsh.PublicExponent.Should().Be(rsa8.PublicExponent);
                        rsaSsh.PublicExponent.Should().Be(rsa1.PublicExponent);

                        rsaSsh.Exponent.Should().Be(rsa8.Exponent);
                        rsaSsh.Exponent.Should().Be(rsa1.Exponent);

                        rsaSsh.P.Should().Be(rsa8.P);
                        rsaSsh.P.Should().Be(rsa1.P);

                        rsaSsh.Q.Should().Be(rsa8.Q);
                        rsaSsh.Q.Should().Be(rsa1.Q);

                        rsaSsh.DP.Should().Be(rsa8.DP);
                        rsaSsh.DP.Should().Be(rsa1.DP);

                        rsaSsh.DQ.Should().Be(rsa8.DQ);
                        rsaSsh.DQ.Should().Be(rsa1.DQ);

                        rsaSsh.QInv.Should().Be(rsa8.QInv);
                        rsaSsh.QInv.Should().Be(rsa1.QInv);

                        break;
                    }

                    case "ed25519":
                    {
                        var openSshKey = sshKey.GetPrivateKey(SshKeyFormat.OpenSsh);
                        openSshKey.Should().StartWith("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG");

                        var pkcs8Key = sshKey.GetPrivateKey(SshKeyFormat.Pkcs8);
                        pkcs8Key.Should().StartWith("-----BEGIN PRIVATE KEY-----\nM");

                        var pkcs1Key = sshKey.GetPrivateKey(SshKeyFormat.Pkcs1);
                        pkcs1Key.Should().Be("");

                        var openSsh = ParseOpenSshPrivateKey(openSshKey);
                        openSsh.Should().BeOfType<Ed25519PrivateKeyParameters>();

                        var pkcs8 = ParsePkcs8PrivateKey(pkcs8Key);
                        pkcs8.Should().BeOfType<Ed25519PrivateKeyParameters>();

                        var edSsh = (Ed25519PrivateKeyParameters)openSsh;
                        var ed8 = (Ed25519PrivateKeyParameters)pkcs8;

                        edSsh.GetEncoded().Should().BeEquivalentTo(ed8.GetEncoded());
                        edSsh.GetEncoded().Should().HaveCount(32);

                        break;
                    }

                    default:
                    {
                        Execute.Assertion.FailWith($"Unknown SSH key type: {sshKey.KeyType}");
                        break;
                    }
                }

                // Verify the original keys are in the right format
                if (sshKey.Name.Contains("openssh imported"))
                    sshKey.GetPrivateKey(SshKeyFormat.Original).Should().StartWith("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl");
                else if (sshKey.Name.Contains("pkcs8 imported"))
                    sshKey.GetPrivateKey(SshKeyFormat.Original).Should().StartWith("-----BEGIN PRIVATE KEY-----\nM");
                else if (sshKey.Name.Contains("pkcs1 imported"))
                    sshKey.GetPrivateKey(SshKeyFormat.Original).Should().StartWith("-----BEGIN RSA PRIVATE KEY-----\nMII");
            }
        }

        [Fact]
        public void GetVaultAccounts_with_no_items_work()
        {
            var flow = new RestFlow().Get(EncryptFixture("get-vault-with-no-items-response"));
            var keychain = new Keychain(
                new AesKey("x4ouqoqyhcnqojrgubso4hsdga", "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex())
            );

            var (accounts, _) = Client.GetVaultItems("ru74fjxlkipzzctorwj4icrj2a", keychain, TestData.SessionKey, flow);

            Assert.Empty(accounts);
        }

        [Fact]
        public void GetVaultAccounts_returns_server_secrets()
        {
            var flow = new RestFlow().Get(EncryptFixture("get-vault-with-server-secrets-response"));
            var keychain = new Keychain(
                new AesKey("e2e2ungb5d4tl7ls4ohxwhtd2e", "518f5d0f72d118252c4a5ac0b87af54210bb0f4aee0210fe8adbe3343c8a11ea".DecodeHex())
            );

            var (accounts, _) = Client.GetVaultItems("6xkojw55yh4uo4vtdewghr5boi", keychain, TestData.SessionKey, flow);

            Assert.Contains(accounts, x => x.Name == "server-test");
        }

        [Fact]
        public void GetVaultAccounts_makes_GET_request_to_specific_url()
        {
            var flow = new RestFlow()
                .Get(EncryptFixture("get-vault-accounts-ru74-response"))
                .ExpectUrl("1password.com/api/v1/vault")
                .ToRestClient(ApiUrl);
            var keychain = new Keychain(
                new AesKey("x4ouqoqyhcnqojrgubso4hsdga", "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex())
            );

            Client.GetVaultItems("ru74fjxlkipzzctorwj4icrj2a", keychain, TestData.SessionKey, flow);
        }

        [Fact]
        public void GetVaultAccounts_with_multiple_batches_returns_all_accounts()
        {
            var flow = new RestFlow()
                .Get(EncryptFixture("get-vault-accounts-ru74-batch-1-response"))
                .Get(EncryptFixture("get-vault-accounts-ru74-batch-2-response"))
                .Get(EncryptFixture("get-vault-accounts-ru74-batch-3-response"));
            var keychain = new Keychain(
                new AesKey("x4ouqoqyhcnqojrgubso4hsdga", "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex())
            );

            var (accounts, _) = Client.GetVaultItems("ru74fjxlkipzzctorwj4icrj2a", keychain, TestData.SessionKey, flow);

            Assert.Equal(3, accounts.Length);
        }

        [Fact]
        public void LogOut_works()
        {
            var flow = new RestFlow().Put("{'success': 1}");

            Client.LogOut(flow);
        }

        [Fact]
        public void LogOut_makes_PUT_request_to_specific_url()
        {
            var flow = new RestFlow().Put("{'success': 1}").ExpectUrl("1password.com/api/v1/session/signout").ToRestClient(ApiUrl);

            Client.LogOut(flow);
        }

        [Fact]
        public void LogOut_throws_on_bad_response()
        {
            var flow = new RestFlow().Put("{'success': 0}");

            Exceptions.AssertThrowsInternalError(() => Client.LogOut(flow), "Failed to logout");
        }

        [Fact]
        public void DecryptKeyset_decrypts_all_keys()
        {
            var keysets = ParseFixture<R.KeysetsInfo>("get-keysets-response");
            var keychain = new Keychain();
            Client.DecryptKeysets(keysets.Keysets, Credentials, keychain);

            // Master key
            Assert.NotNull(keychain.GetAes("mp"));

            var keysetIds = new[]
            {
                "szerdhg2ww2ahjo4ilz57x7cce",
                "yf2ji37vkqdow7pnbo3y37b3lu",
                "srkx3r5c3qgyzsdswfc4awgh2m",
                "sm5hkw3mxwdcwcgljf4kyplwea",
            };

            foreach (var i in keysetIds)
            {
                Assert.NotNull(keychain.GetAes(i));
                Assert.NotNull(keychain.GetRsa(i));
            }
        }

        [Fact]
        public void DeriveMasterKey_returns_master_key()
        {
            var expected = "09f6cf6acc4f64f2ac6af5d912427253c4dd5e1a48dfc6bfea21df8f6d3a701e".DecodeHex();
            var key = Client.DeriveMasterKey("PBES2g-HS256", 100000, "i2enf0xq-XPKCFFf5UZqNQ".Decode64Loose(), TestData.Credentials);

            Assert.Equal("mp", key.Id);
            Assert.Equal(expected, key.Key);
        }

        [Fact]
        public void GetApiUrl_returns_correct_url()
        {
            Assert.Equal("https://my.1password.com/api", Client.GetApiUrl("my.1password.com"));
            Assert.Equal("https://my.1password.eu/api", Client.GetApiUrl("my.1password.eu"));
        }

        [Fact]
        public void MakeRestClient_sets_base_url()
        {
            var rest = Client.MakeRestClient(null, "https://base.url");
            Assert.Equal("https://base.url", rest.BaseUrl);
        }

        [Fact]
        public void MakeRestClient_copies_base_url()
        {
            var rest = Client.MakeRestClient(new RestClient(null, "https://base.url"));
            Assert.Equal("https://base.url", rest.BaseUrl);
        }

        //
        // Helpers
        //

        private class NotImplementedUi : IUi
        {
            public virtual Passcode ProvideGoogleAuthPasscode() => throw new NotImplementedException();

            public virtual Passcode ProvideWebAuthnRememberMe() => throw new NotImplementedException();

            public virtual DuoChoice ChooseDuoFactor(DuoDevice[] devices) => throw new NotImplementedException();

            public virtual string ProvideDuoPasscode(DuoDevice device) => throw new NotImplementedException();

            public virtual void UpdateDuoStatus(DuoStatus status, string text) => throw new NotImplementedException();
        }

        private class CancelingUi : NotImplementedUi
        {
            public override Passcode ProvideGoogleAuthPasscode() => Passcode.Cancel;

            public override Passcode ProvideWebAuthnRememberMe() => Passcode.Cancel;
        }

        private string EncryptFixture(string name)
        {
            return EncryptBytes(GetFixture(name).ToBytes());
        }

        private string EncryptBytes(byte[] bytes)
        {
            var encrypted = TestData.SessionKey.Encrypt(bytes);
            return JsonConvert.SerializeObject(encrypted.ToDictionary());
        }

        private static AsymmetricKeyParameter ParseOpenSshPrivateKey(string privateKey)
        {
            using var pemReader = new PemReader(new StringReader(privateKey));
            return OpenSshPrivateKeyUtilities.ParsePrivateKeyBlob(pemReader.ReadPemObject().Content);
        }

        private static AsymmetricKeyParameter ParsePkcs8PrivateKey(string privateKey)
        {
            using var pemReader = new PemReader(new StringReader(privateKey));
            return (AsymmetricKeyParameter)pemReader.ReadObject();
        }

        private static AsymmetricKeyParameter ParsePkcs1PrivateKey(string privateKey)
        {
            using var pemReader = new PemReader(new StringReader(privateKey));
            return ((AsymmetricCipherKeyPair)pemReader.ReadObject()).Private;
        }

        //
        // Data
        //

        private const string ApiUrl = "https://my.1password.com/api";

        private static readonly Client.SecondFactor[] GoogleAuthFactors = { new Client.SecondFactor(Client.SecondFactorKind.GoogleAuthenticator) };

        private static readonly Client.SecondFactorResult GoogleAuthMfaResult = Client.SecondFactorResult.Done(
            new Dictionary<string, string> { ["code"] = "123456" },
            false
        );

        // TODO: All the tests here use the data from this account. I don't care about the account
        //       or exposing its credentials, but I don't want to have inconsistent test data.
        //       Everything should be either re-encrypted or somehow harmonized across all the tests
        //       to use the same username, password and account key.
        private static readonly Credentials Credentials = new Credentials
        {
            Username = "detunized@gmail.com",
            Password = "Dk%hnM9q2xLY5z6Pe#t&Wutt8L&^W!sz",
            AccountKey = "A3-FRN8GF-RBDFX9-6PFY4-6A5E5-457F5-999GY",
            DeviceUuid = "rz64r4uhyvgew672nm4ncaqonq",
            Domain = "my.1password.com",
        };
    }
}
