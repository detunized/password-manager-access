// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using Newtonsoft.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.OpenSsl;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.OnePassword;
using PasswordManagerAccess.OnePassword.Ui;
using Shouldly;
using Xunit;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class ClientTest : TestBase
    {
        //
        // Public methods
        //

        [Fact]
        public void GetItem_returns_account()
        {
            // Arrange
            var transport = new RestFlow()
                .Get(EncryptFixture("get-vault-item-response"))
                .ExpectUrl("1password.com/api/v1/vault/ru74fjxlkipzzctorwj4icrj2a/item/wm3uxq4xsmb4mghxw6o3s7zrem");
            var rest = transport.ToRestClient(ApiUrl);
            var keychain = new Keychain(
                new AesKey("x4ouqoqyhcnqojrgubso4hsdga", "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex())
            );
            var session = new Session(TestData.Credentials, keychain, TestData.SessionKey, rest, transport);

            // Act
            var result = Client.GetItem("wm3uxq4xsmb4mghxw6o3s7zrem", "ru74fjxlkipzzctorwj4icrj2a", session);

            // Assert
            result.TryPickT0(out var account, out _).ShouldBeTrue();
            account.Id.ShouldBe("wm3uxq4xsmb4mghxw6o3s7zrem");
        }

        [Fact]
        public void GetItem_returns_NoItem_when_not_found()
        {
            // Arrange
            var transport = new RestFlow()
                .Get(GetFixture("get-vault-item-not-found-response"), HttpStatusCode.NotFound)
                .ExpectUrl("1password.com/api/v1/vault/ru74fjxlkipzzctorwj4icrj2a/item/nonexistent");
            var rest = transport.ToRestClient(ApiUrl);
            var keychain = new Keychain(
                new AesKey("x4ouqoqyhcnqojrgubso4hsdga", "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex())
            );
            var session = new Session(TestData.Credentials, keychain, TestData.SessionKey, rest, transport);

            // Act
            var result = Client.GetItem("nonexistent", "ru74fjxlkipzzctorwj4icrj2a", session);

            // Assert
            result.TryPickT2(out var noItem, out _).ShouldBeTrue();
            noItem.ShouldBe(NoItem.NotFound);
        }

        [Fact]
        public void ListAllVaults_returns_vaults()
        {
            // Arrange
            var flow = new RestFlow().Get(EncryptFixture("get-account-info-response")).Get(EncryptFixture("get-keysets-response"));

            // Act
            var vaults = Client.ListAllVaults(Credentials, new Keychain(), TestData.SessionKey, flow);

            // Assert
            vaults.ShouldNotBeEmpty();
        }

        //
        // Internal methods
        //

        [Fact]
        public void ParseServiceAccountToken_returns_parsed_token()
        {
            // Act
            var parsed = Client.ParseServiceAccountToken(TestData.ServiceAccountAccessToken);

            // Assert
            parsed.Username.ShouldBe("3joey3mfq7yws@1passwordserviceaccounts.com");
            parsed.Password.ShouldBeNull();
            parsed.AccountKey.ShouldBe("A3-Y6T9TL-NYJW82-344C5-GTHJQ-YWGD6-NWC2J");
            parsed.Domain.ShouldBe("lastpassruby-team.1password.com");
            parsed.DeviceUuid.ShouldBe("qv557zvdo2kbta4z6x3t2shuby");
            parsed.SrpX.ShouldBe("40cda13824f823d28b8bc34ee0c35581ea5195e09e599e4992d33b3fa8179525");
            parsed.Key.Key.ToUrlSafeBase64NoPadding().ShouldBe("5FsPUVlIqJwvn5OBdqXbB1zWYG3CVJ6fmWxlZ8zchjk");
        }

        [Theory]
        [InlineData("")]
        [InlineData("blah-blah-blah")]
        [InlineData("ops_")]
        [InlineData("e30")]
        [InlineData("ops_e30")]
        public void ParseServiceAccountToken_throws_on_invalid_token(string token)
        {
            // Act later
            var act = () => Client.ParseServiceAccountToken(token);

            // Assert
            var ex = act.ShouldThrow<InternalErrorException>();
            ex.Message.ShouldStartWith("Invalid service account token");
        }

        [Fact]
        public void StartNewSession_returns_session_on_ok()
        {
            // Arrange
            var flow = new RestFlow().Get(GetFixture("start-new-session-response"));

            // Act
            var (sessionId, srpInfo) = Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow);

            // Assert
            sessionId.ShouldBe(TestData.SessionId);
            srpInfo.SrpMethod.ShouldBe(TestData.SrpInfo.SrpMethod);
            srpInfo.KeyMethod.ShouldBe(TestData.SrpInfo.KeyMethod);
            srpInfo.Iterations.ShouldBe(TestData.SrpInfo.Iterations);
            srpInfo.Salt.ShouldBe(TestData.SrpInfo.Salt);
        }

        [Fact]
        public void StartNewSession_makes_GET_request_to_specific_url()
        {
            // Arrange
            var flow = new RestFlow().Get(GetFixture("start-new-session-response")).ExpectUrl("1password.com/api/v2/auth").ToRestClient(ApiUrl);

            // Act/Assert
            Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow);
        }

        [Fact]
        public void StartNewSession_throws_on_unknown_status()
        {
            // Arrange
            var flow = new RestFlow().Get("{'status': 'unknown', 'sessionID': 'blah'}");

            // Act later
            Action act = () => Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow);

            // Assert
            var ex = act.ShouldThrow<InternalErrorException>();
            ex.Message.ShouldStartWith("Failed to start a new session, unsupported response status");
        }

        [Fact]
        public void StartNewSession_throws_on_network_error()
        {
            // Arrange
            var error = new HttpRequestException("Network error");
            var flow = new RestFlow().Get(error);

            // Act later
            Action act = () => Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow);

            // Assert
            var ex = act.ShouldThrow<NetworkErrorException>();
            ex.InnerException.ShouldBe(error);
        }

        [Fact]
        public void StartNewSession_throws_on_invalid_json()
        {
            // Arrange
            var flow = new RestFlow().Get("{'reason': 'deprecated'}", HttpStatusCode.Forbidden);

            // Act later
            Action act = () => Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow);

            // Assert
            var ex = act.ShouldThrow<InternalErrorException>();
            ex.Message.ShouldBe("The server responded with the failure reason: 'deprecated'");
        }

        [Fact]
        public void StartNewSession_reports_failure_reason()
        {
            // Arrange
            var flow = new RestFlow().Get("} invalid json {");

            // Act later
            Action act = () => Client.StartNewSession(TestData.Credentials, TestData.AppInfo, flow);

            // Assert
            var ex = act.ShouldThrow<InternalErrorException>();
            ex.Message.ShouldStartWith("Invalid or unexpected response");
        }

        [Fact]
        public void RegisterDevice_works()
        {
            // Arrange
            var flow = new RestFlow().Post("{'success': 1}");

            // Act/Assert
            Client.RegisterDevice(TestData.DeviceUuid, TestData.AppInfo, flow);
        }

        [Fact]
        public void RegisterDevice_makes_POST_request_to_specific_url()
        {
            // Arrange
            var flow = new RestFlow().Post("{'success': 1}").ExpectUrl("1password.com/api/v1/device").ToRestClient(ApiUrl);

            // Act/Assert
            Client.RegisterDevice(TestData.DeviceUuid, TestData.AppInfo, flow);
        }

        [Fact]
        public void RegisterDevice_throws_on_error()
        {
            // Arrange
            var flow = new RestFlow().Post("{'success': 0}");

            // Act later
            Action act = () => Client.RegisterDevice(TestData.DeviceUuid, TestData.AppInfo, flow);

            // Assert
            var ex = act.ShouldThrow<InternalErrorException>();
            ex.Message.ShouldStartWith("Failed to register the device");
        }

        [Fact]
        public void ReauthorizeDevice_works()
        {
            // Arrange
            var flow = new RestFlow().Put("{'success': 1}");

            // Act/Assert
            Client.ReauthorizeDevice(TestData.DeviceUuid, TestData.AppInfo, flow);
        }

        [Fact]
        public void ReauthorizeDevice_makes_PUT_request_to_specific_url()
        {
            // Arrange
            var flow = new RestFlow().Put("{'success': 1}").ExpectUrl("1password.com/api/v1/device").ToRestClient(ApiUrl);

            // Act/Assert
            Client.ReauthorizeDevice(TestData.DeviceUuid, TestData.AppInfo, flow);
        }

        [Fact]
        public void ReauthorizeDevice_throws_on_error()
        {
            // Arrange
            var flow = new RestFlow().Put("{'success': 0}");

            // Act later
            Action act = () => Client.ReauthorizeDevice(TestData.DeviceUuid, TestData.AppInfo, flow);

            // Assert
            var ex = act.ShouldThrow<InternalErrorException>();
            ex.Message.ShouldStartWith("Failed to reauthorize the device");
        }

        [Fact]
        public void VerifySessionKey_returns_success()
        {
            // Arrange
            var flow = new RestFlow().Post(EncryptFixture("verify-key-response"));

            // Act
            var result = Client.VerifySessionKey(TestData.Credentials, TestData.AppInfo, TestData.SessionKey, flow);

            // Assert
            result.Status.ShouldBe(Client.VerifyStatus.Success);
        }

        [Fact]
        public void VerifySessionKey_makes_POST_request_to_specific_url()
        {
            // Arrange
            var flow = new RestFlow().Post(EncryptFixture("verify-key-response")).ExpectUrl("1password.com/api/v2/auth/verify").ToRestClient(ApiUrl);

            // Act/Assert
            Client.VerifySessionKey(TestData.Credentials, TestData.AppInfo, TestData.SessionKey, flow);
        }

        [Fact]
        public void VerifySessionKey_returns_factors()
        {
            // Arrange
            var flow = new RestFlow().Post(EncryptFixture("verify-key-response-mfa"));

            // Act
            var result = Client.VerifySessionKey(TestData.Credentials, TestData.AppInfo, TestData.SessionKey, flow);

            // Assert
            result.Factors.Length.ShouldBe(3);
        }

        [Fact]
        public void VerifySessionKey_throws_BadCredentials_on_auth_error()
        {
            // Arrange
            var flow = new RestFlow().Post(EncryptFixture("no-auth-response"));

            // Act later
            Action act = () => Client.VerifySessionKey(TestData.Credentials, TestData.AppInfo, TestData.SessionKey, flow);

            // Assert
            var ex = act.ShouldThrow<BadCredentialsException>();
            ex.Message.ShouldBe("Username, password or account key is incorrect");
        }

        [Fact]
        public void GetSecondFactors_returns_factors()
        {
            // Arrange
            var expected = new[]
            {
                Client.SecondFactorKind.GoogleAuthenticator,
                Client.SecondFactorKind.RememberMeToken,
                Client.SecondFactorKind.Duo,
            };
            var mfa = JsonConvert.DeserializeObject<R.MfaInfo>(
                """
                {
                    "duo": { "enabled": true },
                    "totp": { "enabled": true },
                    "dsecret": { "enabled": true }
                }
                """
            );

            // Act
            var factors = Client.GetSecondFactors(mfa).Select(x => x.Kind).ToArray();

            // Assert
            factors.ShouldBe(expected);
        }

        [Fact]
        public void GetSecondFactors_ignores_missing_factors()
        {
            // Arrange
            var expected = new[] { Client.SecondFactorKind.GoogleAuthenticator };
            var mfa = JsonConvert.DeserializeObject<R.MfaInfo>(
                """
                {
                    "totp": { "enabled": true }
                }
                """
            );

            // Act
            var factors = Client.GetSecondFactors(mfa).Select(x => x.Kind).ToArray();

            // Assert
            factors.ShouldBe(expected);
        }

        [Fact]
        public void GetSecondFactors_ignores_disabled_factors()
        {
            // Arrange
            var expected = new[] { Client.SecondFactorKind.GoogleAuthenticator };
            var mfa = JsonConvert.DeserializeObject<R.MfaInfo>(
                """
                {
                    "duo": { "enabled": false },
                    "totp": { "enabled": true },
                    "dsecret": { "enabled": false }
                }
                """
            );

            // Act
            var factors = Client.GetSecondFactors(mfa).Select(x => x.Kind).ToArray();

            // Assert
            factors.ShouldBe(expected);
        }

        [Fact]
        public void PerformSecondFactorAuthentication_throws_on_canceled_mfa()
        {
            // Arrange
            var flow = new RestFlow();

            // Act later
            Action act = () =>
                Client.PerformSecondFactorAuthentication(GoogleAuthFactors, Credentials, TestData.SessionKey, new CancelingUi(), null, flow);

            // Assert
            var ex = act.ShouldThrow<CanceledMultiFactorException>();
            ex.Message.ShouldBe("Second factor step is canceled by the user");
        }

        [Fact]
        public void ChooseInteractiveSecondFactor_returns_high_priority_factor()
        {
            // Arrange
            var factors = new[]
            {
                new Client.SecondFactor(Client.SecondFactorKind.GoogleAuthenticator),
                new Client.SecondFactor(Client.SecondFactorKind.Duo),
            };

            // Act
            var chosen = Client.ChooseInteractiveSecondFactor(factors);

            // Assert
            chosen.Kind.ShouldBe(Client.SecondFactorKind.Duo);
        }

        [Fact]
        public void ChooseInteractiveSecondFactor_throws_on_empty_factors()
        {
            // Act later
            Action act = () => Client.ChooseInteractiveSecondFactor(new Client.SecondFactor[0]);

            // Assert
            var ex = act.ShouldThrow<InternalErrorException>();
            ex.Message.ShouldBe("The list of 2FA methods is empty");
        }

        [Fact]
        public void ChooseInteractiveSecondFactor_throws_on_missing_factors()
        {
            // Arrange
            var factors = new[] { new Client.SecondFactor(Client.SecondFactorKind.RememberMeToken) };

            // Act later
            Action act = () => Client.ChooseInteractiveSecondFactor(factors);

            // Assert
            var ex = act.ShouldThrow<InternalErrorException>();
            ex.Message.ShouldBe("The list of 2FA methods doesn't contain any supported methods");
        }

        [Fact]
        public void SubmitSecondFactorCode_returns_remember_me_token()
        {
            // Arrange
            var flow = new RestFlow().Post(EncryptFixture("mfa-response"));

            // Act
            var token = Client.SubmitSecondFactorResult(Client.SecondFactorKind.GoogleAuthenticator, GoogleAuthMfaResult, TestData.SessionKey, flow);

            // Assert
            token.ShouldBe("gUhBItRHUI7vAc04TJNUkA");
        }

        [Fact]
        public void SubmitSecondFactorCode_makes_POST_request_to_specific_url()
        {
            // Arrange
            var flow = new RestFlow().Post(EncryptFixture("mfa-response")).ExpectUrl("1password.com/api/v1/auth/mfa").ToRestClient(ApiUrl);

            // Act/Assert
            Client.SubmitSecondFactorResult(Client.SecondFactorKind.GoogleAuthenticator, GoogleAuthMfaResult, TestData.SessionKey, flow);
        }

        [Fact]
        public void SubmitSecondFactorCode_throws_BadMultiFactor_on_auth_error()
        {
            // Arrange
            var flow = new RestFlow().Post(EncryptFixture("no-auth-response"));

            // Act later
            Action act = () =>
                Client.SubmitSecondFactorResult(Client.SecondFactorKind.GoogleAuthenticator, GoogleAuthMfaResult, TestData.SessionKey, flow);

            // Assert
            var ex = act.ShouldThrow<BadMultiFactorException>();
            ex.Message.ShouldBe("Incorrect second factor code");
        }

        [Fact]
        public void GetAccountInfo_works()
        {
            // Arrange
            var flow = new RestFlow().Get(EncryptFixture("get-account-info-response"));

            // Act/Assert
            Client.GetAccountInfo(TestData.SessionKey, flow);
        }

        [Fact]
        public void GetAccountInfo_makes_GET_request_to_specific_url()
        {
            // Arrange
            var flow = new RestFlow().Get(EncryptFixture("get-account-info-response")).ExpectUrl("1password.com/api/v1/account").ToRestClient(ApiUrl);

            // Act/Assert
            Client.GetAccountInfo(TestData.SessionKey, flow);
        }

        [Fact]
        public void GetKeysets_works()
        {
            // Arrange
            var flow = new RestFlow().Get(EncryptFixture("get-keysets-response"));

            // Act/Assert
            Client.GetKeysets(TestData.SessionKey, flow);
        }

        [Fact]
        public void GetKeysets_makes_GET_request_to_specific_url()
        {
            // Arrange
            var flow = new RestFlow()
                .Get(EncryptFixture("get-keysets-response"))
                .ExpectUrl("1password.com/api/v1/account/keysets")
                .ToRestClient(ApiUrl);

            // Act/Assert
            Client.GetKeysets(TestData.SessionKey, flow);
        }

        [Fact]
        public void GetVaultItems_returns_accounts()
        {
            // Arrange
            var flow = new RestFlow().Get(EncryptFixture("get-vault-accounts-ru74-response"));
            var keychain = new Keychain(
                new AesKey("x4ouqoqyhcnqojrgubso4hsdga", "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex())
            );

            // Act
            var (accounts, _) = Client.GetVaultItems("ru74fjxlkipzzctorwj4icrj2a", keychain, TestData.SessionKey, flow);

            // Assert
            accounts.ShouldNotBeEmpty();
        }

        [Fact]
        public void GetVaultItems_returns_ssh_keys()
        {
            // Arrange
            var flow = new RestFlow().Get(EncryptFixture("get-vault-accounts-ixsi-response"));
            var keychain = new Keychain(
                new AesKey("i32wahdpkpvhog37mtsnqzy4bm", "91bbd5df47ba0de2437a8ed1fbb9064cc9d3ad78ea472516fb5192263ec46e7d".DecodeHex())
            );

            // Act
            var (_, sshKeys) = Client.GetVaultItems("ixsi7ub55tanrwgvbyvn7cjpha", keychain, TestData.SessionKey, flow);

            // Assert
            sshKeys.Length.ShouldBe(4);
            sshKeys.Count(x => x.Name == "ssh-key-1").ShouldBe(1);

            var key = sshKeys.First(x => x.Name == "ssh-key-1");
            key.Description.ShouldBe("SHA256:QB4tVGscKvicUwhQh/ozOCg7JUUj8h56zL3PIPuPGQs");
            key.Note.ShouldBe("blah-blah notes");
            key.PrivateKey.ShouldStartWith("-----BEGIN PRIVATE KEY-----\nMIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDaUFtI3U5Zq4gQ");
            key.PublicKey.ShouldStartWith("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDaUFtI3");
            key.Fingerprint.ShouldBe("SHA256:QB4tVGscKvicUwhQh/ozOCg7JUUj8h56zL3PIPuPGQs");
            key.KeyType.ShouldBe("rsa-4096");
        }

        [Fact]
        public void GetVaultItems_returns_converts_ssh_keys()
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
                        openSshKey.ShouldStartWith("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG");

                        var pkcs8Key = sshKey.GetPrivateKey(SshKeyFormat.Pkcs8);
                        pkcs8Key.ShouldStartWith("-----BEGIN PRIVATE KEY-----\nMII");

                        var pkcs1Key = sshKey.GetPrivateKey(SshKeyFormat.Pkcs1);
                        pkcs1Key.ShouldStartWith("-----BEGIN RSA PRIVATE KEY-----\nMII");

                        var openSsh = ParseOpenSshPrivateKey(openSshKey);

                        var pkcs8 = ParsePkcs8PrivateKey(pkcs8Key);
                        pkcs8.ShouldBeOfType<RsaPrivateCrtKeyParameters>();

                        var pkcs1 = ParsePkcs1PrivateKey(pkcs1Key);
                        pkcs1.ShouldBeOfType<RsaPrivateCrtKeyParameters>();

                        var rsaSsh = (RsaPrivateCrtKeyParameters)openSsh;
                        var rsa8 = (RsaPrivateCrtKeyParameters)pkcs8;
                        var rsa1 = (RsaPrivateCrtKeyParameters)pkcs1;

                        rsaSsh.Modulus.ShouldBe(rsa8.Modulus);
                        rsaSsh.Modulus.ShouldBe(rsa1.Modulus);

                        rsaSsh.PublicExponent.ShouldBe(rsa8.PublicExponent);
                        rsaSsh.PublicExponent.ShouldBe(rsa1.PublicExponent);

                        rsaSsh.Exponent.ShouldBe(rsa8.Exponent);
                        rsaSsh.Exponent.ShouldBe(rsa1.Exponent);

                        rsaSsh.P.ShouldBe(rsa8.P);
                        rsaSsh.P.ShouldBe(rsa1.P);

                        rsaSsh.Q.ShouldBe(rsa8.Q);
                        rsaSsh.Q.ShouldBe(rsa1.Q);

                        rsaSsh.DP.ShouldBe(rsa8.DP);
                        rsaSsh.DP.ShouldBe(rsa1.DP);

                        rsaSsh.DQ.ShouldBe(rsa8.DQ);
                        rsaSsh.DQ.ShouldBe(rsa1.DQ);

                        rsaSsh.QInv.ShouldBe(rsa8.QInv);
                        rsaSsh.QInv.ShouldBe(rsa1.QInv);

                        break;
                    }

                    case "ed25519":
                    {
                        var openSshKey = sshKey.GetPrivateKey(SshKeyFormat.OpenSsh);
                        openSshKey.ShouldStartWith("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG");

                        var pkcs8Key = sshKey.GetPrivateKey(SshKeyFormat.Pkcs8);
                        pkcs8Key.ShouldStartWith("-----BEGIN PRIVATE KEY-----\nM");

                        var pkcs1Key = sshKey.GetPrivateKey(SshKeyFormat.Pkcs1);
                        pkcs1Key.ShouldBe("");

                        var openSsh = ParseOpenSshPrivateKey(openSshKey);
                        openSsh.ShouldBeOfType<Ed25519PrivateKeyParameters>();

                        var pkcs8 = ParsePkcs8PrivateKey(pkcs8Key);
                        pkcs8.ShouldBeOfType<Ed25519PrivateKeyParameters>();

                        var edSsh = (Ed25519PrivateKeyParameters)openSsh;
                        var ed8 = (Ed25519PrivateKeyParameters)pkcs8;

                        edSsh.GetEncoded().ShouldBe(ed8.GetEncoded());
                        edSsh.GetEncoded().Length.ShouldBe(32);

                        break;
                    }

                    default:
                    {
                        throw new InvalidOperationException($"Unknown SSH key type: {sshKey.KeyType}");
                    }
                }

                // Verify the original keys are in the right format
                if (sshKey.Name.Contains("openssh imported"))
                    sshKey.GetPrivateKey(SshKeyFormat.Original).ShouldStartWith("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl");
                else if (sshKey.Name.Contains("pkcs8 imported"))
                    sshKey.GetPrivateKey(SshKeyFormat.Original).ShouldStartWith("-----BEGIN PRIVATE KEY-----\nM");
                else if (sshKey.Name.Contains("pkcs1 imported"))
                    sshKey.GetPrivateKey(SshKeyFormat.Original).ShouldStartWith("-----BEGIN RSA PRIVATE KEY-----\nMII");
            }
        }

        [Fact]
        public void GetVaultItems_with_no_items_work()
        {
            // Arrange
            var flow = new RestFlow().Get(EncryptFixture("get-vault-with-no-items-response"));
            var keychain = new Keychain(
                new AesKey("x4ouqoqyhcnqojrgubso4hsdga", "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex())
            );

            // Act
            var (accounts, _) = Client.GetVaultItems("ru74fjxlkipzzctorwj4icrj2a", keychain, TestData.SessionKey, flow);

            // Assert
            accounts.ShouldBeEmpty();
        }

        [Fact]
        public void GetVaultItems_returns_server_secrets()
        {
            // Arrange
            var flow = new RestFlow().Get(EncryptFixture("get-vault-with-server-secrets-response"));
            var keychain = new Keychain(
                new AesKey("e2e2ungb5d4tl7ls4ohxwhtd2e", "518f5d0f72d118252c4a5ac0b87af54210bb0f4aee0210fe8adbe3343c8a11ea".DecodeHex())
            );

            // Act
            var (accounts, _) = Client.GetVaultItems("6xkojw55yh4uo4vtdewghr5boi", keychain, TestData.SessionKey, flow);

            // Assert
            accounts.ShouldContain(x => x.Name == "server-test");
        }

        [Fact]
        public void GetVaultItems_makes_GET_request_to_specific_url()
        {
            // Arrange
            var flow = new RestFlow()
                .Get(EncryptFixture("get-vault-accounts-ru74-response"))
                .ExpectUrl("1password.com/api/v1/vault")
                .ToRestClient(ApiUrl);
            var keychain = new Keychain(
                new AesKey("x4ouqoqyhcnqojrgubso4hsdga", "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex())
            );

            // Act/Assert
            Client.GetVaultItems("ru74fjxlkipzzctorwj4icrj2a", keychain, TestData.SessionKey, flow);
        }

        [Fact]
        public void GetVaultItems_with_multiple_batches_returns_all_accounts()
        {
            // Arrange
            var flow = new RestFlow()
                .Get(EncryptFixture("get-vault-accounts-ru74-batch-1-response"))
                .Get(EncryptFixture("get-vault-accounts-ru74-batch-2-response"))
                .Get(EncryptFixture("get-vault-accounts-ru74-batch-3-response"));
            var keychain = new Keychain(
                new AesKey("x4ouqoqyhcnqojrgubso4hsdga", "ce92c6d1af345c645211ad49692b22338d128d974e3b6718c868e02776c873a9".DecodeHex())
            );

            // Act
            var (accounts, _) = Client.GetVaultItems("ru74fjxlkipzzctorwj4icrj2a", keychain, TestData.SessionKey, flow);

            // Assert
            accounts.Length.ShouldBe(3);
        }

        [Fact]
        public void LogOut_works()
        {
            // Arrange
            var flow = new RestFlow().Put("{'success': 1}");

            // Act/Assert
            Client.LogOut(flow);
        }

        [Fact]
        public void LogOut_makes_PUT_request_to_specific_url()
        {
            // Arrange
            var flow = new RestFlow().Put("{'success': 1}").ExpectUrl("1password.com/api/v1/session/signout").ToRestClient(ApiUrl);

            // Act/Assert
            Client.LogOut(flow);
        }

        [Fact]
        public void LogOut_throws_on_bad_response()
        {
            // Arrange
            var flow = new RestFlow().Put("{'success': 0}");

            // Act later
            Action act = () => Client.LogOut(flow);

            // Assert
            var ex = act.ShouldThrow<InternalErrorException>();
            ex.Message.ShouldBe("Failed to logout");
        }

        [Fact]
        public void DecryptKeyset_decrypts_all_keys()
        {
            // Arrange
            var keysets = ParseFixture<R.KeysetsInfo>("get-keysets-response");
            var keychain = new Keychain();

            // Act
            Client.DecryptKeysets(keysets.Keysets, Credentials, keychain);

            // Assert
            keychain.GetAes("mp").ShouldNotBeNull();

            var keysetIds = new[]
            {
                "szerdhg2ww2ahjo4ilz57x7cce",
                "yf2ji37vkqdow7pnbo3y37b3lu",
                "srkx3r5c3qgyzsdswfc4awgh2m",
                "sm5hkw3mxwdcwcgljf4kyplwea",
            };

            foreach (var i in keysetIds)
            {
                keychain.GetAes(i).ShouldNotBeNull();
                keychain.GetRsa(i).ShouldNotBeNull();
            }
        }

        [Fact]
        public void DeriveMasterKey_returns_master_key()
        {
            // Arrange
            var expected = "09f6cf6acc4f64f2ac6af5d912427253c4dd5e1a48dfc6bfea21df8f6d3a701e".DecodeHex();

            // Act
            var key = Client.DeriveMasterKey("PBES2g-HS256", 100000, "i2enf0xq-XPKCFFf5UZqNQ".Decode64Loose(), TestData.Credentials);

            // Assert
            key.Id.ShouldBe("mp");
            key.Key.ShouldBe(expected);
        }

        [Theory]
        [InlineData("my.1password.com", "https://my.1password.com/api")]
        [InlineData("my.1password.eu", "https://my.1password.eu/api")]
        public void GetApiUrl_returns_correct_url(string domain, string expectedUrl)
        {
            // Act
            var url = Client.GetApiUrl(domain);

            // Assert
            url.ShouldBe(expectedUrl);
        }

        [Fact]
        public void MakeRestClient_sets_base_url()
        {
            // Arrange
            var rest = Client.MakeRestClient(null, "https://base.url");

            // Assert
            rest.BaseUrl.ShouldBe("https://base.url");
        }

        [Fact]
        public void MakeRestClient_copies_base_url()
        {
            // Arrange
            var rest = Client.MakeRestClient(new RestClient(null, "https://base.url"));

            // Assert
            rest.BaseUrl.ShouldBe("https://base.url");
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
