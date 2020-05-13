// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Xml.Linq;
using Moq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass;
using PasswordManagerAccess.LastPass.Ui;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class ClientTest
    {
        // The general idea is to test as high level as possible even though it might get tedious.
        // This ensures that if/when the implementation changes we still get the same behavior.

        [Fact]
        public void OpenVault_returns_accounts()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                    .ExpectUrl("/iterations.php")
                .Post(OkResponseNoPrivateKey)
                    .ExpectUrl("/login.php")
                .Get(TestData.BlobBase64)
                    .ExpectUrl("/getaccts.php?")
                .Post("")
                    .ExpectUrl("/logout.php");

            // TODO: Decryption fails here because of the incorrect password
            var accounts = Client.OpenVault(Username, Password, ClientInfo, null, flow);

            Assert.NotEmpty(accounts);
        }

        [Fact]
        public void OpenVault_returns_accounts_with_otp()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                    .ExpectUrl("/iterations.php")
                .Post(OtpRequiredResponse)
                    .ExpectUrl("/login.php")
                .Post(OkResponseNoPrivateKey)
                    .ExpectUrl("/login.php")
                    .ExpectContent($"otp={Otp}")
                .Get(TestData.BlobBase64)
                    .ExpectUrl("/getaccts.php?")
                .Post("")
                    .ExpectUrl("/logout.php");

            // TODO: Decryption fails here because of the incorrect password
            var accounts = Client.OpenVault(Username, Password, ClientInfo, new OtpProvidingUi(), flow);

            Assert.NotEmpty(accounts);
        }

        [Fact]
        public void OpenVault_returns_accounts_with_otp_and_rememeber_me()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                    .ExpectUrl("/iterations.php")
                .Post(OtpRequiredResponse)
                    .ExpectUrl("/login.php")
                .Post(OkResponseNoPrivateKey)
                    .ExpectUrl("/login.php")
                    .ExpectContent($"otp={Otp}")
                .Post("")
                    .ExpectUrl("/trust.php")
                .Get(TestData.BlobBase64)
                    .ExpectUrl("/getaccts.php?")
                .Post("")
                    .ExpectUrl("/logout.php");

            // TODO: Decryption fails here because of the incorrect password
            var accounts = Client.OpenVault(Username, Password, ClientInfo, new OtpProvidingWithRememberMeUi(), flow);

            Assert.NotEmpty(accounts);
        }

        [Fact]
        public void OpenVault_returns_accounts_with_oob()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                    .ExpectUrl("/iterations.php")
                .Post(OobRequiredResponse)
                    .ExpectUrl("/login.php")
                .Post(OobRetryResponse)
                    .ExpectUrl("/login.php")
                    .ExpectContent("outofbandrequest=1")
                .Post(OkResponseNoPrivateKey)
                    .ExpectUrl("/login.php")
                    .ExpectContent("outofbandrequest=1")
                    .ExpectContent("outofbandretry=1")
                    .ExpectContent("outofbandretryid=retry-id")
                .Get(TestData.BlobBase64)
                    .ExpectUrl("/getaccts.php?")
                .Post("")
                    .ExpectUrl("/logout.php");

            // TODO: Decryption fails here because of the incorrect password
            var accounts = Client.OpenVault(Username, Password, ClientInfo, new WaitingForOobUi(), flow);

            Assert.NotEmpty(accounts);
        }

        [Fact]
        public void OpenVault_returns_accounts_with_oob_and_rememeber_me()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                    .ExpectUrl("/iterations.php")
                .Post(OobRequiredResponse)
                    .ExpectUrl("/login.php")
                .Post(OobRetryResponse)
                    .ExpectUrl("/login.php")
                    .ExpectContent("outofbandrequest=1")
                .Post(OkResponseNoPrivateKey)
                    .ExpectUrl("/login.php")
                    .ExpectContent("outofbandrequest=1")
                    .ExpectContent("outofbandretry=1")
                    .ExpectContent("outofbandretryid=retry-id")
                .Post("")
                    .ExpectUrl("/trust.php")
                .Get(TestData.BlobBase64)
                    .ExpectUrl("/getaccts.php?")
                .Post("")
                    .ExpectUrl("/logout.php");

            // TODO: Decryption fails here because of the incorrect password
            var accounts = Client.OpenVault(Username, Password, ClientInfo, new WaitingForOobWithRememberMeUi(), flow);

            Assert.NotEmpty(accounts);
        }

        [Fact]
        public void OpenVault_throws_on_invalid_username()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                .Post("<response><error cause='unknownemail' /></response>");

            Exceptions.AssertThrowsBadCredentials(
                () => Client.OpenVault(Username, Password, ClientInfo, null, flow),
                "Invalid username");
        }

        [Fact]
        public void OpenVault_throws_on_invalid_password()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                .Post("<response><error cause='unknownpassword' /></response>");

            Exceptions.AssertThrowsBadCredentials(
                () => Client.OpenVault(Username, Password, ClientInfo, null, flow),
                "Invalid password");
        }

        [Fact]
        public void OpenVault_throws_on_canceled_otp()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                .Post(OtpRequiredResponse);

            Exceptions.AssertThrowsCanceledMultiFactor(
                () => Client.OpenVault(Username, Password, ClientInfo, new CancelingUi(), flow),
                "Second factor step is canceled by the user");
        }

        [Fact]
        public void OpenVault_throws_on_failed_otp()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                .Post(OtpRequiredResponse)
                .Post("<response><error cause='googleauthfailed' /></response>");

            Exceptions.AssertThrowsBadMultiFactor(
                () => Client.OpenVault(Username, Password, ClientInfo, new OtpProvidingUi(), flow),
                "Second factor code is incorrect");
        }

        [Fact]
        public void OpenVault_throws_on_canceled_oob()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                .Post(OobRequiredResponse);

            Exceptions.AssertThrowsCanceledMultiFactor(
                () => Client.OpenVault(Username, Password, ClientInfo, new CancelingUi(), flow),
                "Out of band step is canceled by the user");
        }

        [Fact]
        public void OpenVault_throws_on_failed_oob()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                .Post(OobRequiredResponse)
                .Post("<response><error cause='multifactorresponsefailed' /></response>");

            Exceptions.AssertThrowsBadMultiFactor(
                () => Client.OpenVault(Username, Password, ClientInfo, new WaitingForOobUi(), flow),
                "Out of band authentication failed");
        }

        [Theory]
        [InlineData("<response><error cause='Blah' /></response>", "Blah")]
        [InlineData("<response><error cause='Pfff' message='Blah' /></response>", "Blah")]
        [InlineData("<response><error message='Blah' /></response>", "Blah")]
        [InlineData("<response><error /></response>", "Unknown error")]
        public void OpenVault_throws_on_other_errors(string response, string expected)
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                .Post(response);

            Exceptions.AssertThrowsInternalError(
                () => Client.OpenVault(Username, Password, ClientInfo, null, flow),
                expected);
        }

        [Fact]
        public void Login_returns_session()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                .Post(OkResponse);

            var session = Client.Login(Username, Password, ClientInfo, null, flow);

            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public void Login_returns_session_with_otp()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString()) // 1. iterations
                .Post(OtpRequiredResponse)          // 2. normal login attempt
                .Post(OkResponse)                   // 3. login with otp
                .Post("");                          // 4. save trusted device

            var session = Client.Login(Username, Password, ClientInfo, new OtpProvidingUi(), flow);

            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public void Login_returns_session_with_oob()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString()) // 1. iterations
                .Post(OobRequiredResponse)          // 2. normal login attempt
                .Post(OkResponse)                   // 3. check oob
                .Post("");                          // 4. save trusted device

            var session = Client.Login(Username, Password, ClientInfo, new WaitingForOobUi(), flow);

            AssertSessionWithPrivateKey(session);
        }

        [Theory]
        [InlineData("-1", -1)]
        [InlineData("0", 0)]
        [InlineData("1337", 1337)]
        [InlineData("100100", 100100)]
        public void RequestIterationCount_returns_iteration_count(string response, int expected)
        {
            var flow = new RestFlow().Post(response);
            var count = Client.RequestIterationCount(Username, flow);

            Assert.Equal(expected, count);
        }

        [Theory]
        [InlineData("")]
        [InlineData("abc")]
        [InlineData("12345678901234567890")]
        public void RequestIterationCount_throws_on_invalid_response(string response)
        {
            var flow = new RestFlow().Post(response);

            Exceptions.AssertThrowsInternalError(
                () => Client.RequestIterationCount(Username, flow),
                "Request iteration count failed: unexpected response");
        }

        [Fact]
        public void RequestIterationCount_makes_POST_request_to_specific_url_with_parameters()
        {
            var flow = new RestFlow()
                .Post("0")
                    .ExpectUrl("https://lastpass.com/iterations.php")
                    .ExpectContent($"email={Username}");

            Client.RequestIterationCount(Username, flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void PerformSingleLoginRequest_returns_parsed_xml()
        {
            var flow = new RestFlow().Post("<ok />");
            var xml = Client.PerformSingleLoginRequest(Username,
                                                       Password,
                                                       1,
                                                       new Dictionary<string, object>(),
                                                       ClientInfo,
                                                       flow);

            Assert.NotNull(xml);
        }

        [Fact]
        public void PerformSingleLoginRequest_makes_POST_request_to_specific_url_with_parameters()
        {
            var flow = new RestFlow()
                .Post("<ok />")
                    .ExpectUrl("https://lastpass.com/login.php")
                    .ExpectContent("method=cli")
                    .ExpectContent($"username={Username}")
                    .ExpectContent($"iterations={KeyIterationCount}")
                    .ExpectContent("hash=5e966139c28deab2c5955fcfa66ae6bebb55548a5f79d1d639abf7b0ce78d891")
                    .ExpectContent($"trustlabel={ClientInfo.Description}");

            Client.PerformSingleLoginRequest(Username,
                                             Password,
                                             KeyIterationCount,
                                             new Dictionary<string, object>(),
                                             ClientInfo,
                                             flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void LoginWithOtp_returns_session()
        {
            var flow = new RestFlow().Post(OkResponse);
            var session = Client.LoginWithOtp(Username,
                                              Password,
                                              KeyIterationCount,
                                              Client.OtpMethod.GoogleAuth,
                                              ClientInfo,
                                              new OtpProvidingUi(),
                                              flow);

            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public void LoginWithOtp_passes_otp_in_POST_parameters()
        {
            var flow = new RestFlow()
                .Post(OkResponse)
                    .ExpectContent($"otp={Otp}");

            Client.LoginWithOtp(Username,
                                Password,
                                KeyIterationCount,
                                Client.OtpMethod.GoogleAuth,
                                ClientInfo,
                                new OtpProvidingUi(),
                                flow);
        }

        [Fact]
        public void LoginWithOtp_with_remember_me_marks_device_as_trusted()
        {
            var flow = new RestFlow()
                .Post(OkResponse)
                    .ExpectUrl("/login.php")
                .Post("")
                    .ExpectUrl("/trust.php");

            Client.LoginWithOtp(Username,
                                Password,
                                KeyIterationCount,
                                Client.OtpMethod.GoogleAuth,
                                ClientInfo,
                                new OtpProvidingWithRememberMeUi(),
                                flow);
        }

        [Fact]
        public void LoginWithOob_returns_session()
        {
            var flow = new RestFlow().Post(OkResponse);
            var session = Client.LoginWithOob(Username,
                                              Password,
                                              KeyIterationCount,
                                              LastPassAuthOobParameters,
                                              ClientInfo,
                                              new WaitingForOobUi(),
                                              flow);

            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public void LoginWithOob_retries_after_unsuccessful_attempt()
        {
            var flow = new RestFlow()
                .Post(OobRetryResponse)
                .Post(OkResponse)
                    .ExpectContent("outofbandretry=1")
                    .ExpectContent("outofbandretryid=retry-id");

            var session = Client.LoginWithOob(Username,
                                              Password,
                                              KeyIterationCount,
                                              LastPassAuthOobParameters,
                                              ClientInfo,
                                              new WaitingForOobUi(),
                                              flow);

            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public void LoginWithOob_sends_otp_in_POST_parameters()
        {
            var flow = new RestFlow()
                .Post(OkResponse)
                    .ExpectContent($"otp={Otp}");

            var session = Client.LoginWithOob(Username,
                                              Password,
                                              KeyIterationCount,
                                              LastPassAuthOobParameters,
                                              ClientInfo,
                                              new PasscodeProvidingOobUi(),
                                              flow);

            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public void LoginWithOob_with_remember_me_marks_device_as_trusted()
        {
            var flow = new RestFlow()
                .Post(OkResponse)
                    .ExpectUrl("/login.php")
                .Post("")
                    .ExpectUrl("/trust.php");

            Client.LoginWithOob(Username,
                                Password,
                                KeyIterationCount,
                                LastPassAuthOobParameters,
                                ClientInfo,
                                new WaitingForOobWithRememberMeUi(),
                                flow);
        }

        [Fact]
        public void ApproveOob_calls_Ui_ApproveLastPassAuth()
        {
            var ui = new Mock<IUi>();
            ui.Setup(x => x.ApproveLastPassAuth()).Returns(OobResult.Cancel);

            Client.ApproveOob(LastPassAuthOobParameters, ui.Object, null);

            ui.VerifyAll();
        }

        [Fact]
        public void ApproveOob_calls_Ui_ApproveDuo()
        {
            var ui = new Mock<IUi>();
            ui.Setup(x => x.ApproveDuo()).Returns(OobResult.Cancel);

            Client.ApproveOob(DuoOobParameters, ui.Object, null);

            ui.VerifyAll();
        }

        [Fact]
        public void ApproveOob_calls_IDuoUi()
        {
            // TODO: See how to test this
        }

        [Fact]
        public void ApproveOob_throws_on_missing_method()
        {
            Exceptions.AssertThrowsInternalError(
                () => Client.ApproveOob(new Dictionary<string, string>(), null, null),
                "Out of band method is not specified");
        }

        [Fact]
        public void ApproveOob_throws_on_unknown_method()
        {
            Exceptions.AssertThrowsUnsupportedFeature(
                () => Client.ApproveOob(new Dictionary<string, string> {["outofbandtype"] = "blah"}, null, null),
                "Out of band method 'blah' is not supported");
        }

        [Theory]
        [InlineData("duo_host")]
        [InlineData("duo_signature")]
        public void ApproveOob_throws_on_missing_duo_host(string name)
        {
            var parameters = new Dictionary<string, string>
            {
                ["outofbandtype"] = "duo",
                ["preferduowebsdk"] = "1",
                ["duo_host"] = "duo-host",
                ["duo_signature"] = "duo-signature",
            };
            parameters.Remove(name);

            Exceptions.AssertThrowsInternalError(() => Client.ApproveOob(parameters, null, null),
                                                 $"Invalid response: '{name}' parameter not found");
        }

        [Fact]
        public void MarkDeviceAsTrusted_makes_POST_request_to_specific_url_with_parameters_and_cookies()
        {
            var flow = new RestFlow()
                .Post("")
                    .ExpectUrl("https://lastpass.com/trust.php")
                    .ExpectContent($"uuid={ClientInfo.Id}")
                    .ExpectContent($"trustlabel={ClientInfo.Description}")
                    .ExpectContent($"token={Session.Token}")
                    .ExpectCookie("PHPSESSID", Session.Id);

            Client.MarkDeviceAsTrusted(Session, ClientInfo, flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void Logout_makes_POST_request_to_specific_url_with_parameters_and_cookies()
        {
            var flow = new RestFlow()
                .Post("")
                    .ExpectUrl("https://lastpass.com/logout.php")
                    .ExpectContent("method=cli")
                    .ExpectContent("noredirect=1")
                    .ExpectCookie("PHPSESSID", Session.Id);

            Client.Logout(Session, flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void DownloadVault_returns_blob()
        {
            var expected = "blah-blah".ToBytes();
            var flow = new RestFlow().Get(expected.ToBase64());
            var blob = Client.DownloadVault(Session, flow);

            Assert.Equal(expected, blob);
        }

        [Fact]
        public void DownloadVault_makes_GET_request_to_specific_url_with_cookies()
        {
            var flow = new RestFlow()
                .Get("blah-blah".ToBase64())
                    .ExpectUrl("https://lastpass.com/getaccts.php?")
                    .ExpectUrl("requestsrc=cli")
                    .ExpectCookie("PHPSESSID", Session.Id);

            Client.DownloadVault(Session, flow.ToRestClient(BaseUrl));
        }

        [Theory]
        [InlineData(Platform.Desktop, "cli")]
        [InlineData(Platform.Mobile, "android")]
        public void GetVaultEndpoint_includes_platform_in_endpoint(Platform platform, string expected)
        {
            var endpoint = Client.GetVaultEndpoint(platform);

            Assert.Contains($"requestsrc={expected}", endpoint);
        }

        [Fact]
        public void GetSessionCookies_escapes_session_id()
        {
            var session = new Session(" /:;?=", -1, "", Platform.Desktop, "");
            var cookies = Client.GetSessionCookies(session);

            Assert.Equal("%20%2F%3A%3B%3F%3D", cookies["PHPSESSID"]);
        }

        [Fact]
         public void ParseXml_returns_parsed_xml()
        {
            var response = new RestResponse<string> {Content = "<ok />"};

            Assert.NotNull(Client.ParseXml(response));
        }

        [Fact]
        public void ParseXml_throws_on_invalid_xml()
        {
            var response = new RestResponse<string>
            {
                Content = "> invalid xml <",
                RequestUri = new Uri("https://int.er.net")
            };

            Exceptions.AssertThrowsInternalError(
                () => Client.ParseXml(response),
                "Failed to parse XML in response from https://int.er.net");
        }

        [Fact]
        public void ExtractSessionFromLoginResponse_returns_session()
        {
            var xml = XDocument.Parse(OkResponse);
            var session = Client.ExtractSessionFromLoginResponse(xml, KeyIterationCount, ClientInfo);

            AssertSessionWithPrivateKey(session);
        }

        [Theory]
        [InlineData(OkResponseNoPrivateKey)]
        [InlineData(OkResponseBlankPrivateKey)]
        public void ExtractSessionFromLoginResponse_returns_session_without_private_key(string response)
        {
            var xml = XDocument.Parse(response);
            var session = Client.ExtractSessionFromLoginResponse(xml, KeyIterationCount, ClientInfo);

            AssertSessionWithoutPrivateKey(session);
        }

        [Theory]
        [InlineData("<response><error blah='' /></response>", "")]
        [InlineData("<response><error blah='blah-blah' /></response>", "blah-blah")]
        public void GetErrorAttribute_returns_attribute_value(string response, string expected)
        {
            var xml = XDocument.Parse(response);
            var value = Client.GetErrorAttribute(xml, "blah");

            Assert.Equal(expected, value);
        }

        [Fact]
        public void GetErrorAttribute_throws_when_attribute_is_not_present()
        {
            var xml = XDocument.Parse("<response><error blah='blah-blah' /></response>");

            Exceptions.AssertThrowsInternalError(
                () => Client.GetErrorAttribute(xml, "poof"),
                "Unknown response schema: attribute 'poof' is missing");
        }

        [Fact]
        public void GetOptionalErrorAttribute_returns_null_when_attribute_is_not_present()
        {
            var xml = XDocument.Parse("<response><error blah='blah-blah' /></response>");
            var value = Client.GetOptionalErrorAttribute(xml, "poof");

            Assert.Null(value);
        }

        [Fact]
        public void GetAllErrorAttributes_returns_all_names_and_values()
        {
            var expected = new Dictionary<string, string> {["a"] = "b", ["c"] = "d", ["e"] = "f"};
            var xml = XDocument.Parse("<response><error a='b' c='d' e='f' /></response>");
            var all = Client.GetAllErrorAttributes(xml);

            Assert.Equal(expected, all);
        }

        // TODO: Figure out how to test this!
        //       All methods require username/password which I don't want to expose here.
        //       Actually, I'm pretty sure the password is lost and the whole test blob
        //       needs to be regenerated.
        //       Currently all the vault tests that deal with decryption are disabled.

        [Fact]
        public void ParseVault_returns_vault_with_correct_accounts()
        {
            var accounts = Client.ParseVault(TestData.Blob, TestData.EncryptionKey, TestData.PrivateKey);

            Assert.Equal(TestData.Accounts.Length, accounts.Length);
            for (var i = 0; i < accounts.Length; i++)
            {
                Assert.Equal(TestData.Accounts[i].Id, accounts[i].Id);
                Assert.Equal(TestData.Accounts[i].Name, accounts[i].Name);
                Assert.Equal(TestData.Accounts[i].Username, accounts[i].Username);
                Assert.Equal(TestData.Accounts[i].Password, accounts[i].Password);
                Assert.Equal(TestData.Accounts[i].Url, accounts[i].Url);
                Assert.Equal(TestData.Accounts[i].Group, accounts[i].Path);
            }
        }

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(5)]
        [InlineData(10)]
        [InlineData(100)]
        [InlineData(1000)]
        public void ParseVault_throws_on_truncated_blob(int cut)
        {
            Exceptions.AssertThrowsInternalError(
                () => Client.ParseVault(TestData.Blob.Sub(0, TestData.Blob.Length - cut),
                                        TestData.EncryptionKey,
                                        TestData.PrivateKey),
                "Blob is truncated or corrupted");
        }

        //
        // Helpers
        //

        // OTP and OOB
        private class CancelingUi: FakeUi
        {
            public CancelingUi(): base(OtpResult.Cancel, OobResult.Cancel)
            {
            }
        }

        // OTP only
        private class OtpProvidingUi: FakeUi
        {
            public OtpProvidingUi(): base(new OtpResult(Otp, false), null)
            {
            }
        }

        // OTP only
        private class OtpProvidingWithRememberMeUi: FakeUi
        {
            public OtpProvidingWithRememberMeUi(): base(new OtpResult(Otp, true), null)
            {
            }
        }

        // OOB only
        private class WaitingForOobUi: FakeUi
        {
            public WaitingForOobUi(): base(null, OobResult.WaitForApproval(false))
            {
            }
        }

        // OOB only
        private class WaitingForOobWithRememberMeUi: FakeUi
        {
            public WaitingForOobWithRememberMeUi(): base(null, OobResult.WaitForApproval(true))
            {
            }
        }

        private class PasscodeProvidingOobUi: FakeUi
        {
            public PasscodeProvidingOobUi(): base(null, OobResult.ContinueWithPasscode(Otp, false))
            {
            }
        }

        private class FakeUi: IUi
        {
            protected FakeUi(OtpResult otp, OobResult oob)
            {
                _otp = otp;
                _oob = oob;
            }

            public OtpResult ProvideGoogleAuthPasscode() => _otp;
            public OtpResult ProvideMicrosoftAuthPasscode() => _otp;
            public OtpResult ProvideYubikeyPasscode() => _otp;
            public OobResult ApproveLastPassAuth() => _oob;
            public OobResult ApproveDuo() => _oob;

            public DuoChoice ChooseDuoFactor(DuoDevice[] devices)
            {
                return new DuoChoice(new DuoDevice("id", "name", new[] {DuoFactor.Push}),
                                     DuoFactor.Push,
                                     false);
            }

            public string ProvideDuoPasscode(DuoDevice device)
            {
                return "passcode";
            }

            public void UpdateDuoStatus(DuoStatus status, string text)
            {
            }

            private readonly OtpResult _otp;
            private readonly OobResult _oob;
        }

        private static void AssertSessionWithPrivateKey(Session session)
        {
            AssertSessionCommon(session);
            Assert.Equal("private-key", session.EncryptedPrivateKey);
        }

        private static void AssertSessionWithoutPrivateKey(Session session)
        {
            AssertSessionCommon(session);
            Assert.Null(session.EncryptedPrivateKey);
        }

        private static void AssertSessionCommon(Session session)
        {
            Assert.Equal("session-id", session.Id);
            Assert.Equal(KeyIterationCount, session.KeyIterationCount);
            Assert.Equal("token", session.Token);
            Assert.Equal(Platform.Desktop, session.Platform);
        }

        //
        // Data
        //

        private const string BaseUrl = "https://lastpass.com";
        private const string Username = "username";
        private const string Password = "password";
        private const string Otp = "123456";
        private const int KeyIterationCount = 1337;

        private static readonly ClientInfo ClientInfo = new ClientInfo(Platform.Desktop,
                                                                       "client-id",
                                                                       "description");

        private static readonly Session Session = new Session("session-id",
                                                              KeyIterationCount,
                                                              "token",
                                                              Platform.Desktop,
                                                              "private-key");

        private static readonly Dictionary<string, string> LastPassAuthOobParameters = new Dictionary<string, string>
        {
            ["outofbandtype"] = "lastpassauth"
        };

        private static readonly Dictionary<string, string> DuoOobParameters = new Dictionary<string, string>
        {
            ["outofbandtype"] = "duo"
        };

        private const string OkResponse =
            "<response>" +
                "<ok sessionid='session-id' token='token' privatekeyenc='private-key' />" +
             "</response>";

        private const string OkResponseNoPrivateKey =
            "<response>" +
                "<ok sessionid='session-id' token='token' />" +
             "</response>";

        private const string OkResponseBlankPrivateKey =
            "<response>" +
                "<ok sessionid='session-id' token='token' privatekeyenc='' />" +
             "</response>";

        private const string OtpRequiredResponse =
            "<response>" +
                "<error cause='googleauthrequired' />" +
            "</response>";

        private const string OobRequiredResponse =
            "<response>" +
                "<error cause='outofbandrequired' outofbandtype='lastpassauth' />" +
            "</response>";

        private const string OobRetryResponse =
            "<response>" +
                "<error cause='outofbandrequired' retryid='retry-id' />" +
            "</response>";
    }
}
