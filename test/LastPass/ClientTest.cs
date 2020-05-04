// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass;
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
                .Post("")
                    .ExpectUrl("/trust.php")
                .Get(TestData.BlobBase64)
                    .ExpectUrl("/getaccts.php?")
                .Post("")
                    .ExpectUrl("/logout.php");

            // TODO: Decryption fails here because of the incorrect password
            var accounts = Client.OpenVault(Username, Password, ClientInfo, new OtpProvidingUi(), flow);

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
                .Post("")
                    .ExpectUrl("/trust.php")
                .Get(TestData.BlobBase64)
                    .ExpectUrl("/getaccts.php?")
                .Post("")
                    .ExpectUrl("/logout.php");

            // TODO: Decryption fails here because of the incorrect password
            var accounts = Client.OpenVault(Username, Password, ClientInfo, new OtpProvidingUi(), flow);

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
        public void OpenVault_throws_on_failed_oob()
        {
            var flow = new RestFlow()
                .Post(KeyIterationCount.ToString())
                .Post(OobRequiredResponse)
                .Post("<response><error cause='multifactorresponsefailed' /></response>");

            Exceptions.AssertThrowsBadMultiFactor(
                () => Client.OpenVault(Username, Password, ClientInfo, new OtpProvidingUi(), flow),
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

            var session = Client.Login(Username, Password, ClientInfo, new OtpProvidingUi(), flow);

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
                                              Ui.SecondFactorMethod.GoogleAuth,
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
                                Ui.SecondFactorMethod.GoogleAuth,
                                ClientInfo,
                                new OtpProvidingUi(),
                                flow);
        }

        [Fact]
        public void LoginWithOob_returns_session()
        {
            var flow = new RestFlow().Post(OkResponse);
            var session = Client.LoginWithOob(Username,
                                              Password,
                                              KeyIterationCount,
                                              Ui.OutOfBandMethod.LastPassAuth,
                                              ClientInfo,
                                              new OtpProvidingUi(),
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
                                              Ui.OutOfBandMethod.LastPassAuth,
                                              ClientInfo,
                                              new OtpProvidingUi(),
                                              flow);

            AssertSessionWithPrivateKey(session);
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
        [InlineData("<response><error outofbandtype='lastpassauth' /></response>", Ui.OutOfBandMethod.LastPassAuth)]
        [InlineData("<response><error outofbandtype='toopher' /></response>", Ui.OutOfBandMethod.Toopher)]
        [InlineData("<response><error outofbandtype='duo' /></response>", Ui.OutOfBandMethod.Duo)]
        public void ExtractOobMethodFromLoginResponse_returns_oob_method(string response, Ui.OutOfBandMethod expected)
        {
            var xml = XDocument.Parse(response);
            var method = Client.ExtractOobMethodFromLoginResponse(xml);

            Assert.Equal(expected, method);
        }

        [Fact]
        public void ExtractOobMethodFromLoginResponse_throws_on_unknown_method()
        {
            var xml = XDocument.Parse("<response><error outofbandtype='blah' /></response>");

            Exceptions.AssertThrowsUnsupportedFeature(
                () => Client.ExtractOobMethodFromLoginResponse(xml),
                "Out-of-band method 'blah' is not supported");
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

        [Fact]
        public void ParseVault_throws_on_truncated_blob()
        {
            var tests = new[] {1, 2, 3, 4, 5, 10, 100, 1000};
            foreach (var i in tests)
            {
                var e = Assert.Throws<ParseException>(
                    () => Client.ParseVault(TestData.Blob.Take(TestData.Blob.Length - i).ToArray(),
                                            TestData.EncryptionKey,
                                            TestData.PrivateKey));
                Assert.Equal(ParseException.FailureReason.CorruptedBlob, e.Reason);
                Assert.Equal("Blob is truncated", e.Message);
            }
        }

        //
        // Helpers
        //

        private class OtpProvidingUi: Ui
        {
            public override string ProvideSecondFactorPassword(SecondFactorMethod method)
            {
                return Otp;
            }

            public override void AskToApproveOutOfBand(OutOfBandMethod method)
            {
            }
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
                                                                       "description",
                                                                       true);

        private static readonly Session Session = new Session("session-id",
                                                              KeyIterationCount,
                                                              "token",
                                                              Platform.Desktop,
                                                              "private-key");

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
