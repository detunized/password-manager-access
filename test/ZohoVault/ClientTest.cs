// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using Moq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.ZohoVault;
using Xunit;

namespace PasswordManagerAccess.Test.ZohoVault
{
    // TODO: Fix and enable
#if TESTS_ARE_WORKING
    public class RemoteTest: TestBase
    {
        public const string Username = "lebowski";
        public const string Password = "logjammin";
        public const string Token = "1auth2token3";
        public const string LoginUrlPrefix = "https://accounts.zoho.com/login?";
        public const string LogoutUrlPrefix = "https://accounts.zoho.com/apiauthtoken/delete?";
        public const string LogoutResponse = "RESULT=TRUE";

        // Copied from VaultTest (RIP)
        [Fact]
        public void Open_with_json_returns_vault()
        {
            var parsed = JObject.Parse(GetFixture("vault-response"))["operation"]["details"].ToObject<R.Vault>();
            var vault = Vault.Open(parsed, TestData.Key);
            var accounts = vault.Accounts;

            Assert.Equal(2, accounts.Length);

            Assert.Equal("30024000000008008", accounts[0].Id);
            Assert.Equal("facebook", accounts[0].Name);
            Assert.Equal("mark", accounts[0].Username);
            Assert.Equal("zuckerberg", accounts[0].Password);
            Assert.Equal("http://facebook.com", accounts[0].Url);
            Assert.Equal("", accounts[0].Note);

            Assert.Equal("30024000000008013", accounts[1].Id);
            Assert.Equal("microsoft", accounts[1].Name);
            Assert.Equal("bill", accounts[1].Username);
            Assert.Equal("gates", accounts[1].Password);
            Assert.Equal("http://microsoft.com", accounts[1].Url);
            Assert.Equal("", accounts[1].Note);
        }

        [Fact]
        public void Login_returns_token()
        {
            Assert.Equal(Token, Remote.Login(Username, Password, SetupWebClientWithSuccess().Object));
        }

        [Fact]
        public void Login_makes_post_request_to_specific_url()
        {
            var webClient = SetupWebClientWithSuccess();
            Remote.Login(Username, Password, webClient.Object);

            webClient.Verify(
                x => x.Post(It.Is<string>(s => s.StartsWith(LoginUrlPrefix)),
                            It.IsAny<Dictionary<string, object>>(),
                            It.IsAny<Dictionary<string, string>>(),
                            It.IsAny<Dictionary<string, string>>()),
                Times.Once);
        }

        [Fact]
        public void Login_makes_post_request_with_correct_username_and_password()
        {
            var webClient = SetupWebClientWithSuccess();
            Remote.Login(Username, Password, webClient.Object);

            webClient.Verify(
                x => x.Post(
                    It.IsAny<string>(),
                    It.Is<Dictionary<string, object>>(p => p["LOGIN_ID"] as string == Username &&
                                                           p["PASSWORD"] as string == Password),
                    It.IsAny<Dictionary<string, string>>(),
                    It.IsAny<Dictionary<string, string>>()),
                Times.Once);
        }

        [Fact]
        public void Login_makes_post_request_with_cookie_set()
        {
            var webClient = SetupWebClientWithSuccess();
            Remote.Login(Username, Password, webClient.Object);

            webClient.Verify(
                x => x.Post(
                    It.IsAny<string>(),
                    It.IsAny<Dictionary<string, object>>(),
                    It.IsAny<Dictionary<string, string>>(),
                    It.Is<Dictionary<string, string>>(c => c["iamcsr"].StartsWith("12345678"))),
                Times.Once);
        }

        [Fact]
        public void Login_throws_on_network_error()
        {
            var webClient = SetupWebClient(new WebException());
            Exceptions.AssertThrowsNetworkError(() => Remote.Login(Username, Password, webClient.Object),
                                                "Network error occurred");
        }

        [Fact]
        public void Login_throws_on_error()
        {
            var webClient = SetupWebClient("showerror('It failed')");
            Exceptions.AssertThrowsBadCredentials(() => Remote.Login(Username, Password, webClient.Object),
                                                  "Login failed, most likely the credentials are invalid");
        }

        [Fact]
        public void Logout_makes_get_request_to_specific_url()
        {
            var webClient = SetupWebClientForGet(LogoutResponse);
            Remote.Logout(Token, webClient.Object);

            webClient.Verify(
                x => x.Get(
                    It.Is<string>(s => s.StartsWith(LogoutUrlPrefix)),
                    It.IsAny<Dictionary<string, string>>(),
                    It.IsAny<Dictionary<string, string>>()),
                Times.Once);
        }

        [Fact]
        public void Logout_makes_get_request_with_token()
        {
            var webClient = SetupWebClientForGet(LogoutResponse);
            Remote.Logout(Token, webClient.Object);

            var authToken = string.Format("AUTHTOKEN={0}", Token);
            webClient.Verify(
                x => x.Get(
                    It.Is<string>(s => s.EndsWith(authToken)),
                    It.IsAny<Dictionary<string, string>>(),
                    It.IsAny<Dictionary<string, string>>()),
                Times.Once);
        }

        [Fact]
        public void Authenticate_returns_key()
        {
            var webClient = SetupWebClientForGetWithFixture("auth-info-response");
            Assert.Equal(TestData.Key, Remote.Authenticate(Token, TestData.Passphrase, webClient.Object));
        }

        [Fact]
        public void Authenticate_throws_on_incorrect_passphrase()
        {
            var webClient = SetupWebClientForGetWithFixture("auth-info-response");
            Exceptions.AssertThrowsBadCredentials(
                () => Remote.Authenticate(Token, "Not really a passphrase", webClient.Object),
                "Passphrase is incorrect");
        }

        [Fact]
        public void DownloadVault_returns_vault_json()
        {
            var webClient = SetupWebClientForGetWithFixture("vault-response");
            Assert.NotNull(Remote.DownloadVault(Token, TestData.Key, webClient.Object));
        }

        [Fact]
        public void DownloadVault_throws_on_network_error()
        {
            var webClient = SetupWebClientForGet(new WebException());
            Exceptions.AssertThrowsNetworkError(() => Remote.DownloadVault(Token, TestData.Key, webClient.Object),
                                                "Network error occurred");
        }

        // TODO: Add more GetAuthInfo tests

        [Fact]
        public void GetAuthInfo_returns_auth_info()
        {
            var webClient = SetupWebClientForGetWithFixture("auth-info-response");
            var info = Remote.GetAuthInfo(Token, webClient.Object);

            Assert.Equal(1000, info.IterationCount);
            Assert.Equal("f78e6ffce8e57501a02c9be303db2c68".ToBytes(), info.Salt);
            Assert.Equal("awNZM8agxVecKpRoC821Oq6NlvVwm6KpPGW+cLdzRoc2Mg5vqPQzoONwww==".Decode64(), info.EncryptionCheck);
        }

        [Fact]
        public void ParseSwitchTo_decodes_url()
        {
            var encoded = "switchto('https\\x3A\\x2F\\x2Faccounts.zoho.com\\x2Ftfa\\x2Fauth" +
                          "\\x3Fserviceurl\\x3Dhttps\\x253A\\x252F\\x252Fvault.zoho.com');";
            var url = Remote.ParseSwitchTo(encoded);

            Assert.Equal("https://accounts.zoho.com/tfa/auth?serviceurl=https%3A%2F%2Fvault.zoho.com", url);
        }

        //
        // Helpers
        //

        private static MockRestResponse Response(string content)
        {
            // TODO: See if we need more, maybe fill all of them for completeness
            return new MockRestResponse()
            {
                Content = content,
                RawBytes = content.ToBytes(),
                StatusCode = HttpStatusCode.OK,
                ResponseStatus = ResponseStatus.Completed,
                Cookies = new List<RestResponseCookie>
                {
                    new RestResponseCookie() { Name = "IAMAUTHTOKEN", Value = Token }
                },
            };
        }

        private static MockRestResponse Response(Exception e)
        {
            // TODO: See if we need more, maybe fill all of them for completeness
            return new MockRestResponse()
            {
                Content = "",
                RawBytes = "".ToBytes(),
                StatusCode = HttpStatusCode.InternalServerError,
                ResponseStatus = ResponseStatus.Error,
                ErrorException = e,
            };
        }

        private static Mock<IWebClient> SetupWebClientWithSuccess()
        {
            return SetupWebClient("showsuccess('')");
        }

        private static Mock<IWebClient> SetupWebClient(string response)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<Dictionary<string, object>>(),
                                   It.IsAny<Dictionary<string, string>>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Returns(Response(response));

            return webClient;
        }

        private static Mock<IWebClient> SetupWebClient(Exception e)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.Post(It.IsAny<string>(),
                                   It.IsAny<Dictionary<string, object>>(),
                                   It.IsAny<Dictionary<string, string>>(),
                                   It.IsAny<Dictionary<string, string>>()))
                .Returns(Response(e));

            return webClient;
        }

        private static Mock<IWebClient> SetupWebClientForGet(string response)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.Get(It.IsAny<string>(),
                                  It.IsAny<Dictionary<string, string>>(),
                                  It.IsAny<Dictionary<string, string>>()))
                .Returns(Response(response));

            return webClient;
        }

        private static Mock<IWebClient> SetupWebClientForGet(Exception e)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.Get(It.IsAny<string>(),
                                  It.IsAny<Dictionary<string, string>>(),
                                  It.IsAny<Dictionary<string, string>>()))
                .Returns(Response(e));

            return webClient;
        }

        private Mock<IWebClient> SetupWebClientForGetWithFixture(string filename)
        {
            return SetupWebClientForGet(GetFixture(filename));
        }
    }

    internal class MockRestResponse: IRestResponse
    {
        public IRestRequest Request { get; set; }
        public string ContentType { get; set; }
        public long ContentLength { get; set; }
        public string ContentEncoding { get; set; }
        public string Content { get; set; }
        public HttpStatusCode StatusCode { get; set; }
        public string StatusDescription { get; set; }
        public byte[] RawBytes { get; set; }
        public Uri ResponseUri { get; set; }
        public string Server { get; set; }
        public IList<RestResponseCookie> Cookies { get; set; }
        public IList<Parameter> Headers { get; set; }
        public ResponseStatus ResponseStatus { get; set; }
        public string ErrorMessage { get; set; }
        public Exception ErrorException { get; set; }
        public Version ProtocolVersion { get; set; }

        // Mimic RestSharp.RestResponse
        public bool IsSuccessful => StatusCode == HttpStatusCode.OK &&
                                    ResponseStatus == ResponseStatus.Completed;
    }
#endif
}
