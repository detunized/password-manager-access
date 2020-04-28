// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class ClientTest
    {
        [Fact]
        public void Login_returns_session()
        {
            var flow = new RestFlow()
                .Post("1337")
                .Post(OkResponse);

            var session = Client.Login(Username, Password, ClientInfo, null, flow);

            Assert.Equal("session-id", session.Id);
            Assert.Equal(1337, session.KeyIterationCount);
            Assert.Equal("token", session.Token);
            Assert.Equal("private-key", session.EncryptedPrivateKey);
            Assert.Equal(Platform.Desktop, session.Platform);
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
        public void RequestIterationCount_makes_POST_request_to_specific_url_and_parameters()
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
        public void PerformSingleLoginRequest_makes_POST_request_to_specific_url_and_parameters()
        {
            var flow = new RestFlow()
                .Post("<ok />")
                    .ExpectUrl("https://lastpass.com/login.php")
                    .ExpectContent("method=cli")
                    .ExpectContent($"username={Username}")
                    .ExpectContent("iterations=1337")
                    .ExpectContent($"trustlabel={ClientInfo.Description}");

            Client.PerformSingleLoginRequest(Username,
                                             Password,
                                             1337,
                                             new Dictionary<string, object>(),
                                             ClientInfo,
                                             flow.ToRestClient(BaseUrl));
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

        // TODO: Figure out how to test this!
        //       All methods require username/password which I don't want to expose here.
        //       Actually, I'm pretty sure the password is lost and the whole test blob
        //       needs to be regenerated.
        //       Currently all the vault tests that deal with decryption are disabled.

        [Fact]
        public void ParseVault_returns_vault_with_correct_accounts()
        {
            var accounts = Client.ParseVault(new Blob(TestData.Blob, 1, TestData.EncryptedPrivateKey),
                                             TestData.EncryptionKey);

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
                    () => Client.ParseVault(new Blob(TestData.Blob.Take(TestData.Blob.Length - i).ToArray(), 1, ""),
                                            new byte[16]));
                Assert.Equal(ParseException.FailureReason.CorruptedBlob, e.Reason);
                Assert.Equal("Blob is truncated", e.Message);
            }
        }

        //
        // Data
        //

        private const string BaseUrl = "https://lastpass.com";
        private const string Username = "username";
        private const string Password = "password";

        private static readonly ClientInfo ClientInfo = new ClientInfo(Platform.Desktop, "id", "description", true);

        private const string OkResponse =
            "<response>" +
                "<ok sessionid='session-id' token='token' privatekeyenc='private-key' />" +
             "</response>";
    }
}
