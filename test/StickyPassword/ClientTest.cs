// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Threading;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.StickyPassword;
using PasswordManagerAccess.StickyPassword.Ui;
using Xunit;

namespace PasswordManagerAccess.Test.StickyPassword
{
    using static ClientTestData;

    public class ClientTest
    {
        [Fact]
        public void OpenVaultDb_throws_CanceledMultiFactorException_when_user_cancels()
        {
            var flow = new RestFlow().Post(ResponseWithError4002);

            Exceptions.AssertThrowsCanceledMultiFactor(
                () => Client.OpenVaultDb(Username, Password, DeviceId, DeviceName, GetCancelingUi(), flow),
                "Second factor step is canceled by the user");
        }

        [Fact]
        public void OpenVaultDb_throws_BadMultiFactorException_on_incorrect_passcode()
        {
            var flow = new RestFlow()
                .Post(ResponseWithError4002)
                .Post(ResponseWithError4003);

            Exceptions.AssertThrowsBadMultiFactor(
                () => Client.OpenVaultDb(Username, Password, DeviceId, DeviceName, GetPasscodeProvidingUi(), flow),
                "Second factor code is not correct");
        }

        [Fact]
        public void GetEncryptedTokenAndPasscode_returns_token_and_passcode()
        {
            var flow = new RestFlow()
                .Post(ResponseWithError4002)
                .Post(GetTokenResponse)
                    .ExpectContent($"pin={EmailPasscode}");

            var (token, passcode) = Client.GetEncryptedTokenAndPasscode(Username,
                                                                        DeviceId,
                                                                        GetPasscodeProvidingUi(),
                                                                        flow);

            Assert.Equal(EncryptedToken, token);
            Assert.Equal(EmailPasscode, passcode);
        }

        [Fact]
        public void GetEncryptedTokenAndPasscode_triggers_email_resend()
        {
            var flow = new RestFlow()
                .Post(ResponseWithError4002)
                .Post(ResponseWithError4002)
                .Post(GetTokenResponse)
                    .ExpectContent($"pin={EmailPasscode}");

            var ui = GetUi(Passcode.Resend, new Passcode(EmailPasscode));
            var (token, passcode) = Client.GetEncryptedTokenAndPasscode(Username, DeviceId, ui, flow);

            Assert.Equal(EncryptedToken, token);
            Assert.Equal(EmailPasscode, passcode);
        }

        [Fact]
        public void GetEncryptedToken_returns_response()
        {
            var flow = new RestFlow().Post(GetTokenResponse);
            var token = Client.GetEncryptedToken(Username, DeviceId, NoPasscode, Timestamp, flow);

            Assert.Equal(EncryptedToken, token);
        }

        [Fact]
        public void GetEncryptedToken_makes_POST_request_with_specific_url_and_parameters()
        {
            var flow = new RestFlow()
                .Post(GetTokenResponse)
                    .ExpectUrl("https://spcb.stickypassword.com/SPCClient/GetCrpToken")
                    .ExpectContent($"uaid={UrlEncodedUsername}");

            Client.GetEncryptedToken(Username, DeviceId, NoPasscode, Timestamp, flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void GetEncryptedToken_throws_on_non_zero_status()
        {
            var flow = new RestFlow().Post(ResponseWithError);

            Exceptions.AssertThrowsInternalError(
                () => Client.GetEncryptedToken(Username, DeviceId, NoPasscode, Timestamp, flow),
                "Failed to retrieve the encrypted token");
        }

        [Fact]
        public void GetEncryptedToken_throws_BadCredentialsException_on_1006_status()
        {
            var flow = new RestFlow().Post(ResponseWithError1006);

            Exceptions.AssertThrowsBadCredentials(
                () => Client.GetEncryptedToken(Username, DeviceId, NoPasscode, Timestamp, flow),
                "Invalid username");
        }

        [Fact]
        public void GetEncryptedToken_returns_EmailPasscodeRequired_on_4002_status()
        {
            var flow = new RestFlow().Post(ResponseWithError4002);
            var token = Client.GetEncryptedToken(Username, DeviceId, NoPasscode, Timestamp, flow);

            Assert.Equal(Client.EmailPasscodeRequired, token);
        }

        [Fact]
        public void GetEncryptedToken_throws_BadMultiFactorException_on_4003_status()
        {
            var flow = new RestFlow().Post(ResponseWithError4003);

            Exceptions.AssertThrowsBadMultiFactor(
                () => Client.GetEncryptedToken(Username, DeviceId, EmailPasscode, Timestamp, flow),
                "Second factor code is not correct");
        }

        [Fact]
        public void GetEncryptedToken_sends_passcode()
        {
            var flow = new RestFlow()
                .Post(GetTokenResponse)
                .ExpectContent($"pin={EmailPasscode}");

            Client.GetEncryptedToken(Username, DeviceId, EmailPasscode, Timestamp, flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void AuthorizeDevice_makes_POST_request_with_specific_url_and_parameters()
        {
            var flow = new RestFlow()
                .Post(AuthorizeDeviceResponse)
                    .ExpectUrl("https://spcb.stickypassword.com/SPCClient/DevAuth")
                    .ExpectContent($"hid={DeviceName}")
                    .ExpectContent($"pin={EmailPasscode}");

            Client.AuthorizeDevice(Username,
                                   Token,
                                   DeviceId,
                                   DeviceName,
                                   EmailPasscode,
                                   Timestamp,
                                   flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void AuthorizeDevice_throws_on_non_zero_status()
        {
            var flow = new RestFlow().Post(ResponseWithError);

            Exceptions.AssertThrowsInternalError(
                () => Client.AuthorizeDevice(Username, Token, DeviceId, DeviceName, NoPasscode, Timestamp, flow),
                "Failed to authorize the device");
        }

        [Fact]
        public void GetS3Token_makes_POST_request_to_specific_url()
        {
            var flow = new RestFlow()
                .Post(GetS3TokenResponse)
                .ExpectUrl("https://spcb.stickypassword.com/SPCClient/GetS3Token");

            Client.GetS3Token(Username, Token, DeviceId, Timestamp, flow.ToRestClient(BaseUrl));
        }

        [Fact]
        public void GetS3Token_returns_s3_token()
        {
            var flow = new RestFlow().Post(GetS3TokenResponse);
            var s3 = Client.GetS3Token(Username, Token, DeviceId, Timestamp, flow);

            Assert.Equal("ASIAIFIAL3EJEOPJXVCQ", s3.Credentials.AccessKeyId);
            Assert.Equal("TRuR/+smCDzIqEcFTe+WCbgoNXK5OD0k4CdWhD6d", s3.Credentials.SecretAccessKey);
            Assert.Equal("FQoDYXdzEHYaDMzzWZ6Bc0LZKKiX5iLYAjsN+/1ou0rwiiiGumEdPZ1dE/o0xP1MvUNlgdcN7HKvoXIiQ4yAnawKDU1" +
                         "/7A/cgJ/QNdnj2yJRq0wz9LZkvKeuh+LMu74/GkvR7NZLM7fCg81lySsGq20wol2Z580l8N6QN/B52fsJq2nwYpalRp" +
                         "1/F0KbgRctffGMqelSvXjeqIH6OIdk53oilM72myMPtVZjjv+0CAyTxpg/ObGSdDazUMmNcBHdU5eJr02FXnOL3b/dh" +
                         "vf1YwMexRiMUNkb+0SpCCF4tApvNgR676nIoRSHtVfe7V1IvaKH6jBuDAUHAAJRyOro5+LwCHTOCaADp0jyuWXNJBD4" +
                         "cRaheWeMvLJBQKspgZp17sEO6MQuuTlBApYGngvrg+kISlU2uUKbOYmqpTTueRQR1h2Qp33/K9JWSf3fsvrhDz2Keri" +
                         "8fe9a5qbpkZ5wavsxko3/jZjvKaO76JAjg8xdKPik08MF",
                         s3.Credentials.SecurityToken);
            Assert.Equal("spclouddata", s3.BucketName);
            Assert.Equal("31645cc8-6ae9-4a22-aaea-557efe9e43af/", s3.ObjectPrefix);
        }

        [Fact]
        public void GetS3Token_throws_on_non_zero_status()
        {
            var flow = new RestFlow().Post(ResponseWithError);

            Exceptions.AssertThrowsInternalError(() => Client.GetS3Token(Username, Token, DeviceId, Timestamp, flow),
                                                 "Failed to retrieve the S3 token");
        }

        [Fact]
        public void FindLatestDbVersion_returns_version_from_s3()
        {
            var flow = new RestFlow().Get(VersionInfo.ToBytes());
            var version = Client.FindLatestDbVersion(S3Token, flow);

            Assert.Equal(Version, version);
        }

        [Fact]
        public void FindLatestDbVersion_requests_file_from_s3()
        {
            var flow = new RestFlow()
                .Get(VersionInfo.ToBytes())
                    .ExpectUrl(Bucket)
                    .ExpectUrl(ObjectPrefix)
                    .ExpectUrl("spc.info");

            Client.FindLatestDbVersion(S3Token, flow);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("\t\n")]
        [InlineData("VERSION\nMILESTONE\n")]
        public void FindLatestDbVersion_throws_on_invalid_format(string response)
        {
            var flow = new RestFlow().Get(response.ToBytes());

            Exceptions.AssertThrowsInternalError(
                () => Client.FindLatestDbVersion(S3Token, flow),
                "Invalid database info format");
        }

        [Fact]
        public void DownloadDb_returns_content_from_s3()
        {
            var flow = new RestFlow().Get(CompressedDbContent);
            var db = Client.DownloadDb(Version, S3Token, flow);

            Assert.Equal(DbContent, db);
        }

        [Fact]
        public void DownloadDb_requests_file_from_s3()
        {
            var flow = new RestFlow()
                .Get("".ToBytes())
                    .ExpectUrl(Bucket)
                    .ExpectUrl(ObjectPrefix)
                    .ExpectUrl(Version);

            Client.DownloadDb(Version, S3Token, flow);
        }

        [Fact]
        public void DownloadDb_throws_on_invalid_deflated_content()
        {
            var flow = new RestFlow().Get("Not really deflated".ToBytes());

            Exceptions.AssertThrowsInternalError(() => Client.DownloadDb(Version, S3Token, flow),
                                                 "Failed to decompress the database");
        }

        //
        // Post
        //
        // All the network calls go through Client.Post, so it makes sense to test only it for
        // all the common behaviors.
        //

        [Fact]
        public void Post_converts_date_to_utc_and_formats_correctly()
        {
            var timestamp = DateTime.Parse("Tue, 17 Mar 2020 12:34:56 +01:00"); // Local time here
            var flow = new RestFlow()
                .Post(SuccessfulResponse)
                    .ExpectHeader("Date", "Tue, 17 Mar 2020 11:34:56 GMT"); // UTC/GMT time here

            Client.Post(flow, "endpoint", DeviceId, timestamp, RestClient.NoParameters);
        }

        [Fact]
        public void Post_sets_common_headers()
        {
            var flow = new RestFlow()
                .Post(SuccessfulResponse)
                .ExpectHeader("Accept", "application/xml")
                .ExpectHeader("Authorization",
                              "Basic TGFzdFBhc3MuUnVieUBnbWFpTC5jT206WlRRMU1HVmpNMlJsWlRRMk5HTTNaV0V4TlRoallqY3dOMlk0Tm1NMU1tUT0=")
                .ExpectHeader("Date", "Fri, 06 Mar 1998 17:24:56 GMT")
                .ExpectHeader("User-Agent",
                              $"SP/8.0.3436 Prot=2 ID={DeviceId} Lng=EN Os=Android/4.4.4 Lic= LicStat= PackageID=");

            Client.Post(flow, "endpoint", DeviceId, Timestamp, RestClient.NoParameters, Username, Token);
        }

        [Theory]
        [InlineData("")]
        [InlineData(">invalid<")]
        [InlineData("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")]
        public void Post_throws_on_invalid_xml(string response)
        {
            var flow = new RestFlow().Post(response);

            Exceptions.AssertThrowsInternalError(
                () => Client.Post(flow, "endpoint", DeviceId, Timestamp, RestClient.NoParameters),
                "Failed to parse XML in response");
        }

        [Fact]
        public void Post_throws_on_network_error()
        {
            var flow = new RestFlow().Post(new HttpRequestException());

            Exceptions.AssertThrowsNetworkError(
                () => Client.Post(flow, "endpoint", DeviceId, Timestamp, RestClient.NoParameters),
                "Network error has occurred");
        }

        [Fact]
        public void Post_throws_bad_password_on_unauthorized()
        {
            var flow = new RestFlow().Post("", HttpStatusCode.Unauthorized);

            Exceptions.AssertThrowsBadCredentials(
                () => Client.Post(flow, "endpoint", DeviceId, Timestamp, RestClient.NoParameters),
                "The password is incorrect");
        }

        [Fact]
        public void Post_throws_on_non_2xx_http_status()
        {
            var flow = new RestFlow().Post("", HttpStatusCode.NotFound);

            Exceptions.AssertThrowsInternalError(
                () => Client.Post(flow, "endpoint", DeviceId, Timestamp, RestClient.NoParameters),
                "failed with status");
        }

        //
        // Helpers
        //

        private class SequenceUi: IUi
        {
            private readonly Passcode[] _passcodes;
            private int _current = 0;

            public SequenceUi(params Passcode[] passcodes)
            {
                _passcodes = passcodes;
            }

            public Passcode ProvideEmailPasscode() => _passcodes[_current++];
        }

        private static IUi GetUi(params Passcode[] passcodes) => new SequenceUi(passcodes);
        private static IUi GetCancelingUi() => GetUi(Passcode.Cancel);
        private static IUi GetPasscodeProvidingUi() => GetUi(new Passcode(EmailPasscode));
    }

    // These tests (hopefully) run in an isolated thread. Here we change the thread global state which might
    // affect other tests that are running in parallel. `DisableParallelization = true` should prevent this.
    [CollectionDefinition("IsolatedThreadClientTest", DisableParallelization = true)]
    public class IsolatedThreadClientTest
    {
        [Fact]
        public void GetEncryptedToken_formats_date_in_en_culture()
        {
            var savedCulture = Thread.CurrentThread.CurrentCulture;
            var savedUiCulture = Thread.CurrentThread.CurrentUICulture;

            try
            {
                Thread.CurrentThread.CurrentCulture = new CultureInfo("fr-FR");
                Thread.CurrentThread.CurrentUICulture = new CultureInfo("fr-FR");

                var flow = new RestFlow()
                    .Post(GetTokenResponse)
                    .ExpectHeader("Date", "Tue, 17 Mar 2020 11:34:56 GMT"); // UTC/GMT time here

                Client.GetEncryptedToken(Username,
                                         DeviceId,
                                         NoPasscode,
                                         DateTime.Parse("Tue, 17 Mar 2020 12:34:56 +01:00"), // Local time here
                                         flow);
            }
            finally
            {
                Thread.CurrentThread.CurrentCulture = savedCulture;
                Thread.CurrentThread.CurrentUICulture = savedUiCulture;
            }
        }
    }

    // This data is shared between ClientTest and IsolatedThreadClientTest
    internal static class ClientTestData
    {
        internal const string BaseUrl = "https://spcb.stickypassword.com/SPCClient/";
        internal const string Username = "LastPass.Ruby@gmaiL.cOm";
        internal const string Password = "Password123!";
        internal const string UrlEncodedUsername = "LastPass.Ruby%40gmaiL.cOm";
        internal const string DeviceId = "12345678-1234-1234-1234-123456789abc";
        internal const string DeviceName = "stickypassword-sharp";
        internal const string EmailPasscode = "passcode-1234";
        internal const string NoPasscode = Client.NoPasscode;

        internal static readonly DateTime Timestamp = new DateTime(year: 1998,
                                                                   month: 3,
                                                                   day: 6,
                                                                   hour: 17,
                                                                   minute: 24,
                                                                   second: 56,
                                                                   kind: DateTimeKind.Utc);

        internal const string Bucket = "bucket";
        internal const string ObjectPrefix = "objectPrefix/";

        internal static readonly S3Token S3Token = new S3Token("access-key-id",
                                                               "secret-access-key",
                                                               "security-token",
                                                               Bucket,
                                                               ObjectPrefix);

        internal const string Version = "123456789";
        internal const string VersionInfo = "VERSION 123456789\nMILESTONE 987654321";

        internal static readonly byte[] DbContent = "All your base are belong to us".ToBytes();
        internal static readonly byte[] CompressedDbContent =
        {
            0x78, 0x9c, 0x73, 0xcc, 0xc9, 0x51, 0xa8, 0xcc,
            0x2f, 0x2d, 0x52, 0x48, 0x4a, 0x2c, 0x4e, 0x55,
            0x48, 0x2c, 0x4a, 0x55, 0x48, 0x4a, 0xcd, 0xc9,
            0xcf, 0x4b, 0x57, 0x28, 0xc9, 0x57, 0x28, 0x2d,
            0x06, 0x00, 0xa5, 0x50, 0x0a, 0xbe,
        };

        internal static readonly byte[] Token = "e450ec3dee464c7ea158cb707f86c52d".ToBytes();
        internal static readonly byte[] EncryptedToken =
        {
            0xd8, 0xcc, 0xc2, 0x1c, 0x69, 0x0a, 0xdb, 0xad,
            0x20, 0x95, 0x5c, 0x1b, 0xf0, 0xaf, 0xdf, 0x78,
            0xbb, 0xd0, 0xd0, 0x15, 0xae, 0xe5, 0x27, 0xb7,
            0xff, 0x79, 0xc1, 0x0b, 0xa9, 0x19, 0xce, 0x40,
        };

        internal const string GetTokenResponse =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<SpcResponse xmlns=\"http://www.stickypassword.com/cb/clientapi/schema/v2\">" +
                "<Status>0</Status>" +
                "<GetCrpTokenResponse>" +
                    "<CrpToken>2MzCHGkK260glVwb8K/feLvQ0BWu5Se3/3nBC6kZzkA=</CrpToken>" +
                "</GetCrpTokenResponse>" +
            "</SpcResponse>";

        internal const string AuthorizeDeviceResponse =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<SpcResponse xmlns=\"http://www.stickypassword.com/cb/clientapi/schema/v2\">" +
                "<Status>0</Status>" +
                "<AccountInfo>" +
                    "<Expiration>2016-12-16Z</Expiration>" +
                    "<LicType>trial</LicType>" +
                    "<AltEmail></AltEmail>" +
                    "<TFAStatus>off</TFAStatus>" +
                "</AccountInfo>" +
            "</SpcResponse>";

        internal const string GetS3TokenResponse =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<SpcResponse xmlns=\"http://www.stickypassword.com/cb/clientapi/schema/v2\">" +
                "<Status>0</Status>" +
                "<AccountInfo>" +
                    "<Expiration>2037-01-01Z</Expiration>" +
                    "<LicType>free</LicType>" +
                    "<AltEmail></AltEmail>" +
                    "<TFAStatus>off</TFAStatus>" +
                "</AccountInfo>" +
                "<GetS3TokenResponse>" +
                    "<AccessKeyId>ASIAIFIAL3EJEOPJXVCQ</AccessKeyId>" +
                    "<SecretAccessKey>TRuR/+smCDzIqEcFTe+WCbgoNXK5OD0k4CdWhD6d</SecretAccessKey>" +
                    "<SessionToken>" +
                        "FQoDYXdzEHYaDMzzWZ6Bc0LZKKiX5iLYAjsN+/1ou0rwiiiGumEdPZ1dE/o0xP1MvUNlgdcN7HKvoXIiQ4yAnawKDU1/" +
                        "7A/cgJ/QNdnj2yJRq0wz9LZkvKeuh+LMu74/GkvR7NZLM7fCg81lySsGq20wol2Z580l8N6QN/B52fsJq2nwYpalRp1/" +
                        "F0KbgRctffGMqelSvXjeqIH6OIdk53oilM72myMPtVZjjv+0CAyTxpg/ObGSdDazUMmNcBHdU5eJr02FXnOL3b/dhvf1" +
                        "YwMexRiMUNkb+0SpCCF4tApvNgR676nIoRSHtVfe7V1IvaKH6jBuDAUHAAJRyOro5+LwCHTOCaADp0jyuWXNJBD4cRah" +
                        "eWeMvLJBQKspgZp17sEO6MQuuTlBApYGngvrg+kISlU2uUKbOYmqpTTueRQR1h2Qp33/K9JWSf3fsvrhDz2Keri8fe9a" +
                        "5qbpkZ5wavsxko3/jZjvKaO76JAjg8xdKPik08MF" +
                    "</SessionToken>" +
                    "<DateExpiration>2017-01-11T12:24:24.000Z</DateExpiration>" +
                    "<BucketName>spclouddata</BucketName>" +
                    "<ObjectPrefix>31645cc8-6ae9-4a22-aaea-557efe9e43af/</ObjectPrefix>" +
                "</GetS3TokenResponse>" +
            "</SpcResponse>";

        internal static readonly string SuccessfulResponse = ResponseWithStatus(0);
        internal static readonly string ResponseWithError = ResponseWithStatus(13);
        internal static readonly string ResponseWithError1006 = ResponseWithStatus(1006);
        internal static readonly string ResponseWithError4002 = ResponseWithStatus(4002);
        internal static readonly string ResponseWithError4003 = ResponseWithStatus(4003);

        internal static string ResponseWithStatus(int status) =>
            "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<SpcResponse xmlns=\"http://www.stickypassword.com/cb/clientapi/schema/v2\">" +
                $"<Status>{status}</Status>" +
            "</SpcResponse>";

    }
}
