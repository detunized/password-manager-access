// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Moq;
using NUnit.Framework;
using RestSharp;

namespace StickyPassword.Test
{
    [TestFixture]
    class RemoteTest
    {
        public const string Username = "lebowski";
        public const string Password = "logjammin";
        public const string DeviceId = "ringer";
        public static readonly DateTime Timestamp = new DateTime(1998, 3, 6);

        public static readonly byte[] Token = new byte[]
        {
            0xd8, 0xcc, 0xc2, 0x1c, 0x69, 0x0a, 0xdb, 0xad,
            0x20, 0x95, 0x5c, 0x1b, 0xf0, 0xaf, 0xdf, 0x78,
            0xbb, 0xd0, 0xd0, 0x15, 0xae, 0xe5, 0x27, 0xb7,
            0xff, 0x79, 0xc1, 0x0b, 0xa9, 0x19, 0xce, 0x40
        };

        public const string Response = @"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?><SpcResponse xmlns=""http://www.stickypassword.com/cb/clientapi/schema/v2""><Status>13</Status><GetCrpTokenResponse><CrpToken>2MzCHGkK260glVwb8K/feLvQ0BWu5Se3/3nBC6kZzkA=</CrpToken></GetCrpTokenResponse></SpcResponse>";

        private const string GetS3TokenResponse =
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
                    "<SessionToken>FQoDYXdzEHYaDMzzWZ6Bc0LZKKiX5iLYAjsN+/1ou0rwiiiGumEdPZ1dE/o0xP1MvUNlgdcN7HKvoXIiQ4yAnawKDU1/7A/cgJ/QNdnj2yJRq0wz9LZkvKeuh+LMu74/GkvR7NZLM7fCg81lySsGq20wol2Z580l8N6QN/B52fsJq2nwYpalRp1/F0KbgRctffGMqelSvXjeqIH6OIdk53oilM72myMPtVZjjv+0CAyTxpg/ObGSdDazUMmNcBHdU5eJr02FXnOL3b/dhvf1YwMexRiMUNkb+0SpCCF4tApvNgR676nIoRSHtVfe7V1IvaKH6jBuDAUHAAJRyOro5+LwCHTOCaADp0jyuWXNJBD4cRaheWeMvLJBQKspgZp17sEO6MQuuTlBApYGngvrg+kISlU2uUKbOYmqpTTueRQR1h2Qp33/K9JWSf3fsvrhDz2Keri8fe9a5qbpkZ5wavsxko3/jZjvKaO76JAjg8xdKPik08MF</SessionToken>" +
                    "<DateExpiration>2017-01-11T12:24:24.000Z</DateExpiration>" +
                    "<BucketName>spclouddata</BucketName>" +
                    "<ObjectPrefix>31645cc8-6ae9-4a22-aaea-557efe9e43af/</ObjectPrefix>" +
                "</GetS3TokenResponse>" +
            "</SpcResponse>";

        [Test]
        public void GetEncryptedToken_sets_api_base_url()
        {
            var client = SetupClient();

            Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object);

            client.VerifySet(x => x.BaseUrl = It.Is<Uri>(
                u => u.AbsoluteUri.Contains("stickypassword.com/SPCClient")));
        }

        [Test]
        public void GetEncryptedToken_sets_user_agent_with_device_id()
        {
            var client = SetupClient();

            Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object);

            client.VerifySet(x => x.UserAgent = It.Is<string>(s => s.Contains(DeviceId)));
        }

        [Test]
        public void GetEncryptedToken_makes_post_request_to_specific_end_point()
        {
            var client = SetupClient();

            Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object);

            client.Verify(x => x.Execute(It.Is<IRestRequest>(
                r => r.Method == Method.POST && r.Resource == "GetCrpToken")));
        }

        [Test]
        public void GetEncryptedToken_date_header_is_set()
        {
            var client = SetupClient();

            Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object);

            var expectedDate = Timestamp.ToUniversalTime().ToString("R");
            client.Verify(x => x.Execute(It.Is<IRestRequest>(
                r => r.Parameters.Exists(
                    p => p.Type == ParameterType.HttpHeader
                        && p.Name == "Date"
                        && p.Value.ToString() == expectedDate))));
        }

        [Test]
        public void GetEncryptedToken_returns_response()
        {
            var client = SetupClient();

            Assert.That(
                Remote.GetEncryptedToken(Username, DeviceId, Timestamp, client.Object),
                Is.EqualTo(Token));
        }

        [Test]
        public void AuthorizeDevice_works()
        {
            // TODO: Provide the actual response
            var client = SetupClient("<SpcResponse><Status>4005</Status></SpcResponse>");

            // TODO: DRY this up
            Remote.AuthorizeDevice(
                "LastPass.Ruby@gmaiL.cOm",
                "e450ec3dee464c7ea158cb707f86c52d".ToBytes(),
                "12345678-1234-1234-1234-123456789abc",
                "stickypassword-sharp",
                Timestamp,
                client.Object);
        }

        [Test]
        public void GetS3Token_returns_s3_token()
        {
            var client = SetupClient(GetS3TokenResponse);

            // TODO: DRY this up
            var s3 = Remote.GetS3Token(
                "LastPass.Ruby@gmaiL.cOm",
                "e450ec3dee464c7ea158cb707f86c52d".ToBytes(),
                "12345678-1234-1234-1234-123456789abc",
                Timestamp,
                client.Object);

            Assert.That(s3.AccessKeyId, Is.EqualTo("ASIAIFIAL3EJEOPJXVCQ"));
            Assert.That(s3.SecretAccessKey, Is.EqualTo("TRuR/+smCDzIqEcFTe+WCbgoNXK5OD0k4CdWhD6d"));
            Assert.That(s3.SessionToken, Is.EqualTo("FQoDYXdzEHYaDMzzWZ6Bc0LZKKiX5iLYAjsN+/1ou0rwiiiGumEdPZ1dE/o0xP1MvUNlgdcN7HKvoXIiQ4yAnawKDU1/7A/cgJ/QNdnj2yJRq0wz9LZkvKeuh+LMu74/GkvR7NZLM7fCg81lySsGq20wol2Z580l8N6QN/B52fsJq2nwYpalRp1/F0KbgRctffGMqelSvXjeqIH6OIdk53oilM72myMPtVZjjv+0CAyTxpg/ObGSdDazUMmNcBHdU5eJr02FXnOL3b/dhvf1YwMexRiMUNkb+0SpCCF4tApvNgR676nIoRSHtVfe7V1IvaKH6jBuDAUHAAJRyOro5+LwCHTOCaADp0jyuWXNJBD4cRaheWeMvLJBQKspgZp17sEO6MQuuTlBApYGngvrg+kISlU2uUKbOYmqpTTueRQR1h2Qp33/K9JWSf3fsvrhDz2Keri8fe9a5qbpkZ5wavsxko3/jZjvKaO76JAjg8xdKPik08MF"));
            Assert.That(s3.DateExpiration, Is.EqualTo("2017-01-11T12:24:24.000Z"));
            Assert.That(s3.BucketName, Is.EqualTo("spclouddata"));
            Assert.That(s3.ObjectPrefix, Is.EqualTo("31645cc8-6ae9-4a22-aaea-557efe9e43af/"));
        }

        //
        // Helpers
        //

        private static Mock<IRestClient> SetupClient(string response = Response)
        {
            var mock = new Mock<IRestClient>();
            mock
                .Setup(x => x.Execute(It.IsAny<IRestRequest>()))
                .Returns(SetupResponse(response).Object);
            return mock;
        }

        private static Mock<IRestResponse> SetupResponse(string response)
        {
            var mock = new Mock<IRestResponse>();
            mock.Setup(x => x.Content).Returns(response);
            return mock;
        }
    }
}
