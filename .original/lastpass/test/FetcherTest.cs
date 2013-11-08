using System;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Xml;
using Moq;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class FetcherTest
    {
        private const string WebExceptionMessage = "WebException occured";
        private const string UnknownEmailMessage = "Invalid username";
        private const string InvalidPasswordMessage = "Invalid password";
        private const string IncorrectGoogleAuthenticatorCodeMessage = "Google Authenticator code is missing or incorrect";
        private const string MissingYubikeyPasswordMessage = "Yubikey password is missing or incorrect";
        private const string IncorrectYubikeyPasswordMessage = "Yubikey password is missing or incorrect";
        private const string OutOfBandAuthenticationRequiredMessage = "Out of band authentication required";
        private const string OutOfBandAuthenticationFailedMessage = "Out of band authentication failed";
        private const string OtherCause = "othercause";
        private const string OtherReasonMessage = "Other reason";
        private const string UnknownReasonMessage = "Unknown reason";
        private const string UnknownResponseSchemaMessage = "Unknown response schema";
        private const string InvalidXmlMessage = "Invalid XML in response";
        private const string InvalidBase64Message = "Invalid base64 in response";

        private const string IterationsUrl = "https://lastpass.com/iterations.php";
        private const string LoginUrl = "https://lastpass.com/login.php";
        private const string AccoutDownloadUrl = "https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0";
        private const string Username = "username";
        private const string Password = "password";
        private const int IterationCount = 5000;
        private const string NoMultifactorPassword = null;
        private const string GoogleAuthenticatorCode = "123456";
        private const string IncorrectGoogleAuthenticatorCode = "654321";
        private const string YubikeyPassword = "emdbwzemyisymdnevznyqhqnklaqheaxszzvtnxjrmkb";
        private const string IncorrectYubikeyPassword = "qlzpirxbsmanfzydaqlkcmiydzmhqjfemruyzyqhmray";
        private const string SessionId = "53ru,Hb713QnEVM5zWZ16jMvxS0";

        private static readonly string IterationResponse = IterationCount.ToString();
        private static readonly string OkResponse = string.Format("<ok sessionid=\"{0}\" />", SessionId);

        private static readonly NameValueCollection SharedExpectedValues = new NameValueCollection
            {
                {"method", "mobile"},
                {"web", "1"},
                {"xml", "1"},
                {"username", Username}
            };

        private static readonly NameValueCollection ExpectedValues = new NameValueCollection(SharedExpectedValues)
            {
                {"hash", "7880a04588cfab954aa1a2da98fd9c0d2c6eba4c53e36a94510e6dbf30759256"},
                {"iterations", string.Format("{0}", IterationCount)}
            };

        //
        // Login
        //

        [Test]
        public void Login_failed_because_of_WebException_in_iteration_request()
        {
            LoginAndVerifyExceptionInIterationRequest<WebException>(new WebException(),
                                                                    LoginException.FailureReason.WebException,
                                                                    WebExceptionMessage);
        }

        [Test]
        public void Login_failed_because_of_WebException_in_login_request()
        {
            LoginAndVerifyExceptionInLoginRequest<WebException>(new WebException(),
                                                                LoginException.FailureReason.WebException,
                                                                WebExceptionMessage);
        }

        [Test]
        public void Login_failed_because_of_unknown_email()
        {
            LoginAndVerifyException(
                "<response><error message=\"Unknown email address.\" cause=\"unknownemail\" /></response>",
                LoginException.FailureReason.LastPassInvalidUsername,
                UnknownEmailMessage);
        }

        [Test]
        public void Login_failed_because_of_invalid_password()
        {
            LoginAndVerifyException(
                "<response><error message=\"Invalid password!\" cause=\"unknownpassword\" /></response>",
                LoginException.FailureReason.LastPassInvalidPassword,
                InvalidPasswordMessage);
        }

        [Test]
        public void Login_failed_because_of_missing_google_authenticator_code()
        {
            LoginAndVerifyException(
                "<response>" +
                    "<error " +
                        "message=\"Google Authenticator authentication required! Upgrade your browser extension so you can enter it.\" " +
                        "cause=\"googleauthrequired\" " +
                    "/>" +
                "</response>",
                LoginException.FailureReason.LastPassIncorrectGoogleAuthenticatorCode,
                IncorrectGoogleAuthenticatorCodeMessage);
        }

        [Test]
        public void Login_failed_because_of_incorrect_google_authenticator_code()
        {
            LoginAndVerifyException(
                IncorrectGoogleAuthenticatorCode,
                "<response>" +
                    "<error " +
                        "message=\"Google Authenticator authentication failed!\" " +
                        "cause=\"googleauthfailed\" " +
                    "/>" +
                "</response>",
                LoginException.FailureReason.LastPassIncorrectGoogleAuthenticatorCode,
                IncorrectGoogleAuthenticatorCodeMessage);
        }

        [Test]
        public void Login_failed_because_of_missing_yubikey_password()
        {
            LoginAndVerifyException(
                "<response>" +
                    "<error " +
                        "message=\"Your account settings have restricted you from logging in from mobile devices that do not support YubiKey authentication.\" " +
                        "cause=\"yubikeyrestricted\" " +
                    "/>" +
                "</response>",
                LoginException.FailureReason.LastPassIncorrectYubikeyPassword,
                MissingYubikeyPasswordMessage);
        }

        [Test]
        public void Login_failed_because_of_incorrect_yubikey_password()
        {
            LoginAndVerifyException(
                IncorrectYubikeyPassword,
                "<response>" +
                    "<error " +
                        "message=\"Your account settings have restricted you from logging in from mobile devices that do not support YubiKey authentication.\" " +
                        "cause=\"yubikeyrestricted\" " +
                    "/>" +
                "</response>",
                LoginException.FailureReason.LastPassIncorrectYubikeyPassword,
                IncorrectYubikeyPasswordMessage);
        }

        [Test]
        public void Login_failed_because_out_of_band_authentication_required()
        {
            LoginAndVerifyException(
                "<response>" +
                    "<error " +
                        "message=\"Multifactor authentication required! Upgrade your browser extension so you can enter it.\" " +
                        "cause=\"outofbandrequired\" " +
                        "retryid=\"2091457e-0ae8-4bee-948c-345afb49a132\" " +
                    "/>" +
                "</response>",
                LoginException.FailureReason.LastPassOutOfBandAuthenticationRequired,
                OutOfBandAuthenticationRequiredMessage);
        }

        [Test]
        public void Login_failed_because_out_of_band_authentication_failed()
        {
            LoginAndVerifyException(
                "<response>" +
                    "<error " +
                        "message=\"Multifactor authentication failed!\" " +
                        "cause=\"multifactorresponsefailed\" " +
                        "type=\"outofband\" " +
                    "/>" +
                "</response>",
                LoginException.FailureReason.LastPassOutOfBandAuthenticationFailed,
                OutOfBandAuthenticationFailedMessage);
        }

        [Test]
        public void Login_failed_for_other_reason_with_message()
        {
            LoginAndVerifyException(
                string.Format("<response><error message=\"{0}\" cause=\"{1}\"/></response>",
                              OtherReasonMessage,
                              OtherCause),
                LoginException.FailureReason.LastPassOther,
                OtherReasonMessage);
        }

        [Test]
        public void Login_failed_for_other_reason_without_message()
        {
            LoginAndVerifyException(
                string.Format("<response><error cause=\"{0}\"/></response>", OtherCause),
                LoginException.FailureReason.LastPassOther,
                OtherCause);
        }

        [Test]
        public void Login_failed_with_message_without_cause()
        {
            LoginAndVerifyException(
                string.Format("<response><error message=\"{0}\"/></response>", OtherReasonMessage),
                LoginException.FailureReason.LastPassOther,
                OtherReasonMessage);
        }

        [Test]
        public void Login_failed_for_unknown_reason_with_error_element()
        {
            LoginAndVerifyException(
                "<response><error /></response>",
                LoginException.FailureReason.LastPassUnknown,
                UnknownReasonMessage);
        }

        [Test]
        public void Login_failed_because_of_unknown_xml_schema()
        {
            LoginAndVerifyException(
                "<response />",
                LoginException.FailureReason.UnknownResponseSchema,
                UnknownResponseSchemaMessage);
        }

        [Test]
        public void Login_failed_because_of_invalid_xml()
        {
            var exception = LoginAndFailWithException(NoMultifactorPassword, IterationResponse, "Invalid XML!");

            Assert.AreEqual(LoginException.FailureReason.InvalidResponse, exception.Reason);
            Assert.AreEqual(InvalidXmlMessage, exception.Message);
            Assert.IsInstanceOf<XmlException>(exception.InnerException);
        }

        [Test]
        public void Login_requests_iteration_count()
        {
            // Simulate login process
            var webClient = new Mock<IWebClient>();
            webClient
                .SetupSequence(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Returns(IterationResponse.ToBytes())
                .Returns(OkResponse.ToBytes());

            Fetcher.Login(Username, Password, NoMultifactorPassword, webClient.Object);

            // Verify the requests were made with appropriate POST values
            var expectedValues = new NameValueCollection {{"email", Username}};
            webClient.Verify(x => x.UploadValues(It.Is<string>(s => s == IterationsUrl),
                                                 It.Is<NameValueCollection>(v => AreEqual(v, expectedValues))),
                             "Did not see POST request with expected values");
        }

        [Test]
        public void Login_requests_with_correct_values()
        {
            LoginAndVerify(NoMultifactorPassword, ExpectedValues);
        }

        [Test]
        public void Login_requests_with_correct_values_with_google_authenticator()
        {
            LoginAndVerify(GoogleAuthenticatorCode,
                           new NameValueCollection(ExpectedValues) {{"otp", GoogleAuthenticatorCode}});
        }

        [Test]
        public void Login_requests_with_correct_values_with_yubikey()
        {
            LoginAndVerify(YubikeyPassword,
                           new NameValueCollection(ExpectedValues) {{"otp", YubikeyPassword}});
        }

        //
        // Download
        //

        [Test]
        public void Fetch_sets_cookies()
        {
            var session = new Session(SessionId, IterationCount);
            var headers = new WebHeaderCollection();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(headers);

            Fetcher.Fetch(session, webClient.Object);

            Assert.AreEqual(string.Format("PHPSESSID={0}", Uri.EscapeDataString(SessionId)),
                            headers["Cookie"]);
        }

        [Test]
        public void Fetch_requests_accounts_from_correct_url()
        {
            var session = new Session(SessionId, IterationCount);
            var response = "VGVzdCBibG9i".ToBytes();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns(response);

            Fetcher.Fetch(session, webClient.Object);

            webClient.Verify(x => x.DownloadData(It.Is<string>(a => a == AccoutDownloadUrl)));
        }

        [Test]
        public void Fetch_returns_blob()
        {
            var session = new Session(SessionId, IterationCount);
            var response = "VGVzdCBibG9i".ToBytes();
            var expectedBlob = "Test blob".ToBytes();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns(response);

            var blob = Fetcher.Fetch(session, webClient.Object);

            Assert.AreEqual(expectedBlob, blob.Bytes);
            Assert.AreEqual(IterationCount, blob.KeyIterationCount);
        }

        [Test]
        public void Fetch_throws_on_WebException()
        {
            var session = new Session(SessionId, IterationCount);
            var webException = new WebException();

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Throws(webException);

            var e = Assert.Throws<FetchException>(() => Fetcher.Fetch(session, webClient.Object));
            Assert.AreEqual(FetchException.FailureReason.WebException, e.Reason);
            Assert.AreEqual(WebExceptionMessage, e.Message);
            Assert.AreSame(webException, e.InnerException);
        }

        [Test]
        public void Fetch_throws_on_invalid_response()
        {
            var session = new Session(SessionId, IterationCount);

            var webClient = new Mock<IWebClient>();
            webClient
                .SetupGet(x => x.Headers)
                .Returns(new WebHeaderCollection());

            webClient
                .Setup(x => x.DownloadData(It.IsAny<string>()))
                .Returns("Invalid base64 string!".ToBytes());

            var e = Assert.Throws<FetchException>(() => Fetcher.Fetch(session, webClient.Object));
            Assert.AreEqual(FetchException.FailureReason.InvalidResponse, e.Reason);
            Assert.AreEqual(InvalidBase64Message, e.Message);
        }

        //
        // Helpers
        //

        // Set up the login process. Response-or-exception parameters provide either
        // response or exception depending on the desired behavior. The login process
        // is two phase: request iteration count, then log in receive the session id.
        // Each of the stages might fail because of the network problems or some other
        // reason.
        private static Mock<IWebClient> SetupLogin(object iterationResponseOrException,
                                                   object loginResponseOrException = null)
        {
            var webClient = new Mock<IWebClient>();
            var sequence = webClient.SetupSequence(x => x.UploadValues(It.IsAny<string>(),
                                                                       It.IsAny<NameValueCollection>()));

            Assert.IsNotNull(iterationResponseOrException);
            if (iterationResponseOrException is Exception)
                sequence.Throws((Exception)iterationResponseOrException);
            else
            {
                Assert.IsInstanceOf<string>(iterationResponseOrException);
                sequence = sequence.Returns(((string)iterationResponseOrException).ToBytes());

                Assert.IsNotNull(loginResponseOrException);
                if (loginResponseOrException is Exception)
                    sequence.Throws((Exception)loginResponseOrException);
                else
                    sequence.Returns(((string)loginResponseOrException).ToBytes());
            }

            return webClient;
        }

        // Try to login and expect an exception, which is later validated by the caller.
        private static LoginException LoginAndFailWithException(string multifactorPassword,
                                                                object iterationResponseOrException,
                                                                object loginResponseOrException = null)
        {
            var webClient = SetupLogin(iterationResponseOrException, loginResponseOrException);
            return Assert.Throws<LoginException>(() => Fetcher.Login(Username,
                                                                     Password,
                                                                     multifactorPassword,
                                                                     webClient.Object));
        }

        // Fail in iteration request and verify the exception.
        // Response-or-exception argument should either a string
        // with the provided response or an exception to be thrown.
        private static void LoginAndVerifyExceptionInIterationRequest<TInnerExceptionType>(object iterationResponseOrException,
                                                                                           LoginException.FailureReason reason,
                                                                                           string message)
        {
            var exception = LoginAndFailWithException(NoMultifactorPassword, iterationResponseOrException);

            // Verify the exception is the one we're expecting
            Assert.AreEqual(reason, exception.Reason);
            Assert.AreEqual(message, exception.Message);
            Assert.IsInstanceOf<TInnerExceptionType>(exception.InnerException);
        }

        // Fail in login request and verify the exception.
        // Response-or-exception argument should either a string
        // with the provided response or an exception to be thrown.
        // The iteration request is not supposed to fail and it's
        // given a valid server response with the proper iteration count.
        private static void LoginAndVerifyExceptionInLoginRequest<TInnerExceptionType>(object loginResponseOrException,
                                                                                       LoginException.FailureReason reason,
                                                                                       string message)
        {
            var exception = LoginAndFailWithException(NoMultifactorPassword,
                                                      IterationResponse,
                                                      loginResponseOrException);

            // Verify the exception is the one we're expecting
            Assert.AreEqual(reason, exception.Reason);
            Assert.AreEqual(message, exception.Message);
            Assert.IsInstanceOf<TInnerExceptionType>(exception.InnerException);
        }

        private static void LoginAndVerifyException(string response,
                                                    LoginException.FailureReason reason,
                                                    string message)
        {
            LoginAndVerifyException(NoMultifactorPassword, response, reason, message);
        }

        private static void LoginAndVerifyException(string multifactorPassword,
                                                    string response,
                                                    LoginException.FailureReason reason,
                                                    string message,
                                                    Exception innerException = null)
        {
            var exception = LoginAndFailWithException(multifactorPassword, IterationResponse, response);

            // Verify the exception is the one we're expecting
            Assert.AreEqual(reason, exception.Reason);
            Assert.AreEqual(message, exception.Message);
            Assert.AreSame(innerException, exception.InnerException);
        }

        private static void LoginAndVerify(string multifactorPassword, NameValueCollection expectedValues)
        {
            // Simulate successful login
            var webClient = new Mock<IWebClient>();
            webClient
                .SetupSequence(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Returns(IterationResponse.ToBytes())
                .Returns(OkResponse.ToBytes());

            Fetcher.Login(Username, Password, multifactorPassword, webClient.Object);

            // Verify the requests were made with appropriate POST values
            webClient.Verify(x => x.UploadValues(It.Is<string>(s => s == LoginUrl),
                                                 It.Is<NameValueCollection>(v => AreEqual(v, expectedValues))),
                             "Did not see POST request with expected values");
        }

        private static bool AreEqual(NameValueCollection a, NameValueCollection b)
        {
            return a.AllKeys.OrderBy(s => s).SequenceEqual(b.AllKeys.OrderBy(s => s)) &&
                   a.AllKeys.All(s => a[s] == b[s]);
        }
    }
}
