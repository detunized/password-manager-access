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
        private const string IncorrectGoogleAuthenticatorCodeMessage = "Google Authenticator code is missing or incorrect";
        private const string IncorrectYubikeyPasswordMessage = "Yubikey password is missing or incorrect";
        private const string OtherCause = "othercause";
        private const string OtherReasonMessage = "Other reason";

        private const string IterationsUrl = "https://lastpass.com/iterations.php";
        private const string LoginUrl = "https://lastpass.com/login.php";
        private const string AccountDownloadUrl = "https://lastpass.com/getaccts.php?mobile=1&b64=1&hash=0.0";
        private const string Username = "username";
        private const string Password = "password";
        private const int IterationCount = 5000;
        private const string NoMultifactorPassword = null;
        private const string GoogleAuthenticatorCode = "123456";
        private const string YubikeyPassword = "emdbwzemyisymdnevznyqhqnklaqheaxszzvtnxjrmkb";
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
        public void Login_failed_because_of_invalid_xml()
        {
            LoginAndVerifyExceptionInLoginRequest<XmlException>("Invalid XML!",
                                                                LoginException.FailureReason.InvalidResponse,
                                                                "Invalid XML in response");
        }

        [Test]
        public void Login_failed_because_of_unknown_email()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("unknownemail", "Unknown email address."),
                                                  LoginException.FailureReason.LastPassInvalidUsername,
                                                  "Invalid username");
        }

        [Test]
        public void Login_failed_because_of_invalid_password()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("unknownpassword", "Invalid password!"),
                                                  LoginException.FailureReason.LastPassInvalidPassword,
                                                  "Invalid password");
        }

        [Test]
        public void Login_failed_because_of_missing_google_authenticator_code()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("googleauthrequired",
                                                                 "Google Authenticator authentication required! Upgrade your browser extension so you can enter it."),
                                                  LoginException.FailureReason.LastPassIncorrectGoogleAuthenticatorCode,
                                                  IncorrectGoogleAuthenticatorCodeMessage);
        }

        [Test]
        public void Login_failed_because_of_incorrect_google_authenticator_code()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("googleauthfailed",
                                                                 "Google Authenticator authentication failed!"),
                                                  LoginException.FailureReason.LastPassIncorrectGoogleAuthenticatorCode,
                                                  IncorrectGoogleAuthenticatorCodeMessage);
        }

        [Test]
        public void Login_failed_because_of_missing_yubikey_password()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("yubikeyrestricted",
                                                                 "Your account settings have restricted you from logging in from mobile devices that do not support YubiKey authentication."),
                                                  LoginException.FailureReason.LastPassIncorrectYubikeyPassword,
                                                  IncorrectYubikeyPasswordMessage);
        }

        [Test]
        public void Login_failed_because_of_incorrect_yubikey_password()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("yubikeyrestricted",
                                                                 "Your account settings have restricted you from logging in from mobile devices that do not support YubiKey authentication."),
                                                  LoginException.FailureReason.LastPassIncorrectYubikeyPassword,
                                                  IncorrectYubikeyPasswordMessage);
        }

        [Test]
        public void Login_failed_because_out_of_band_authentication_required()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("outofbandrequired",
                                                                 "Multifactor authentication required! Upgrade your browser extension so you can enter it."),
                                                  LoginException.FailureReason.LastPassOutOfBandAuthenticationRequired,
                                                  "Out of band authentication required");
        }

        [Test]
        public void Login_failed_because_out_of_band_authentication_failed()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("multifactorresponsefailed",
                                                                 "Multifactor authentication failed!"),
                                                  LoginException.FailureReason.LastPassOutOfBandAuthenticationFailed,
                                                  "Out of band authentication failed");
        }

        [Test]
        public void Login_failed_for_other_reason_with_message()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse(OtherCause, OtherReasonMessage),
                                                  LoginException.FailureReason.LastPassOther,
                                                  OtherReasonMessage);
        }

        [Test]
        public void Login_failed_for_other_reason_without_message()
        {
            LoginAndVerifyExceptionInLoginRequest(string.Format("<response><error cause=\"{0}\"/></response>",
                                                                OtherCause),
                                                  LoginException.FailureReason.LastPassOther,
                                                  OtherCause);
        }

        [Test]
        public void Login_failed_with_message_without_cause()
        {
            LoginAndVerifyExceptionInLoginRequest(string.Format("<response><error message=\"{0}\"/></response>",
                                                                OtherReasonMessage),
                                                  LoginException.FailureReason.LastPassOther,
                                                  OtherReasonMessage);
        }

        [Test]
        public void Login_failed_for_unknown_reason_with_error_element()
        {
            LoginAndVerifyExceptionInLoginRequest("<response><error /></response>",
                                                  LoginException.FailureReason.LastPassUnknown,
                                                  "Unknown reason");
        }

        [Test]
        public void Login_failed_because_of_unknown_xml_schema()
        {
            LoginAndVerifyExceptionInLoginRequest("<response />",
                                                  LoginException.FailureReason.UnknownResponseSchema,
                                                  "Unknown response schema");
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

            webClient.Verify(x => x.DownloadData(It.Is<string>(a => a == AccountDownloadUrl)));
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
            Assert.AreEqual("Invalid base64 in response", e.Message);
        }

        //
        // Helpers
        //

        private static string FormatResponse(string cause, string message)
        {
            return string.Format("<response><error message=\"{0}\" cause=\"{1}\"/></response>",
                                 message,
                                 cause);
        }

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

        // Fail in login request and verify the exception.
        // Response-or-exception argument should either a string
        // with the provided response or an exception to be thrown.
        // The iteration request is not supposed to fail and it's
        // given a valid server response with the proper iteration count.
        private static void LoginAndVerifyExceptionInLoginRequest(object loginResponseOrException,
                                                                  LoginException.FailureReason reason,
                                                                  string message)
        {
            var exception = LoginAndFailWithException(NoMultifactorPassword,
                                                      IterationResponse,
                                                      loginResponseOrException);

            // Verify the exception is the one we're expecting
            Assert.AreEqual(reason, exception.Reason);
            Assert.AreEqual(message, exception.Message);
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
