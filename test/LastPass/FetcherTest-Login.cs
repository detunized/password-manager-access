// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Xml;
using Moq;
using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public partial class FetcherTest
    {
        //
        // Shared data
        //

        private const string Username = "username";
        private const string Password = "password";
        private static readonly ClientInfo ClientInfo = new ClientInfo(Platform.Desktop, "id", "description", true);

        private const string IterationsUrl = "https://lastpass.com/iterations.php";
        private const string LoginUrl = "https://lastpass.com/login.php";
        private const string TrustUrl = "https://lastpass.com/trust.php";

        private const string NoMultifactorPassword = null;
        private const string GoogleAuthenticatorCode = "123456";
        private const string YubikeyPassword = "emdbwzemyisymdnevznyqhqnklaqheaxszzvtnxjrmkb";

        private static readonly ResponseOrException IterationsResponse = new ResponseOrException(IterationCount.ToString());

        private static readonly ResponseOrException OkResponse = new ResponseOrException(
            string.Format("<response><ok sessionid=\"{0}\" privatekeyenc=\"{1}\" /></response>",
                          SessionId,
                          EncryptedPrivateKey));

        private static readonly ResponseOrException OkResponseNoPrivateKey = new ResponseOrException(
            string.Format("<response><ok sessionid=\"{0}\" /></response>",
                          SessionId));

        private static readonly ResponseOrException OkResponseBlankPrivateKey = new ResponseOrException(
            string.Format("<response><ok sessionid=\"{0}\" privatekeyenc=\"\" /></response>",
                          SessionId));

        private static readonly NameValueCollection ExpectedIterationsRequestValues = new NameValueCollection
            {
                {"email", Username}
            };

        private static readonly NameValueCollection ExpectedLoginRequestValues = new NameValueCollection
            {
                {"method", "cli"},
                {"xml", "2"},
                {"username", Username},
                {"hash", "7880a04588cfab954aa1a2da98fd9c0d2c6eba4c53e36a94510e6dbf30759256"},
                {"iterations", string.Format("{0}", IterationCount)},
                {"includeprivatekeyenc", "1"},
                {"outofbandsupported", "1"},
            };

        private const string IncorrectGoogleAuthenticatorCodeMessage = "Google Authenticator code is missing or incorrect";
        private const string IncorrectYubikeyPasswordMessage = "Yubikey password is missing or incorrect";
        private const string OtherCause = "othercause";
        private const string OtherReasonMessage = "Other reason";

        //
        // Login tests
        //

        private class Request
        {
            public readonly string Method;
            public readonly string Url;
            public readonly byte[] Response;
            public readonly Dictionary<string, string> Parameters;
            public readonly Dictionary<string, string> Headers;

            public Request(string method,
                           string url,
                           string response,
                           Dictionary<string, string> parameters = null,
                           Dictionary<string, string> headers = null)
            {
                Method = method;
                Url = url;
                Response = response.ToBytes();
                Parameters = parameters;
                Headers = headers;
            }
        }

        private class MockWebClient: IWebClient
        {
            public MockWebClient(Request[] requests, int failIndex = -1)
            {
                Assert.InRange(failIndex, -1, requests.Length - 1);

                Headers = new WebHeaderCollection();
                _requests = requests;
                _failIndex = failIndex;
            }

            public byte[] DownloadData(string address)
            {
                return CheckRequest(req =>
                {
                    Assert.Equal("GET", req.Method);
                    CheckCommonParts(req, address, null);
                });
            }

            public byte[] UploadValues(string address, NameValueCollection data)
            {
                return CheckRequest(req =>
                {
                    Assert.Equal("POST", req.Method);
                    CheckCommonParts(req, address, data);
                });
            }

            public WebHeaderCollection Headers { get; private set; }

            public void CheckFinished()
            {
                Assert.True(_requests.Length == _currentRequestIndex, "Too few requests have been made");
            }

            private byte[] CheckRequest(Action<Request> check)
            {
                Assert.True(_currentRequestIndex < _requests.Length, "Too many requests");

                try
                {
                    var request = _requests[_currentRequestIndex];
                    check(request);

                    if (_currentRequestIndex == _failIndex)
                        throw new WebException();
                    else
                        return request.Response;
                }
                finally
                {
                    _currentRequestIndex += 1;
                }
            }

            private void CheckCommonParts(Request expected, string url, NameValueCollection parameters)
            {
                Assert.Equal(expected.Url, url);

                if (expected.Parameters != null)
                    CheckParameters(expected.Parameters, parameters);
            }

            private void CheckParameters(Dictionary<string, string> expected, NameValueCollection actual)
            {
                Assert.NotNull(expected);
                Assert.NotNull(actual);

                foreach (var expectedKey in expected)
                {
                    var actualValues = actual.GetValues(expectedKey.Key);
                    Assert.NotNull(actualValues);
                    Assert.Single(actualValues);
                    Assert.Equal(expectedKey.Value, actualValues[0]);
                }

                foreach (var key in actual.AllKeys)
                    Assert.Contains(key, expected.Keys);
            }

            private readonly Request[] _requests;
            private readonly int _failIndex;
            private int _currentRequestIndex = 0;
        }

        private static Session LoginSequence(Request[] requests)
        {
            return Fetcher.Login(Username, Password, ClientInfo, null, new MockWebClient(requests));
        }

        private static void CheckLoginSequence(Request[] requests, Ui ui = null)
        {
            CheckSequence(requests, webClient => Fetcher.Login(Username, Password, ClientInfo, ui, webClient));
        }

        private static void CheckSequence(Request[] requests, Action<IWebClient> executeSequence)
        {
            // Success test
            var webClient = new MockWebClient(requests);
            executeSequence(webClient);
            webClient.CheckFinished();

            // Test failure at each step
            for (var i = 0; i < requests.Length; ++i)
            {
                var e = Assert.Throws<LoginException>(() => executeSequence(new MockWebClient(requests, i)));
                Assert.Equal(LoginException.FailureReason.WebException, e.Reason);
            }
        }

        private static readonly Dictionary<string, string> IterationsParameters = new Dictionary<string, string>
        {
            {"email", Username}
        };

        private static readonly Dictionary<string, string> SimpleLoginParameters = new Dictionary<string, string>
        {
            {"method", "cli"},
            {"xml", "2"},
            {"username", Username},
            {"hash", "7880a04588cfab954aa1a2da98fd9c0d2c6eba4c53e36a94510e6dbf30759256"},
            {"iterations", string.Format("{0}", IterationCount)},
            {"includeprivatekeyenc", "1"},
            {"outofbandsupported", "1"},
            {"uuid", ClientInfo.Id},
            {"trustlabel", ClientInfo.Description},
        };

        private static readonly Dictionary<string, string> GoogleAuthLoginParameters =
            new Dictionary<string, string>(SimpleLoginParameters)
            {
                {"otp", GoogleAuthenticatorCode}
            };

        private static readonly Dictionary<string, string> YubikeyLoginParameters =
            new Dictionary<string, string>(SimpleLoginParameters)
            {
                {"otp", YubikeyPassword}
            };

        private static readonly Dictionary<string, string> OutOfBandLoginParameters =
            new Dictionary<string, string>(SimpleLoginParameters)
            {
                {"outofbandrequest", "1"}
            };

        private static readonly Dictionary<string, string> OutOfBandRetryLoginParameters =
            new Dictionary<string, string>(OutOfBandLoginParameters)
            {
                {"outofbandretry", "1"},
                {"outofbandretryid", "1337"},
            };

        private static readonly Dictionary<string, string> TrustParameters = new Dictionary<string, string>
        {
            {"uuid", ClientInfo.Id},
            {"trustlabel", ClientInfo.Description},
            {"token", Token},
        };

        private static readonly string LoginOkResponse =
            string.Format("<response><ok sessionid=\"{0}\" token=\"{1}\" privatekeyenc=\"{2}\" /></response>",
                          SessionId,
                          Token,
                          EncryptedPrivateKey);

        private static readonly Request IterationsValid = new Request("POST",
                                                                      IterationsUrl,
                                                                      IterationCount.ToString(),
                                                                      IterationsParameters);

        private static readonly Request IterationsInvalid = new Request("POST",
                                                                        IterationsUrl,
                                                                        "Not an integer",
                                                                        IterationsParameters);

        private static readonly Request IterationsTooBig = new Request("POST",
                                                                       IterationsUrl,
                                                                       "2147483648",
                                                                       IterationsParameters);

        private static readonly Request SimpleLoginOk = new Request("POST",
                                                                    LoginUrl,
                                                                    LoginOkResponse,
                                                                    SimpleLoginParameters);

        private static readonly Request SimpleLoginGoogleAuthRequired =
            new Request("POST",
                        LoginUrl,
                        "<response><error cause=\"googleauthrequired\" /></response>");

        private static readonly Request SimpleLoginYubikeyRequired =
            new Request("POST",
                        LoginUrl,
                        "<response><error cause=\"otprequired\" /></response>");

        private static readonly Request SimpleLoginLastPassAuthRequired =
            new Request("POST",
                        LoginUrl,
                        "<response><error cause=\"outofbandrequired\" outofbandtype=\"lastpassauth\" /></response>",
                        SimpleLoginParameters);

        private static readonly Request OobLastPassAuthTimeOut =
            new Request("POST",
                        LoginUrl,
                        "<response><error cause=\"outofbandrequired\" outofbandtype=\"lastpassauth\" retryid=\"1337\" /></response>",
                        OutOfBandLoginParameters);

        private static readonly Request GoogleAuthLogin = new Request("POST",
                                                                      LoginUrl,
                                                                      LoginOkResponse,
                                                                      GoogleAuthLoginParameters);

        private static readonly Request YubikeyLogin = new Request("POST",
                                                                   LoginUrl,
                                                                   LoginOkResponse,
                                                                   YubikeyLoginParameters);

        private static readonly Request OutOfBandLogin = new Request("POST",
                                                                     LoginUrl,
                                                                     LoginOkResponse,
                                                                     OutOfBandLoginParameters);

        private static readonly Request OutOfBandLoginRetry = new Request("POST",
                                                                          LoginUrl,
                                                                          LoginOkResponse,
                                                                          OutOfBandRetryLoginParameters);

        private static readonly Request Trust = new Request("POST",
                                                            TrustUrl,
                                                            "<response />",
                                                            TrustParameters);

        [Fact]
        public void Basic_login_works()
        {
            CheckLoginSequence(new[] {IterationsValid, SimpleLoginOk});
        }

        [Fact]
        public void GoogleAuth_login_works()
        {

            CheckLoginSequence(new[] {IterationsValid, SimpleLoginGoogleAuthRequired, GoogleAuthLogin, Trust},
                               SetupUi(GoogleAuthenticatorCode));
        }

        [Fact]
        public void Yubikey_login_works()
        {

            CheckLoginSequence(new[] {IterationsValid, SimpleLoginYubikeyRequired, YubikeyLogin, Trust},
                               SetupUi(YubikeyPassword));
        }

        [Fact]
        public void LastPassAuth_login_works()
        {

            CheckLoginSequence(new[] {IterationsValid, SimpleLoginLastPassAuthRequired, OutOfBandLogin, Trust},
                               SetupUi(""));
        }

        [Fact]
        public void LastPassAuth_login_with_retry_works()
        {

            CheckLoginSequence(
                new[]
                {
                    IterationsValid,
                    SimpleLoginLastPassAuthRequired,
                    OobLastPassAuthTimeOut,
                    OutOfBandLoginRetry,
                    Trust
                },
                SetupUi(""));
        }

        [Fact]
        public void Login_failed_because_of_invalid_iteration_count()
        {
            var e = Assert.Throws<LoginException>(() => LoginSequence(new[] {IterationsInvalid}));
            Assert.Equal(LoginException.FailureReason.InvalidResponse, e.Reason);
            Assert.Equal("Iteration count is invalid", e.Message);
            Assert.IsType<FormatException>(e.InnerException);
        }

        [Fact]
        public void Login_failed_because_of_very_large_iteration_count()
        {
            var e = Assert.Throws<LoginException>(() => LoginSequence(new[] {IterationsTooBig}));
            Assert.Equal(LoginException.FailureReason.InvalidResponse, e.Reason);
            Assert.Equal("Iteration count is invalid", e.Message);
            Assert.IsType<OverflowException>(e.InnerException);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_because_of_invalid_xml()
        {
            LoginAndVerifyExceptionInLoginRequest<XmlException>(new ResponseOrException("Invalid XML!"),
                                                                LoginException.FailureReason.InvalidResponse,
                                                                "Invalid XML in response");
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_because_of_unknown_email()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("unknownemail", "Unknown email address."),
                                                  LoginException.FailureReason.LastPassInvalidUsername,
                                                  "Invalid username");
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_because_of_invalid_password()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("unknownpassword", "Invalid password!"),
                                                  LoginException.FailureReason.LastPassInvalidPassword,
                                                  "Invalid password");
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_because_of_missing_google_authenticator_code()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("googleauthrequired",
                                                                 "Google Authenticator authentication required! Upgrade your browser extension so you can enter it."),
                                                  LoginException.FailureReason.LastPassIncorrectGoogleAuthenticatorCode,
                                                  IncorrectGoogleAuthenticatorCodeMessage);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_because_of_incorrect_google_authenticator_code()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("googleauthfailed",
                                                                 "Google Authenticator authentication failed!"),
                                                  LoginException.FailureReason.LastPassIncorrectGoogleAuthenticatorCode,
                                                  IncorrectGoogleAuthenticatorCodeMessage);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_because_of_missing_yubikey_password()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("otprequired",
                                                                 "Your account settings have restricted you from logging in from mobile devices that do not support YubiKey authentication."),
                                                  LoginException.FailureReason.LastPassIncorrectYubikeyPassword,
                                                  IncorrectYubikeyPasswordMessage);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_because_of_incorrect_yubikey_password()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("otprequired",
                                                                 "Your account settings have restricted you from logging in from mobile devices that do not support YubiKey authentication."),
                                                  LoginException.FailureReason.LastPassIncorrectYubikeyPassword,
                                                  IncorrectYubikeyPasswordMessage);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_because_out_of_band_authentication_required()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("outofbandrequired",
                                                                 "Multifactor authentication required! Upgrade your browser extension so you can enter it."),
                                                  LoginException.FailureReason.LastPassOutOfBandAuthenticationRequired,
                                                  "Out of band authentication required");
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_because_out_of_band_authentication_failed()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse("multifactorresponsefailed",
                                                                 "Multifactor authentication failed!"),
                                                  LoginException.FailureReason.LastPassOutOfBandAuthenticationFailed,
                                                  "Out of band authentication failed");
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_for_other_reason_with_message()
        {
            LoginAndVerifyExceptionInLoginRequest(FormatResponse(OtherCause, OtherReasonMessage),
                                                  LoginException.FailureReason.LastPassOther,
                                                  OtherReasonMessage);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_for_other_reason_without_message()
        {
            LoginAndVerifyExceptionInLoginRequest(new ResponseOrException(string.Format("<response><error cause=\"{0}\"/></response>",
                                                                                        OtherCause)),
                                                  LoginException.FailureReason.LastPassOther,
                                                  OtherCause);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_with_message_without_cause()
        {
            LoginAndVerifyExceptionInLoginRequest(new ResponseOrException(string.Format("<response><error message=\"{0}\"/></response>",
                                                                          OtherReasonMessage)),
                                                  LoginException.FailureReason.LastPassOther,
                                                  OtherReasonMessage);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_for_unknown_reason_with_error_element()
        {
            LoginAndVerifyExceptionInLoginRequest(new ResponseOrException("<response><error /></response>"),
                                                  LoginException.FailureReason.LastPassUnknown,
                                                  "Unknown reason");
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_failed_because_of_unknown_xml_schema()
        {
            LoginAndVerifyExceptionInLoginRequest(new ResponseOrException("<response />"),
                                                  LoginException.FailureReason.UnknownResponseSchema,
                                                  "Unknown response schema");
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_makes_iterations_request()
        {
            LoginAndVerifyIterationsRequest(NoMultifactorPassword, ExpectedIterationsRequestValues);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_makes_iterations_request_with_google_authenticator()
        {
            LoginAndVerifyIterationsRequest(GoogleAuthenticatorCode, ExpectedIterationsRequestValues);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_makes_iterations_request_with_yubikey()
        {
            LoginAndVerifyIterationsRequest(YubikeyPassword, ExpectedIterationsRequestValues);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_makes_login_request_without_multifactor_password()
        {
            LoginAndVerifyLoginRequest(NoMultifactorPassword, ExpectedLoginRequestValues);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_makes_login_request_with_google_authenticator()
        {
            LoginAndVerifyLoginRequest(GoogleAuthenticatorCode,
                                       new NameValueCollection(ExpectedLoginRequestValues) {{"otp", GoogleAuthenticatorCode}});
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_makes_login_request_with_yubikey()
        {
            LoginAndVerifyLoginRequest(YubikeyPassword,
                                       new NameValueCollection(ExpectedLoginRequestValues) {{"otp", YubikeyPassword}});
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_returns_session_without_multifactor_password()
        {
            LoginAndVerifySession(NoMultifactorPassword);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_returns_session_with_google_authenticator()
        {
            LoginAndVerifySession(GoogleAuthenticatorCode);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_returns_session_with_yubikey_password()
        {
            LoginAndVerifySession(YubikeyPassword);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_returns_session_without_private_key()
        {
            LoginAndVerifySession(NoMultifactorPassword,
                                  OkResponseNoPrivateKey,
                                  expectedPrivateKey: null);
        }

        [Fact(Skip = "TODO: this test is no longer valid")]
        public void Login_returns_session_with_blank_private_key()
        {
            LoginAndVerifySession(NoMultifactorPassword,
                                  OkResponseBlankPrivateKey,
                                  expectedPrivateKey: null);
        }

        //
        // Helpers
        //

        // Formats a valid LastPass response with a cause and a message.
        private static ResponseOrException FormatResponse(string cause, string message)
        {
            return new ResponseOrException(string.Format("<response><error message=\"{0}\" cause=\"{1}\"/></response>",
                                                         message,
                                                         cause));
        }

        private static Ui SetupUi(string multifactorPassword)
        {
            return Mock.Of<Ui>(x => x.ProvideSecondFactorPassword(It.IsAny<Ui.SecondFactorMethod>()) == multifactorPassword);
        }

        // Set up the login process. Response-or-exception parameters provide either
        // response or exception depending on the desired behavior. The login process
        // is two phase: request iteration count, then log in receive the session id.
        // Each of the stages might fail because of the network problems or some other
        // reason.
        private static Mock<IWebClient> SetupLogin(ResponseOrException iterationsResponseOrException,
                                                   ResponseOrException loginResponseOrException = null)
        {
            var webClient = new Mock<IWebClient>();
            var sequence = webClient.SetupSequence(x => x.UploadValues(It.IsAny<string>(),
                                                                       It.IsAny<NameValueCollection>()));

            iterationsResponseOrException.ReturnOrThrow(sequence);
            if (loginResponseOrException != null)
                loginResponseOrException.ReturnOrThrow(sequence);

            return webClient;
        }

        // Imitates the successful login sequence.
        private static Mock<IWebClient> SuccessfullyLogin(string multifactorPassword)
        {
            Session session;
            return SuccessfullyLogin(multifactorPassword, out session);
        }

        // Imitates the successful login sequence, returns the session.
        private static Mock<IWebClient> SuccessfullyLogin(string multifactorPassword, out Session session)
        {
            return SuccessfullyLogin(multifactorPassword, OkResponse, out session);
        }

        // Imitates the successful login sequence, returns the session.
        private static Mock<IWebClient> SuccessfullyLogin(string multifactorPassword,
                                                          ResponseOrException response,
                                                          out Session session)
        {
            var webClient = SetupLogin(IterationsResponse, response);
            session = Fetcher.Login(Username, Password, ClientInfo, SetupUi(multifactorPassword), webClient.Object);
            return webClient;
        }

        // Try to login and expect an exception, which is later validated by the caller.
        private static LoginException LoginAndFailWithException(string multifactorPassword,
                                                                ResponseOrException iterationsResponseOrException,
                                                                ResponseOrException loginResponseOrException = null)
        {
            var webClient = SetupLogin(iterationsResponseOrException, loginResponseOrException);
            return Assert.Throws<LoginException>(() => Fetcher.Login(Username,
                                                                     Password,
                                                                     ClientInfo,
                                                                     SetupUi(multifactorPassword),
                                                                     webClient.Object));
        }

        // Fail in iterations request and verify the exception.
        // Response-or-exception argument should either a string
        // with the provided response or an exception to be thrown.
        private static void LoginAndVerifyExceptionInIterationsRequest<TInnerExceptionType>(ResponseOrException iterationsResponseOrException,
                                                                                            LoginException.FailureReason reason,
                                                                                            string message)
        {
            LoginAndVerifyException(iterationsResponseOrException,
                                    null,
                                    reason,
                                    message,
                                    e => Assert.IsType<TInnerExceptionType>(e));
        }

        // See the overload with an action.
        private static void LoginAndVerifyExceptionInLoginRequest<TInnerExceptionType>(ResponseOrException loginResponseOrException,
                                                                                       LoginException.FailureReason reason,
                                                                                       string message)
        {
            LoginAndVerifyExceptionInLoginRequest(loginResponseOrException,
                                                  reason,
                                                  message,
                                                  e => Assert.IsType<TInnerExceptionType>(e));
        }

        // See the overload with an action.
        private static void LoginAndVerifyExceptionInLoginRequest(ResponseOrException loginResponseOrException,
                                                                  LoginException.FailureReason reason,
                                                                  string message)
        {
            LoginAndVerifyExceptionInLoginRequest(loginResponseOrException, reason, message, Assert.Null);
        }

        // Fail in login request and verify the exception.
        // Response-or-exception argument should either a string
        // with the provided response or an exception to be thrown.
        // The iterations request is not supposed to fail and it's
        // given a valid server response with the proper iteration count.
        private static void LoginAndVerifyExceptionInLoginRequest(ResponseOrException loginResponseOrException,
                                                                  LoginException.FailureReason reason,
                                                                  string message,
                                                                  Action<Exception> verifyInnerException)
        {
            LoginAndVerifyException(IterationsResponse,
                                    loginResponseOrException,
                                    reason,
                                    message,
                                    verifyInnerException);
        }

        // The most generic version. It expects on the requests to fail with an exception.
        // The exception is verified against the expectations.
        private static void LoginAndVerifyException(ResponseOrException iterationsResponseOrException,
                                                    ResponseOrException loginResponseOrException,
                                                    LoginException.FailureReason reason,
                                                    string message,
                                                    Action<Exception> verifyInnerException)
        {
            var exception = LoginAndFailWithException(NoMultifactorPassword,
                                                      iterationsResponseOrException,
                                                      loginResponseOrException);

            Assert.Equal(reason, exception.Reason);
            Assert.Equal(message, exception.Message);
            verifyInnerException(exception.InnerException);
        }

        // Verify the iterations POST request is correct.
        private static void LoginAndVerifyIterationsRequest(string multifactorPassword,
                                                            NameValueCollection expectedValues)
        {
            var webClient = SuccessfullyLogin(multifactorPassword);
            webClient.Verify(x => x.UploadValues(It.Is<string>(s => s == IterationsUrl),
                                                 It.Is<NameValueCollection>(v => AreEqual(v, expectedValues))),
                             "Did not see iterations POST request with expected form data and/or URL");
        }

        // Verify the login POST request is correct.
        private static void LoginAndVerifyLoginRequest(string multifactorPassword,
                                                       NameValueCollection expectedValues)
        {
            var webClient = SuccessfullyLogin(multifactorPassword);
            webClient.Verify(x => x.UploadValues(It.Is<string>(s => s == LoginUrl),
                                                 It.Is<NameValueCollection>(v => AreEqual(v, expectedValues))),
                             "Did not see login POST request with expected form data and/or URL");
        }

        private static void LoginAndVerifySession(string multifactorPassword)
        {
            LoginAndVerifySession(multifactorPassword, OkResponse, EncryptedPrivateKey);
        }

        // Verify the session is correct.
        private static void LoginAndVerifySession(string multifactorPassword,
                                                  ResponseOrException response,
                                                  string expectedPrivateKey)
        {
            Session session;
            SuccessfullyLogin(multifactorPassword, response, out session);

            Assert.Equal(SessionId, session.Id);
            Assert.Equal(IterationCount, session.KeyIterationCount);
            Assert.Equal(expectedPrivateKey, session.EncryptedPrivateKey);
        }

        private static bool AreEqual(NameValueCollection a, NameValueCollection b)
        {
            return a.AllKeys.OrderBy(s => s).SequenceEqual(b.AllKeys.OrderBy(s => s)) &&
                   a.AllKeys.All(s => a[s] == b[s]);
        }
    }
}
