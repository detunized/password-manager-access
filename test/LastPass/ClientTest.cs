// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using FluentAssertions;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.LastPass;
using PasswordManagerAccess.LastPass.Ui;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class ClientTest : TestBase
    {
        // The general idea is to test as high level as possible even though it might get tedious.
        // This ensures that if/when the implementation changes we still get the same behavior.

        [Fact]
        public async Task OpenVault_returns_accounts()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse)
                .ExpectUrl("/login.php")
                .Post(OkResponseValidPrivateKey)
                .ExpectUrl("/login.php")
                .Get(BlobBase64)
                .ExpectUrl("/getaccts.php?")
                .Post("")
                .ExpectUrl("/logout.php");

            // Act
            // TODO: Decryption fails here because of the incorrect password
            var accounts = await Client.OpenVault(Username, Password, ClientInfo, null, flow, ParserOptions.Default, null, CancellationToken.None);

            // Assert
            accounts.Should().NotBeEmpty();
        }

        [Fact]
        public async Task OpenVault_returns_accounts_with_iteration_retry()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse)
                .ExpectUrl("/login.php")
                .Post(OkResponseValidPrivateKey)
                .ExpectUrl("/login.php")
                .Get(BlobBase64)
                .ExpectUrl("/getaccts.php?")
                .Post("")
                .ExpectUrl("/logout.php");

            // Act
            // TODO: Decryption fails here because of the incorrect password
            var accounts = await Client.OpenVault(Username, Password, ClientInfo, null, flow, ParserOptions.Default, null, CancellationToken.None);

            // Assert
            accounts.Should().NotBeEmpty();
        }

        [Fact]
        public async Task OpenVault_returns_accounts_with_otp()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse)
                .ExpectUrl("/login.php")
                .Post(OtpRequiredResponse)
                .ExpectUrl("/login.php")
                .Post(OkResponseValidPrivateKey)
                .ExpectUrl("/login.php")
                .ExpectContent($"otp={Otp}")
                .Get(BlobBase64)
                .ExpectUrl("/getaccts.php?")
                .Post("")
                .ExpectUrl("/logout.php");

            // Act
            // TODO: Decryption fails here because of the incorrect password
            var accounts = await Client.OpenVault(
                Username,
                Password,
                ClientInfo,
                GetOtpProvidingUi(),
                flow,
                ParserOptions.Default,
                null,
                CancellationToken.None
            );

            // Assert
            accounts.Should().NotBeEmpty();
        }

        [Fact]
        public async Task OpenVault_returns_accounts_with_otp_and_remember_me()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse)
                .ExpectUrl("/login.php")
                .Post(OtpRequiredResponse)
                .ExpectUrl("/login.php")
                .Post(OkResponseValidPrivateKey)
                .ExpectUrl("/login.php")
                .ExpectContent($"otp={Otp}")
                .Post("")
                .ExpectUrl("/trust.php")
                .Get(BlobBase64)
                .ExpectUrl("/getaccts.php?")
                .Post("")
                .ExpectUrl("/logout.php");

            // Act
            // TODO: Decryption fails here because of the incorrect password
            var accounts = await Client.OpenVault(
                Username,
                Password,
                ClientInfo,
                GetOtpProvidingWithRememberMeUi(),
                flow,
                ParserOptions.Default,
                null,
                CancellationToken.None
            );

            // Assert
            accounts.Should().NotBeEmpty();
        }

        [Fact]
        public async Task OpenVault_returns_accounts_with_oob()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse)
                .ExpectUrl("/login.php")
                .Post(OobRequiredResponse)
                .ExpectUrl("/login.php")
                .Post(OobRetryResponse)
                .ExpectUrl("/login.php")
                .ExpectContent("outofbandrequest=1")
                .Post(OkResponseValidPrivateKey)
                .ExpectUrl("/login.php")
                .ExpectContent("outofbandrequest=1")
                .ExpectContent("outofbandretry=1")
                .ExpectContent("outofbandretryid=retry-id")
                .Get(BlobBase64)
                .ExpectUrl("/getaccts.php?")
                .Post("")
                .ExpectUrl("/logout.php");

            // Act
            // TODO: Decryption fails here because of the incorrect password
            var accounts = await Client.OpenVault(
                Username,
                Password,
                ClientInfo,
                GetWaitingForOobUi(),
                flow,
                ParserOptions.Default,
                null,
                CancellationToken.None
            );

            // Assert
            accounts.Should().NotBeEmpty();
        }

        [Fact]
        public async Task OpenVault_returns_accounts_with_oob_and_remember_me()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse)
                .ExpectUrl("/login.php")
                .Post(OobRequiredResponse)
                .ExpectUrl("/login.php")
                .Post(OobRetryResponse)
                .ExpectUrl("/login.php")
                .ExpectContent("outofbandrequest=1")
                .Post(OkResponseValidPrivateKey)
                .ExpectUrl("/login.php")
                .ExpectContent("outofbandrequest=1")
                .ExpectContent("outofbandretry=1")
                .ExpectContent("outofbandretryid=retry-id")
                .Post("")
                .ExpectUrl("/trust.php")
                .Get(BlobBase64)
                .ExpectUrl("/getaccts.php?")
                .Post("")
                .ExpectUrl("/logout.php");

            // Act
            // TODO: Decryption fails here because of the incorrect password
            var accounts = await Client.OpenVault(
                Username,
                Password,
                ClientInfo,
                GetWaitingForOobWithRememberMeUi(),
                flow,
                ParserOptions.Default,
                null,
                CancellationToken.None
            );

            // Assert
            accounts.Should().NotBeEmpty();
        }

        [Fact]
        public async Task OpenVault_returns_accounts_with_duo_v4()
        {
            var flow = new RestFlow()
                .Post(IterationResponse)
                .ExpectUrl("/login.php")
                .Post(DuoV4RequiredResponse)
                .ExpectUrl("/login.php")
                .LastPassDuo()
                .Post(OkResponseValidPrivateKey)
                .Get(BlobBase64)
                .ExpectUrl("/getaccts.php?")
                .Post("")
                .ExpectUrl("/logout.php");

            var accounts = await Client.OpenVault(
                Username,
                Password,
                ClientInfo,
                GetWaitingForOobUi(),
                flow,
                ParserOptions.Default,
                null,
                CancellationToken.None
            );

            Assert.NotEmpty(accounts);
        }

        [Fact]
        public async Task OpenVault_lower_cases_email()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse)
                .ExpectUrl("/login.php")
                .ExpectContent($"username={Username.EncodeUriData()}")
                .Post(OkResponseValidPrivateKey)
                .ExpectUrl("/login.php")
                .ExpectContent($"username={Username.EncodeUriData()}")
                .Get(BlobBase64)
                .Post("");

            // Act
            // TODO: Decryption fails here because of the incorrect password
            var accounts = await Client.OpenVault(
                Username.ToUpperInvariant(),
                Password,
                ClientInfo,
                null,
                flow,
                ParserOptions.Default,
                null,
                CancellationToken.None
            );

            // Assert
            accounts.Should().NotBeEmpty();
        }

        [Fact]
        public async Task OpenVault_throws_on_invalid_username()
        {
            // Arrange
            var flow = new RestFlow().Post("<response><error cause='unknownemail' /></response>");

            // Act
            var act = () => Client.OpenVault(Username, Password, ClientInfo, null, flow, ParserOptions.Default, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<BadCredentialsException>().WithMessage("Invalid username");
        }

        [Fact]
        public async Task OpenVault_throws_on_invalid_password()
        {
            // Arrange
            var flow = new RestFlow().Post("<response><error cause='unknownpassword' /></response>");

            // Act
            var act = () => Client.OpenVault(Username, Password, ClientInfo, null, flow, ParserOptions.Default, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<BadCredentialsException>().WithMessage("Invalid password");
        }

        [Fact]
        public async Task OpenVault_throws_on_canceled_otp()
        {
            // Arrange
            var flow = new RestFlow().Post(OtpRequiredResponse);

            // Act
            var act = () =>
                Client.OpenVault(Username, Password, ClientInfo, GetCancelingUi(), flow, ParserOptions.Default, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<CanceledMultiFactorException>().WithMessage("Second factor step is canceled by the user");
        }

        [Fact]
        public async Task OpenVault_throws_on_failed_otp()
        {
            // Arrange
            var flow = new RestFlow().Post(OtpRequiredResponse).Post("<response><error cause='googleauthfailed' /></response>");

            // Act
            var act = () =>
                Client.OpenVault(Username, Password, ClientInfo, GetOtpProvidingUi(), flow, ParserOptions.Default, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<BadMultiFactorException>().WithMessage("Second factor code is incorrect");
        }

        [Fact]
        public async Task OpenVault_throws_on_canceled_oob()
        {
            // Arrange
            var flow = new RestFlow().Post(OobRequiredResponse);

            // Act
            var act = () =>
                Client.OpenVault(Username, Password, ClientInfo, GetCancelingUi(), flow, ParserOptions.Default, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<CanceledMultiFactorException>().WithMessage("Out of band step is canceled by the user");
        }

        [Fact]
        public async Task OpenVault_throws_on_failed_oob()
        {
            // Arrange
            var flow = new RestFlow().Post(OobRequiredResponse).Post("<response><error cause='multifactorresponsefailed' /></response>");

            // Act
            var act = () =>
                Client.OpenVault(Username, Password, ClientInfo, GetWaitingForOobUi(), flow, ParserOptions.Default, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<BadMultiFactorException>().WithMessage("Out of band authentication failed");
        }

        [Theory]
        [InlineData("<response><error cause='Blah' /></response>", "Blah")]
        [InlineData("<response><error cause='Pfff' message='Blah' /></response>", "Blah")]
        [InlineData("<response><error message='Blah' /></response>", "Blah")]
        [InlineData("<response><error /></response>", "Unknown error")]
        public async Task OpenVault_throws_on_other_errors(string response, string expected)
        {
            // Arrange
            var flow = new RestFlow().Post(response);

            // Act
            var act = () => Client.OpenVault(Username, Password, ClientInfo, null, flow, ParserOptions.Default, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<InternalErrorException>().WithMessage(expected);
        }

        [Fact]
        public async Task OpenVault_logs_to_secure_logger()
        {
            // Arrange
            var flow = new RestFlow().Post("<response><error cause='Blah' /></response>");
            var logger = new FakeSecureLogger();

            // Act
            var act = () =>
                Client.OpenVault(
                    Username,
                    Password,
                    ClientInfo,
                    null,
                    flow,
                    new ParserOptions { LoggingEnabled = true },
                    logger,
                    CancellationToken.None
                );

            // Assert
            await act.Should().ThrowAsync<InternalErrorException>().WithMessage("Blah");
            logger.Entries.Should().NotBeEmpty();
            logger.Entries.Should().ContainSingle(x => x.Message.Contains("POST https://lastpass.com/login.php"));
        }

        [Fact]
        public async Task OpenVault_does_not_log_to_secure_logger_when_logging_is_disabled()
        {
            // Arrange
            var flow = new RestFlow().Post("<response><error cause='Blah' /></response>");
            var logger = new FakeSecureLogger();

            // Act
            var act = () =>
                Client.OpenVault(
                    Username,
                    Password,
                    ClientInfo,
                    null,
                    flow,
                    new ParserOptions { LoggingEnabled = false },
                    logger,
                    CancellationToken.None
                );

            // Assert
            await act.Should().ThrowAsync<InternalErrorException>().WithMessage("Blah");
            logger.Entries.Should().BeEmpty();
        }

        [Fact]
        public async Task OpenVault_with_duo_v4_does_not_log_to_secure_logger_when_logging_is_disabled()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse)
                .ExpectUrl("/login.php")
                .Post(DuoV4RequiredResponse)
                .ExpectUrl("/login.php")
                .LastPassDuo()
                .Post(OkResponseValidPrivateKey)
                .Get(BlobBase64)
                .ExpectUrl("/getaccts.php?")
                .Post("")
                .ExpectUrl("/logout.php");
            var logger = new FakeSecureLogger();

            // Act
            await Client.OpenVault(Username, Password, ClientInfo, GetWaitingForOobUi(), flow, ParserOptions.Default, logger, CancellationToken.None);

            // Assert
            logger.Entries.Should().BeEmpty();
        }

        [Fact]
        public async Task OpenVault_with_duo_v4_does_not_log_to_secure_logger_when_logger_is_null()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse)
                .ExpectUrl("/login.php")
                .Post(DuoV4RequiredResponse)
                .ExpectUrl("/login.php")
                .LastPassDuo()
                .Post(OkResponseValidPrivateKey)
                .Get(BlobBase64)
                .ExpectUrl("/getaccts.php?")
                .Post("")
                .ExpectUrl("/logout.php");

            // Act
            await Client.OpenVault(Username, Password, ClientInfo, GetWaitingForOobUi(), flow, ParserOptions.Default, null, CancellationToken.None);

            // Nothing to assert. We expect no exceptions.
        }

        [Fact]
        public async Task OpenVault_attaches_log_to_exception()
        {
            // Arrange
            var flow = new RestFlow().Post("<response><error cause='Blah' /></response>");

            // Act
            var act = () =>
                Client.OpenVault(
                    Username,
                    Password,
                    ClientInfo,
                    null,
                    flow,
                    new ParserOptions { LoggingEnabled = true },
                    new NullLogger(),
                    CancellationToken.None
                );

            // Assert
            var e = await act.Should().ThrowAsync<InternalErrorException>().WithMessage("Blah");
            e.And.Log.Should().NotBeEmpty();
            e.And.Log.Should().ContainSingle(x => x.Message.Contains("POST https://lastpass.com/login.php"));
        }

        [Fact]
        public async Task OpenVault_does_not_attach_log_when_logging_is_disabled()
        {
            // Arrange
            var flow = new RestFlow().Post("<response><error cause='Blah' /></response>");

            // Act
            var act = () =>
                Client.OpenVault(
                    Username,
                    Password,
                    ClientInfo,
                    null,
                    flow,
                    new ParserOptions { LoggingEnabled = false },
                    null,
                    CancellationToken.None
                );

            // Assert
            var e = await act.Should().ThrowAsync<InternalErrorException>().WithMessage("Blah");
            e.And.Log.Should().BeEmpty();
        }

        [Theory]
        [InlineData("blahblah")]
        [InlineData("BlahBlah")]
        [InlineData("BLAHBLAH")]
        public async Task OpenVault_censors_username_in_logs(string username)
        {
            // Arrange
            var flow = new RestFlow().Post("<response><error cause='Blah' /></response>");

            // Act
            var act = () =>
                Client.OpenVault(
                    username,
                    Password,
                    ClientInfo,
                    null,
                    flow,
                    new ParserOptions { LoggingEnabled = true },
                    null,
                    CancellationToken.None
                );

            // Assert
            var e = await act.Should().ThrowAsync<InternalErrorException>().WithMessage("Blah");
            e.And.Log.Should().ContainSingle(x => x.Message.Contains("&username=********&"));
        }

        [Fact]
        public async Task Login_returns_session_and_rest_client()
        {
            // Arrange
            var flow = new RestFlow().Post(OkResponse);

            // Act
            var (session, rest) = await Client.Login(Username, Password, ClientInfo, null, flow, null, CancellationToken.None);

            // Assert
            session.KeyIterationCount.Should().Be(DefaultKeyIterationCount);
            AssertSessionWithPrivateKey(session);
            rest.BaseUrl.Should().Be(BaseUrl);
        }

        [Fact]
        public async Task Login_returns_session_and_rest_client_with_iteration_retry()
        {
            // Arrange
            var flow = new RestFlow().Post(IterationResponse).Post(OkResponse);

            // Act
            var (session, rest) = await Client.Login(Username, Password, ClientInfo, null, flow, null, CancellationToken.None);

            // Assert
            session.KeyIterationCount.Should().Be(IterationCount);
            AssertSessionWithPrivateKey(session);
            rest.BaseUrl.Should().Be(BaseUrl);
        }

        [Fact]
        public async Task Login_returns_session_and_rest_client_with_server_retry()
        {
            // Arrange
            var flow = new RestFlow().Post(ServerResponse).ExpectUrl(BaseUrl).Post(OkResponse).ExpectUrl(AlternativeBaseUrl);

            // Act
            var (session, rest) = await Client.Login(Username, Password, ClientInfo, null, flow, null, CancellationToken.None);

            // Assert
            session.KeyIterationCount.Should().Be(DefaultKeyIterationCount);
            AssertSessionWithPrivateKey(session);
            rest.BaseUrl.Should().Be(AlternativeBaseUrl);
        }

        [Fact]
        public async Task Login_returns_session_and_rest_client_with_server_and_iteration_retries()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(ServerResponse)
                .ExpectUrl(BaseUrl)
                .Post(IterationResponse)
                .ExpectUrl(AlternativeBaseUrl)
                .Post(OkResponse)
                .ExpectUrl(AlternativeBaseUrl);

            // Act
            var (session, rest) = await Client.Login(Username, Password, ClientInfo, null, flow, null, CancellationToken.None);

            // Assert
            session.KeyIterationCount.Should().Be(IterationCount);
            AssertSessionWithPrivateKey(session);
            rest.BaseUrl.Should().Be(AlternativeBaseUrl);
        }

        [Fact]
        public async Task Login_returns_session_and_rest_client_with_otp()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(OtpRequiredResponse) // 1. normal login attempt
                .Post(OkResponse) // 2. login with otp
                .Post(""); // 3. save trusted device

            // Act
            var (session, rest) = await Client.Login(Username, Password, ClientInfo, GetOtpProvidingUi(), flow, null, CancellationToken.None);

            // Assert
            session.KeyIterationCount.Should().Be(DefaultKeyIterationCount);
            AssertSessionWithPrivateKey(session);
            rest.BaseUrl.Should().Be(BaseUrl);
        }

        [Fact]
        public async Task Login_returns_session_and_rest_client_with_iteration_retry_and_otp()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse) // 1. normal login attempt
                .Post(OtpRequiredResponse) // 2. normal login attempt with updated iteration count
                .Post(OkResponse) // 3. login with otp
                .Post(""); // 4. save trusted device

            // Act
            var (session, rest) = await Client.Login(Username, Password, ClientInfo, GetOtpProvidingUi(), flow, null, CancellationToken.None);

            // Assert
            session.KeyIterationCount.Should().Be(IterationCount);
            AssertSessionWithPrivateKey(session);
            rest.BaseUrl.Should().Be(BaseUrl);
        }

        [Fact]
        public async Task Login_returns_session_and_rest_client_with_oob()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(OobRequiredResponse) // 1. normal login attempt
                .Post(OkResponse) // 2. check oob
                .Post(""); // 3. save trusted device

            // Act
            var (session, rest) = await Client.Login(Username, Password, ClientInfo, GetWaitingForOobUi(), flow, null, CancellationToken.None);

            // Assert
            session.KeyIterationCount.Should().Be(DefaultKeyIterationCount);
            AssertSessionWithPrivateKey(session);
            rest.BaseUrl.Should().Be(BaseUrl);
        }

        [Fact]
        public async Task Login_returns_session_and_rest_client_with_iteration_retry_and_oob()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(IterationResponse) // 1. normal login attempt
                .Post(OobRequiredResponse) // 2. normal login attempt with updated iteration count
                .Post(OkResponse) // 3. check oob
                .Post(""); // 4. save trusted device

            // Act
            var (session, rest) = await Client.Login(Username, Password, ClientInfo, GetWaitingForOobUi(), flow, null, CancellationToken.None);

            // Assert
            session.KeyIterationCount.Should().Be(IterationCount);
            AssertSessionWithPrivateKey(session);
            rest.BaseUrl.Should().Be(BaseUrl);
        }

        [Fact]
        public async Task PerformSingleLoginRequest_returns_parsed_xml()
        {
            // Arrange
            var flow = new RestFlow().Post("<ok />");

            // Act
            var xml = await Client.PerformSingleLoginRequest(
                Username,
                Password,
                1,
                new Dictionary<string, object>(),
                ClientInfo,
                flow,
                CancellationToken.None
            );

            // Assert
            xml.Should().NotBeNull();
        }

        [Fact]
        public async Task PerformSingleLoginRequest_makes_POST_request_to_specific_url_with_parameters()
        {
            // Arrange
            var flow = new RestFlow()
                .Post("<ok />")
                .ExpectUrl("https://lastpass.com/login.php")
                .ExpectContent("method=cli")
                .ExpectContent($"username={Username.EncodeUriData()}")
                .ExpectContent($"iterations={IterationCount}")
                .ExpectContent("hash=26ecd8a4442e24fde414bd0594233b1bbdb55fa410d56a5d8284a316c7298b65")
                .ExpectContent($"trustlabel={ClientInfo.Description}");

            // Act
            var xml = await Client.PerformSingleLoginRequest(
                Username,
                Password,
                IterationCount,
                new Dictionary<string, object>(),
                ClientInfo,
                flow.ToRestClient(BaseUrl),
                CancellationToken.None
            );

            // Assert
            xml.Should().NotBeNull();
        }

        [Fact]
        public async Task LoginWithOtp_returns_session()
        {
            // Arrange
            var flow = new RestFlow().Post(OkResponse);

            // Act
            var session = await Client.LoginWithOtp(
                Username,
                Password,
                DefaultKeyIterationCount,
                Client.OtpMethod.GoogleAuth,
                ClientInfo,
                GetOtpProvidingUi(),
                flow,
                CancellationToken.None
            );

            // Assert
            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public async Task LoginWithOtp_passes_otp_in_POST_parameters()
        {
            // Arrange
            var flow = new RestFlow().Post(OkResponse).ExpectContent($"otp={Otp}");

            // Act
            var session = await Client.LoginWithOtp(
                Username,
                Password,
                DefaultKeyIterationCount,
                Client.OtpMethod.GoogleAuth,
                ClientInfo,
                GetOtpProvidingUi(),
                flow,
                CancellationToken.None
            );

            // Assert
            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public async Task LoginWithOtp_with_remember_me_marks_device_as_trusted()
        {
            // Arrange
            var flow = new RestFlow().Post(OkResponse).ExpectUrl("/login.php").Post("").ExpectUrl("/trust.php");

            // Act
            var session = await Client.LoginWithOtp(
                Username,
                Password,
                DefaultKeyIterationCount,
                Client.OtpMethod.GoogleAuth,
                ClientInfo,
                GetOtpProvidingWithRememberMeUi(),
                flow,
                CancellationToken.None
            );

            // Assert
            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public async Task LoginWithOob_returns_session()
        {
            // Arrange
            var flow = new RestFlow().Post(OkResponse);

            // Act
            var session = await Client.LoginWithOob(
                Username,
                Password,
                DefaultKeyIterationCount,
                LastPassAuthOobParameters,
                ClientInfo,
                GetWaitingForOobUi(),
                flow,
                null,
                CancellationToken.None
            );

            // Assert
            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public async Task LoginWithOob_retries_after_unsuccessful_attempt()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(OobRetryResponse)
                .Post(OkResponse)
                .ExpectContent("outofbandretry=1")
                .ExpectContent("outofbandretryid=retry-id");

            // Act
            var session = await Client.LoginWithOob(
                Username,
                Password,
                DefaultKeyIterationCount,
                LastPassAuthOobParameters,
                ClientInfo,
                GetWaitingForOobUi(),
                flow,
                null,
                CancellationToken.None
            );

            // Assert
            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public async Task LoginWithOob_sends_otp_in_POST_parameters()
        {
            // Arrange
            var flow = new RestFlow().Post(OkResponse).ExpectContent($"otp={Otp}");

            // Act
            var session = await Client.LoginWithOob(
                Username,
                Password,
                DefaultKeyIterationCount,
                LastPassAuthOobParameters,
                ClientInfo,
                GetPasscodeProvidingOobUi(),
                flow,
                null,
                CancellationToken.None
            );

            // Assert
            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public async Task LoginWithOob_with_remember_me_marks_device_as_trusted()
        {
            // Arrange
            var flow = new RestFlow().Post(OkResponse).ExpectUrl("/login.php").Post("").ExpectUrl("/trust.php");

            // Act
            var session = await Client.LoginWithOob(
                Username,
                Password,
                DefaultKeyIterationCount,
                LastPassAuthOobParameters,
                ClientInfo,
                GetWaitingForOobWithRememberMeUi(),
                flow,
                null,
                CancellationToken.None
            );

            // Assert
            AssertSessionWithPrivateKey(session);
        }

        [Fact]
        public async Task ApproveOob_calls_Ui_ApproveLastPassAuth()
        {
            // Arrange
            var ui = GetCancelingUi();

            // Act
            await Client.ApproveOob(Username, LastPassAuthOobParameters, ui, null, null, CancellationToken.None);

            // Assert
            ui.ApproveLastPassAuthCalledTimes.Should().Be(1);
        }

        [Fact]
        public async Task ApproveOob_calls_Ui_ApproveDuo()
        {
            // Arrange
            var ui = GetCancelingUi();

            // Act
            await Client.ApproveOob(Username, DuoOobParameters, ui, null, null, CancellationToken.None);

            // Assert
            ui.ApproveDuoCalledTimes.Should().Be(1);
        }

        [Fact]
        public void ApproveOob_calls_IDuoUi()
        {
            // TODO: See how to test this. Maybe Duo.Authenticate should be hidden behind an interface that we can mock.
        }

        [Fact]
        public async Task ApproveOob_throws_on_missing_method()
        {
            // Arrange/Act
            var act = () => Client.ApproveOob(Username, new Dictionary<string, string>(), null, null, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<InternalErrorException>().WithMessage("Out of band method is not specified");
        }

        [Fact]
        public async Task ApproveOob_throws_on_unknown_method()
        {
            // Arrange/Act
            var act = () =>
                Client.ApproveOob(Username, new Dictionary<string, string> { ["outofbandtype"] = "blah" }, null, null, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<UnsupportedFeatureException>().WithMessage("Out of band method 'blah' is not supported");
        }

        [Theory]
        [InlineData("duo_host")]
        [InlineData("duo_signature")]
        [InlineData("duo_bytes")]
        public async Task ApproveOob_throws_on_missing_duo_v1_parameters(string name)
        {
            // Arrange
            var parameters = new Dictionary<string, string>
            {
                ["outofbandtype"] = "duo",
                ["preferduowebsdk"] = "1",
                ["duo_host"] = "duo-host",
                ["duo_signature"] = "duo-signature",
                ["duo_bytes"] = "duo-bytes",
            };
            parameters.Remove(name);

            // Act
            var act = () => Client.ApproveOob(Username, parameters, null, null, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<InternalErrorException>().WithMessage($"Invalid response: '{name}' parameter not found");
        }

        [Theory]
        [InlineData("duo_session_token")]
        [InlineData("duo_private_token")]
        public async Task ApproveOob_throws_on_missing_duo_v4_parameters(string name)
        {
            // Arrange
            var parameters = new Dictionary<string, string>
            {
                ["outofbandtype"] = "duo",
                ["preferduowebsdk"] = "1",
                ["duo_authentication_url"] = "duo-authentication-url",
                ["duo_session_token"] = "duo-session-token",
                ["duo_private_token"] = "duo-private-token",
            };
            parameters.Remove(name);

            // Act
            var act = () => Client.ApproveOob(Username, parameters, null, null, null, CancellationToken.None);

            // Assert
            await act.Should().ThrowAsync<InternalErrorException>().WithMessage($"Invalid response: '{name}' parameter not found");
        }

        [Fact]
        public async Task ExchangeDuoSignatureForPasscode_returns_checkduo_code()
        {
            // Arrange
            var flow = new RestFlow().Post("<ok code='blah' />");

            // Act
            var passcode = await Client.ExchangeDuoSignatureForPasscode("", "", "", flow, CancellationToken.None);

            // Assert
            passcode.Should().Be("checkduoblah");
        }

        [Fact]
        public async Task ExchangeDuoSignatureForPasscode_makes_POST_request_to_specific_url_with_parameters()
        {
            // Arrange
            var salt = "salt-salt";
            var signature = "signature-signature";
            var flow = new RestFlow()
                .Post("<ok code='blah' />")
                .ExpectUrl("https://lastpass.com/duo.php")
                .ExpectContent($"username={Username.EncodeUriData()}")
                .ExpectContent($"akey={salt}")
                .ExpectContent($"sig_response={signature}");

            // Act/Assert
            await Client.ExchangeDuoSignatureForPasscode(
                username: Username,
                signature: signature,
                salt: salt,
                rest: flow.ToRestClient(BaseUrl),
                CancellationToken.None
            );
        }

        [Theory]
        [InlineData("<ok code='blah' />")]
        [InlineData("<ok code='blah'></ok>")]
        [InlineData("<ok code='blah' more='not less'></ok>")]
        [InlineData("<ok code='blah' more='not less'><moretags><inside /></moretags></ok>")]
        public void ExtractDuoPasscodeFromDuoResponse_returns_passcode(string response)
        {
            // Arrange
            var xml = XDocument.Parse(response);

            // Act
            var passcode = Client.ExtractDuoPasscodeFromDuoResponse(xml);

            // Assert
            passcode.Should().Be("blah");
        }

        [Theory]
        [InlineData("<ok />")]
        [InlineData("<ok ></ok>")]
        [InlineData("<ok code=''></ok>")]
        [InlineData("<ok notcode='blah'></ok>")]
        [InlineData("<notok code='blah'></notok>")]
        [InlineData("<notok><ok code='blah' /></notok>")]
        public void ExtractDuoPasscodeFromDuoResponse_throws_on_invalid_response(string response)
        {
            // Arrange
            var xml = XDocument.Parse(response);

            // Act
            var act = () => Client.ExtractDuoPasscodeFromDuoResponse(xml);

            // Assert
            act.Should().Throw<InternalErrorException>().WithMessage("Invalid response: *");
        }

        [Fact]
        public async Task MarkDeviceAsTrusted_makes_POST_request_to_specific_url_with_parameters_and_cookies()
        {
            // Arrange
            var flow = new RestFlow()
                .Post("")
                .ExpectUrl("https://lastpass.com/trust.php")
                .ExpectContent($"uuid={ClientInfo.Id}")
                .ExpectContent($"trustlabel={ClientInfo.Description}")
                .ExpectContent($"token={Session.Token}")
                .ExpectCookie("PHPSESSID", Session.Id);

            // Act/Assert
            await Client.MarkDeviceAsTrusted(Session, ClientInfo, flow.ToRestClient(BaseUrl), CancellationToken.None);
        }

        [Fact]
        public async Task Logout_makes_POST_request_to_specific_url_with_parameters_and_cookies()
        {
            // Arrange
            var flow = new RestFlow()
                .Post("")
                .ExpectUrl("https://lastpass.com/logout.php")
                .ExpectContent("method=cli")
                .ExpectContent("noredirect=1")
                .ExpectCookie("PHPSESSID", Session.Id);

            // Act/Assert
            await Client.Logout(Session, flow.ToRestClient(BaseUrl), CancellationToken.None);
        }

        [Fact]
        public async Task DownloadVault_returns_blob()
        {
            // Arrange
            var flow = new RestFlow().Get("blah-blah".ToBytes().ToBase64());

            // Act
            var blob = await Client.DownloadVault(Session, flow, CancellationToken.None);

            // Assert
            blob.Should().Equal("blah-blah".ToBytes());
        }

        [Fact]
        public async Task DownloadVault_makes_GET_request_to_specific_url_with_cookies()
        {
            // Arrange
            var flow = new RestFlow()
                .Get("blah-blah".ToBase64())
                .ExpectUrl("https://lastpass.com/getaccts.php?")
                .ExpectUrl("requestsrc=cli")
                .ExpectCookie("PHPSESSID", Session.Id);

            // Act/Assert
            await Client.DownloadVault(Session, flow.ToRestClient(BaseUrl), CancellationToken.None);
        }

        [Theory]
        [InlineData(Platform.Desktop, "cli")]
        [InlineData(Platform.Mobile, "android")]
        public void GetVaultEndpoint_includes_platform_in_endpoint(Platform platform, string expected)
        {
            // Act
            var endpoint = Client.GetVaultEndpoint(platform);

            // Assert
            endpoint.Should().Contain($"requestsrc={expected}");
        }

        [Fact]
        public void GetSessionCookies_escapes_session_id()
        {
            // Arrange
            var session = new Session(" /:;?=", -1, "", Platform.Desktop, "");

            // Act
            var cookies = Client.GetSessionCookies(session);

            // Assert
            cookies["PHPSESSID"].Should().Be("%20%2F%3A%3B%3F%3D");
        }

        [Fact]
        public void ParseXml_returns_parsed_xml()
        {
            // Arrange
            var response = new RestResponse<string> { Content = "<ok />" };

            // Act
            var xml = Client.ParseXml(response);

            // Assert
            xml.Should().NotBeNull();
        }

        [Fact]
        public void ParseXml_throws_on_invalid_xml()
        {
            // Arrange
            var response = new RestResponse<string> { Content = "> invalid xml <", RequestUri = new Uri("https://int.er.net") };

            // Act
            var act = () => Client.ParseXml(response);

            // Assert
            act.Should().Throw<InternalErrorException>().WithMessage("Failed to parse XML in response from https://int.er.net/");
        }

        [Fact]
        public void ExtractSessionFromLoginResponse_returns_session()
        {
            // Arrange
            var xml = XDocument.Parse(OkResponse);

            // Act
            var session = Client.ExtractSessionFromLoginResponse(xml, DefaultKeyIterationCount, ClientInfo);

            // Assert
            AssertSessionWithPrivateKey(session);
        }

        [Theory]
        [InlineData(OkResponseNoPrivateKey)]
        [InlineData(OkResponseBlankPrivateKey)]
        public void ExtractSessionFromLoginResponse_returns_session_without_private_key(string response)
        {
            // Arrange
            var xml = XDocument.Parse(response);

            // Act
            var session = Client.ExtractSessionFromLoginResponse(xml, DefaultKeyIterationCount, ClientInfo);

            // Assert
            AssertSessionWithoutPrivateKey(session);
        }

        [Theory]
        [InlineData("<response><error blah='' /></response>", "")]
        [InlineData("<response><error blah='blah-blah' /></response>", "blah-blah")]
        public void GetErrorAttribute_returns_attribute_value(string response, string expected)
        {
            // Arrange
            var xml = XDocument.Parse(response);

            // Act
            var value = Client.GetErrorAttribute(xml, "blah");

            // Assert
            value.Should().Be(expected);
        }

        [Fact]
        public void GetErrorAttribute_throws_when_attribute_is_not_present()
        {
            // Arrange
            var xml = XDocument.Parse("<response><error blah='blah-blah' /></response>");

            // Act
            var act = () => Client.GetErrorAttribute(xml, "poof");

            // Assert
            act.Should().Throw<InternalErrorException>().WithMessage("Unknown response schema: attribute 'poof' is missing");
        }

        [Fact]
        public void GetOptionalErrorAttribute_returns_null_when_attribute_is_not_present()
        {
            // Arrange
            var xml = XDocument.Parse("<response><error blah='blah-blah' /></response>");

            // Act
            var value = Client.GetOptionalErrorAttribute(xml, "poof");

            // Assert
            value.Should().BeNull();
        }

        [Fact]
        public void GetAllErrorAttributes_returns_all_names_and_values()
        {
            // Arrange
            var expected = new Dictionary<string, string>
            {
                ["a"] = "b",
                ["c"] = "d",
                ["e"] = "f",
            };

            // Act
            var xml = XDocument.Parse("<response><error a='b' c='d' e='f' /></response>");
            var all = Client.GetAllErrorAttributes(xml);

            // Assert
            all.Should().Equal(expected);
        }

        // TODO: Figure out how to test this!
        //       All methods require username/password which I don't want to expose here.
        //       Actually, I'm pretty sure the password is lost and the whole test blob
        //       needs to be regenerated.
        //       Currently all the vault tests that deal with decryption are disabled.

        [Fact]
        public void ParseVault_returns_vault_with_correct_accounts()
        {
            // Arrange/Act
            var accounts = Client.ParseVault(Blob, TestData.EncryptionKey, TestData.PrivateKey, ParserOptions.Default);

            // Assert
            accounts.Length.Should().BeGreaterOrEqualTo(TestData.Accounts.Length);
            for (var i = 0; i < TestData.Accounts.Length; i++)
            {
                var account = TestData.Accounts[i];

                accounts[i].Id.Should().Be(account.Id);
                accounts[i].Name.Should().Be(account.Name);
                accounts[i].Username.Should().Be(account.Username);
                accounts[i].Password.Should().Be(account.Password);
                accounts[i].Url.Should().Be(account.Url);
                accounts[i].Path.Should().Be(account.Group);
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
            // Arrange/Act
            var act = () => Client.ParseVault(Blob.Sub(0, Blob.Length - cut), TestData.EncryptionKey, TestData.PrivateKey, ParserOptions.Default);

            // Assert
            act.Should().Throw<InternalErrorException>().WithMessage("Blob is truncated or corrupted");
        }

        //
        // Helpers
        //

        private class FakeSecureLogger : ISecureLogger
        {
            public List<LogEntry> Entries { get; } = [];

            public void Log(LogEntry entry) => Entries.Add(entry);
        }

        private class FakeUi(OtpResult otp, OobResult oob) : IAsyncUi
        {
            public int ProvideGoogleAuthPasscodeCalledTimes { get; private set; }
            public int ProvideMicrosoftAuthPasscodeCalledTimes { get; private set; }
            public int ProvideYubikeyPasscodeCalledTimes { get; private set; }
            public int ApproveLastPassAuthCalledTimes { get; private set; }
            public int ApproveDuoCalledTimes { get; private set; }
            public int ChooseDuoFactorCalledTimes { get; set; }
            public int ProvideDuoPasscodeCalledTimes { get; set; }
            public int UpdateDuoStatusCalledTimes { get; set; }

            public Task<OtpResult> ProvideGoogleAuthPasscode(CancellationToken cancellationToken)
            {
                ProvideGoogleAuthPasscodeCalledTimes++;
                return Task.FromResult(otp);
            }

            public Task<OtpResult> ProvideMicrosoftAuthPasscode(CancellationToken cancellationToken)
            {
                ProvideMicrosoftAuthPasscodeCalledTimes++;
                return Task.FromResult(otp);
            }

            public Task<OtpResult> ProvideYubikeyPasscode(CancellationToken cancellationToken)
            {
                ProvideYubikeyPasscodeCalledTimes++;
                return Task.FromResult(otp);
            }

            public Task<OobResult> ApproveLastPassAuth(CancellationToken cancellationToken)
            {
                ApproveLastPassAuthCalledTimes++;
                return Task.FromResult(oob);
            }

            public Task<OobResult> ApproveDuo(CancellationToken cancellationToken)
            {
                ApproveDuoCalledTimes++;
                return Task.FromResult(oob);
            }

            public Task<DuoChoice> ChooseDuoFactor(DuoDevice[] devices, CancellationToken cancellationToken)
            {
                ChooseDuoFactorCalledTimes++;
                return Task.FromResult(new DuoChoice(new DuoDevice("id", "name", [DuoFactor.Push]), DuoFactor.Push, false));
            }

            public Task<string> ProvideDuoPasscode(DuoDevice device, CancellationToken cancellationToken)
            {
                ProvideDuoPasscodeCalledTimes++;
                return Task.FromResult("passcode");
            }

            public Task UpdateDuoStatus(DuoStatus status, string text, CancellationToken cancellationToken)
            {
                UpdateDuoStatusCalledTimes++;
                return Task.CompletedTask;
            }
        }

        // OTP and OOB
        private static FakeUi GetCancelingUi() => new(OtpResult.Cancel, OobResult.Cancel);

        // OTP only
        private static FakeUi GetOtpProvidingUi() => new(new OtpResult(Otp, false), null);

        private static FakeUi GetOtpProvidingWithRememberMeUi() => new(new OtpResult(Otp, true), null);

        // OOB only
        private static FakeUi GetWaitingForOobUi() => new(null, OobResult.WaitForApproval(false));

        private static FakeUi GetWaitingForOobWithRememberMeUi() => new(null, OobResult.WaitForApproval(true));

        private static FakeUi GetPasscodeProvidingOobUi() => new(null, OobResult.ContinueWithPasscode(Otp, false));

        private static void AssertSessionWithPrivateKey(Session session)
        {
            AssertSessionCommon(session);
            session.EncryptedPrivateKey.Should().Be("private-key");
        }

        private static void AssertSessionWithoutPrivateKey(Session session)
        {
            AssertSessionCommon(session);
            session.EncryptedPrivateKey.Should().BeNull();
        }

        private static void AssertSessionCommon(Session session)
        {
            session.Id.Should().Be("session-id");
            session.Token.Should().Be("token");
            session.Platform.Should().Be(Platform.Desktop);
        }

        //
        // Data
        //

        private string BlobBase64 => GetFixture("blob-base64", "txt");
        private byte[] Blob => BlobBase64.Decode64();

        private const string BaseUrl = "https://lastpass.com";
        private const string AlternativeBaseUrl = "https://lastpass.eu";
        private const string Username = "lastpass.ruby@gmail.com";
        private const string Password = "&nT%*pMWJb*7s6u1";
        private const int IterationCount = 5000;
        private const string Otp = "123456";
        private const int DefaultKeyIterationCount = 100100;

        private static readonly ClientInfo ClientInfo = new(Platform.Desktop, "client-id", "description");
        private static readonly Session Session = new("session-id", IterationCount, "token", Platform.Desktop, "private-key");

        private static readonly Dictionary<string, string> LastPassAuthOobParameters = new() { ["outofbandtype"] = "lastpassauth" };

        private static readonly Dictionary<string, string> DuoOobParameters = new() { ["outofbandtype"] = "duo" };

        private static readonly string OkResponseValidPrivateKey =
            "<response>"
            + $"<ok sessionid='session-id' token='token' iterations='{IterationCount}' privatekeyenc='{TestData.EncryptedPrivateKey}' />"
            + "</response>";

        private const string OkResponse = "<response>" + "<ok sessionid='session-id' token='token' privatekeyenc='private-key' />" + "</response>";

        private const string OkResponseNoPrivateKey = "<response>" + "<ok sessionid='session-id' token='token' />" + "</response>";

        private const string OkResponseBlankPrivateKey =
            "<response>" + "<ok sessionid='session-id' token='token' privatekeyenc='' />" + "</response>";

        private const string OtpRequiredResponse = "<response>" + "<error cause='googleauthrequired' />" + "</response>";

        private const string OobRequiredResponse = "<response>" + "<error cause='outofbandrequired' outofbandtype='lastpassauth' />" + "</response>";

        private const string DuoV4RequiredResponse = """
            <response>
                <error cause="outofbandrequired"
                       outofbandtype="duo"
                       preferduowebsdk="1"
                       duo_authentication_url="https://duo.url?sid=duo_sid"
                       duo_session_token="session_token"
                       duo_private_token="private_token"
                />
            </response>
            """;

        private const string OobRetryResponse = "<response>" + "<error cause='outofbandrequired' retryid='retry-id' />" + "</response>";

        private static readonly string IterationResponse = "<response>" + $"<error iterations='{IterationCount}' />" + "</response>";

        private const string ServerResponse =
            "<response>" + "<error server='lastpass.eu' message='our princess is in another castle' />" + "</response>";
    }

    internal static class RestFlowDuoExtensions
    {
        // TODO: Move this part to DuoV4Test
        public static RestFlow Duo(this RestFlow flow)
        {
            return flow.Get(DuoMainHtmlResponse) // Duo: main frame
                .Post("") // Duo: submit system parameters
                .Get(DuoDevicesResponse) // Duo: get devices
                .Post(DuoSubmitFactorResponse) // Duo:
                .Post(DuoStatusSuccessResponse)
                .Post("", responseUrl: "https://duo.done?code=duo_code&state=duo_state");
        }

        public static RestFlow LastPassDuo(this RestFlow flow)
        {
            return flow.Duo().Post(LmiapiDuoResponse);
        }

        private const string DuoMainHtmlResponse = """
            <html>
                <body>
                    <form id="plugin_form">
                        <input name="_xsrf" value="duo_xsrf" />
                    </form>
                </body>
            </html>
            """;

        private const string DuoDevicesResponse = """
            {
                "stat": "OK",
                "response": {
                    "phones": [
                        {
                            "key": "PHONE1",
                            "name": "Phone 1",
                            "sms_batch_size": 10,
                            "next_passcode": "1",
                            "index": "phone1",
                            "requires_compliance_text": true,
                            "keypress_confirm": "",
                            "end_of_number": "1111",
                            "mobile_otpable": true
                        },
                        {
                            "key": "PHONE2",
                            "name": "Phone 2",
                            "sms_batch_size": 10,
                            "next_passcode": "1",
                            "index": "phone2",
                            "requires_compliance_text": true,
                            "keypress_confirm": "",
                            "end_of_number": "2222",
                            "mobile_otpable": true
                        }
                    ],
                    "auth_method_order": [
                        { "deviceKey": "PHONE1", "factor": "Duo Push" },
                        { "deviceKey": "PHONE2", "factor": "Duo Push" },
                        { "deviceKey": "PHONE1", "factor": "SMS Passcode" },
                        { "deviceKey": "PHONE2", "factor": "SMS Passcode" },
                        { "deviceKey": "PHONE1", "factor": "Phone Call" },
                        { "deviceKey": "PHONE2", "factor": "Phone Call" }
                    ]
                }
            }
            """;

        private const string DuoSubmitFactorResponse = """
            {
                "stat": "OK",
                "response": {
                    "txid": "duo_txid"
                }
            }
            """;

        private const string DuoStatusSuccessResponse = """
            {
                "stat": "OK",
                "response": {
                    "status_code": "allow",
                    "result": "SUCCESS",
                    "reason": "User approved",
                }
            }
            """;

        private const string LmiapiDuoResponse = """
            {
                "status": "allowed",
                "oneTimeToken": "duo_one_time_token"
            }
            """;
    }
}
