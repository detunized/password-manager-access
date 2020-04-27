// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.LastPass;
using Xunit;

namespace PasswordManagerAccess.Test.LastPass
{
    public class ExceptionsTest
    {
        private const string _message = "message";
        private readonly Exception _innerException = new Exception();
        private const FetchException.FailureReason _fetchReason = FetchException.FailureReason.InvalidResponse;
        private const LoginException.FailureReason _loginReason = LoginException.FailureReason.InvalidResponse;
        private const LogoutException.FailureReason _logoutReason = LogoutException.FailureReason.WebException;
        private const ParseException.FailureReason _parseReason = ParseException.FailureReason.CorruptedBlob;

        [Fact]
        public void BaseException_with_message()
        {
            var e = new BaseException(_message);

            Assert.Equal(_message, e.Message);
            Assert.Null(e.InnerException);
        }

        [Fact]
        public void BaseException_with_message_and_inner_exception()
        {
            var e = new BaseException(_message, _innerException);

            Assert.Equal(_message, e.Message);
            Assert.Same(_innerException, e.InnerException);
        }

        [Fact]
        public void FetchException_with_message()
        {
            var e = new FetchException(_fetchReason, _message);

            Assert.Equal(_message, e.Message);
            Assert.Null(e.InnerException);
            Assert.Equal(_fetchReason, e.Reason);
        }

        [Fact]
        public void FetchException_with_message_and_inner_exception()
        {
            var e = new FetchException(_fetchReason, _message, _innerException);

            Assert.Equal(_message, e.Message);
            Assert.Same(_innerException, e.InnerException);
            Assert.Equal(_fetchReason, e.Reason);
        }

        [Fact]
        public void LoginException_with_message()
        {
            var e = new LoginException(_loginReason, _message);

            Assert.Equal(_message, e.Message);
            Assert.Null(e.InnerException);
            Assert.Equal(_loginReason, e.Reason);
        }

        [Fact]
        public void LoginException_with_message_and_inner_exception()
        {
            var e = new LoginException(_loginReason, _message, _innerException);

            Assert.Equal(_message, e.Message);
            Assert.Same(_innerException, e.InnerException);
            Assert.Equal(_loginReason, e.Reason);
        }

        [Fact]
        public void LogoutException_with_message()
        {
            var e = new LogoutException(_logoutReason, _message);

            Assert.Equal(_message, e.Message);
            Assert.Null(e.InnerException);
            Assert.Equal(_logoutReason, e.Reason);
        }

        [Fact]
        public void LogoutException_with_message_and_inner_exception()
        {
            var e = new LogoutException(_logoutReason, _message, _innerException);

            Assert.Equal(_message, e.Message);
            Assert.Same(_innerException, e.InnerException);
            Assert.Equal(_logoutReason, e.Reason);
        }

        [Fact]
        public void ParseException_with_message()
        {
            var e = new ParseException(_parseReason, _message);

            Assert.Equal(_message, e.Message);
            Assert.Null(e.InnerException);
            Assert.Equal(_parseReason, e.Reason);
        }

        [Fact]
        public void ParseException_with_message_and_inner_exception()
        {
            var e = new ParseException(_parseReason, _message, _innerException);

            Assert.Equal(_message, e.Message);
            Assert.Same(_innerException, e.InnerException);
            Assert.Equal(_parseReason, e.Reason);
        }
    }
}
