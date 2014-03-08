// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class ExceptionsTest
    {
        private const string _message = "message";
        private readonly Exception _innerException = new Exception();
        private const FetchException.FailureReason _fetchReason = FetchException.FailureReason.InvalidResponse;
        private const LoginException.FailureReason _loginReason = LoginException.FailureReason.InvalidResponse;
        private const ParseException.FailureReason _parseReason = ParseException.FailureReason.CorruptedBlob;

        [Test]
        public void BaseException_with_message()
        {
            var e = new BaseException(_message);
            Assert.AreEqual(_message, e.Message);
            Assert.IsNull(e.InnerException);
        }

        [Test]
        public void BaseException_with_message_and_inner_exception()
        {
            var e = new BaseException(_message, _innerException);
            Assert.AreEqual(_message, e.Message);
            Assert.AreSame(_innerException, e.InnerException);
        }

        [Test]
        public void FetchException_with_message()
        {
            var e = new FetchException(_fetchReason, _message);
            Assert.AreEqual(_message, e.Message);
            Assert.IsNull(e.InnerException);
            Assert.AreEqual(_fetchReason, e.Reason);
        }

        [Test]
        public void FetchException_with_message_and_inner_exception()
        {
            var e = new FetchException(_fetchReason, _message, _innerException);
            Assert.AreEqual(_message, e.Message);
            Assert.AreSame(_innerException, e.InnerException);
            Assert.AreEqual(_fetchReason, e.Reason);
        }

        [Test]
        public void LoginException_with_message()
        {
            var e = new LoginException(_loginReason, _message);
            Assert.AreEqual(_message, e.Message);
            Assert.IsNull(e.InnerException);
            Assert.AreEqual(_loginReason, e.Reason);
        }

        [Test]
        public void LoginException_with_message_and_inner_exception()
        {
            var e = new LoginException(_loginReason, _message, _innerException);
            Assert.AreEqual(_message, e.Message);
            Assert.AreSame(_innerException, e.InnerException);
            Assert.AreEqual(_loginReason, e.Reason);
        }

        [Test]
        public void ParseException_with_message()
        {
            var e = new ParseException(_parseReason, _message);
            Assert.AreEqual(_message, e.Message);
            Assert.IsNull(e.InnerException);
            Assert.AreEqual(_parseReason, e.Reason);
        }

        [Test]
        public void ParseException_with_message_and_inner_exception()
        {
            var e = new ParseException(_parseReason, _message, _innerException);
            Assert.AreEqual(_message, e.Message);
            Assert.AreSame(_innerException, e.InnerException);
            Assert.AreEqual(_parseReason, e.Reason);
        }
    }
}
