// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class ExceptionsTest
    {
        private const string Message = "message";
        private const LoginException.FailureReason LoginReason = LoginException.FailureReason.Unknown;
        private readonly Exception InnerException = new Exception();

        [Test]
        public void BaseException_with_message()
        {
            var e = new BaseException(Message);
            Assert.AreEqual(Message, e.Message);
            Assert.IsNull(e.InnerException);
        }

        [Test]
        public void BaseException_with_message_and_inner_exception()
        {
            var e = new BaseException(Message, InnerException);
            Assert.AreEqual(Message, e.Message);
            Assert.AreSame(InnerException, e.InnerException);
        }

        [Test]
        public void LoginException_with_message()
        {
            var e = new LoginException(LoginReason, Message);
            Assert.AreEqual(Message, e.Message);
            Assert.IsNull(e.InnerException);
            Assert.AreEqual(LoginReason, e.Reason);
        }

        [Test]
        public void LoginException_with_message_and_inner_exception()
        {
            var e = new LoginException(LoginReason, Message, InnerException);
            Assert.AreEqual(Message, e.Message);
            Assert.AreSame(InnerException, e.InnerException);
            Assert.AreEqual(LoginReason, e.Reason);
        }
    }
}
