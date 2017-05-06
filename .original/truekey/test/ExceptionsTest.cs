// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace TrueKey.Test
{
    [TestFixture]
    class ExceptionsTest
    {
        [Test]
        public void BaseException_with_message()
        {
            VerifyExceptionMessage(new BaseException(Message));
        }

        [Test]
        public void BaseException_with_message_and_inner_exception()
        {
            VerifyExceptionMessageAndInner(new BaseException(Message, InnerException));
        }

        [Test]
        public void CryptoException_with_message()
        {
            VerifyExceptionMessage(new CryptoException(Message));
        }

        [Test]
        public void CryptoException_with_message_and_inner_exception()
        {
            VerifyExceptionMessageAndInner(new BaseException(Message, InnerException));
        }

        [Test]
        public void FetchException_with_message()
        {
            var e = new FetchException(FetchReason, Message);

            VerifyExceptionMessage(e);
            Assert.That(e.Reason, Is.EqualTo(FetchReason));
        }

        [Test]
        public void FetchException_with_message_and_inner_exception()
        {
            var e = new FetchException(FetchReason, Message, InnerException);

            VerifyExceptionMessageAndInner(e);
            Assert.That(e.Reason, Is.EqualTo(FetchReason));
        }

        //
        // Data
        //

        private const string Message = "message";
        private static readonly Exception InnerException = new Exception();

        private const FetchException.FailureReason FetchReason =
            FetchException.FailureReason.UnknownError;

        //
        // Helpers
        //

        private void VerifyExceptionMessage(BaseException e)
        {
            Assert.That(e.Message, Is.EqualTo(Message));
            Assert.That(e.InnerException, Is.Null);
        }

        private void VerifyExceptionMessageAndInner(BaseException e)
        {
            Assert.That(e.Message, Is.EqualTo(Message));
            Assert.That(e.InnerException, Is.SameAs(InnerException));
        }
    }
}
