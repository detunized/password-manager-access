// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    class ExceptionsTest
    {
        [Test]
        public void BaseException_properties_are_set()
        {
            VerifyException(new BaseException(Message, InnerException));
        }

        [Test]
        public void CryptoException_properties_are_set()
        {
            VerifyException(new CryptoException(Message, InnerException));
        }

        [Test]
        public void JTokenAccessException_properties_are_set()
        {
            VerifyException(new JTokenAccessException(Message, InnerException));
        }

        //
        // Data
        //

        private const string Message = "message";
        private static readonly Exception InnerException = new Exception();

        //
        // Helpers
        //

        private static void VerifyException(BaseException e)
        {
            Assert.That(e.Message, Is.EqualTo(Message));
            Assert.That(e.InnerException, Is.SameAs(InnerException));
        }
    }
}
