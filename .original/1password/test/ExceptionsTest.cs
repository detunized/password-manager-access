// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;
using NUnit.Framework.Constraints;

namespace OnePassword.Test
{
    [TestFixture]
    public class ExceptionsTest
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

        [Test]
        public void ClientException_properties_are_set()
        {
            var e = new ClientException(ClientException.FailureReason.UnknownError,
                                        Message,
                                        InnerException);
            VerifyException(e);
            Assert.That(e.Reason, Is.EqualTo(ClientException.FailureReason.UnknownError));
        }

        //
        // Data
        //

        private const string Message = "message";
        private static readonly Exception InnerException = new Exception();

        //
        // Helpers
        //

        public static Constraint ThrowsInvalidResponseWithMessage(string message)
        {
            return ThrowsReasonWithMessage(ClientException.FailureReason.InvalidResponse, message);
        }

        public static Constraint ThrowsRespondedWithErrorWithMessage(string message)
        {
            return ThrowsReasonWithMessage(ClientException.FailureReason.RespondedWithError, message);
        }

        public static Constraint ThrowsUnsupportedFeatureWithMessage(string message)
        {
            return ThrowsReasonWithMessage(ClientException.FailureReason.UnsupportedFeature, message);
        }

        public static Constraint ThrowsInvalidOpeationWithMessage(string message)
        {
            return ThrowsReasonWithMessage(ClientException.FailureReason.InvalidOperation, message);
        }

        public static Constraint ThrowsReasonWithMessage(ClientException.FailureReason reason, string message)
        {
            return Throws.TypeOf<ClientException>()
                .And.Property("Reason").EqualTo(reason)
                .And.Message.Contains(message);
        }

        private static void VerifyException(BaseException e)
        {
            Assert.That(e.Message, Is.EqualTo(Message));
            Assert.That(e.InnerException, Is.SameAs(InnerException));
        }
    }
}
