// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;
using NUnit.Framework.Constraints;

namespace OPVault.Test
{
    [TestFixture]
    public class ExceptionsTest
    {
        [Test]
        public void JTokenAccessException_properties_are_set()
        {
            VerifyException(new JTokenAccessException(Message, InnerException));
        }

        [Test]
        public void ParseException_properties_are_set()
        {
            var reason = ParseException.FailureReason.UnknownError;
            var e = new ParseException(reason, Message, InnerException);

            VerifyException(e);
            Assert.That(e.Reason, Is.EqualTo(reason));
        }

        //
        // Data
        //

        private const string Message = "message";
        private static readonly Exception InnerException = new Exception();

        //
        // Helpers
        //

        public static Constraint ThrowsInvalidFormatWithMessage(string message)
        {
            return ThrowsReasonWithMessage(ParseException.FailureReason.InvalidFormat, message);
        }

        public static Constraint ThrowsCorruptedWithMessage(string message)
        {
            return ThrowsReasonWithMessage(ParseException.FailureReason.Corrupted, message);
        }

        public static Constraint ThrowsReasonWithMessage(ParseException.FailureReason reason, string message)
        {
            return Throws.TypeOf<ParseException>()
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
