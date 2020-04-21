// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.TrueKey;
using Xunit;

namespace PasswordManagerAccess.Test.TrueKey
{
    public class ExceptionsTest
    {
        [Fact]
        public void BaseException_properties_are_set()
        {
            VerifyException(new BaseException(Message, InnerException));
        }

        [Fact]
        public void FetchException_properties_are_set()
        {
            VerifyExceptionWithReason(new FetchException(Reason, Message, InnerException));
        }

        //
        // Data
        //

        private const string Message = "message";
        private static readonly Exception InnerException = new Exception();

        private const FetchException.FailureReason Reason =
            FetchException.FailureReason.UnknownError;

        //
        // Helpers
        //

        private static void VerifyException(BaseException e)
        {
            Assert.Equal(Message, e.Message);
            Assert.Same(InnerException, e.InnerException);
        }

        private static void VerifyExceptionWithReason(BaseException e)
        {
            VerifyException(e);
            // TODO: Don't need this after migration
            //Assert.That(e, Has.Property("Reason").EqualTo(Reason));
        }
    }
}
