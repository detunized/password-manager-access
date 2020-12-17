// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class TryTest
    {
        [Fact]
        public void Try_FromValue_makes_try_with_value()
        {
            var t = Try.FromValue("blah");

            Assert.Equal("blah", t.Value);
        }

        [Fact]
        public void Try_FromError_makes_try_with_error()
        {
            var e = new Exception();
            var t = Try.FromError<int>(e);

            Assert.Same(e, t.Error);
        }

        [Fact]
        public void Try_FromError_with_message_makes_try_with_error()
        {
            var e = new Exception();
            var t = Try.FromError<int>("error", e);

            Assert.IsType<InternalErrorException>(t.Error);
            Assert.Same(e, t.Error.InnerException);
        }

        [Fact]
        public void TryT_FromValue_makes_try_with_value()
        {
            var t = Try<string>.FromValue("blah");

            Assert.Equal("blah", t.Value);
        }

        [Fact]
        public void TryT_FromError_makes_try_with_error()
        {
            var e = new Exception();
            var t = Try<int>.FromError(e);

            Assert.Same(e, t.Error);
        }

        [Fact]
        public void TryT_FromError_with_message_makes_try_with_error()
        {
            var e = new Exception();
            var t = Try<int>.FromError("error", e);

            Assert.IsType<InternalErrorException>(t.Error);
            Assert.Same(e, t.Error.InnerException);
        }

        [Fact]
        public void TryT_is_value()
        {
            var t = new Try<int>(1337);

            Assert.True(t.IsValue);
            Assert.False(t.IsError);
            Assert.Equal(1337, t.Value);
            Assert.Null(t.Error);
        }

        [Fact]
        public void TryT_is_error()
        {
            var e = new Exception();
            var t = new Try<int>(e);

            Assert.False(t.IsValue);
            Assert.True(t.IsError);
            Assert.Same(e, t.Error);
        }

        [Fact]
        public void TryT_Value_throws_on_error()
        {
            var e = new TryTestException("blah-blah");
            var t = new Try<int>(e);

            var thrown = Assert.Throws<TryTestException>(() => t.Value);
            Assert.Same(e, thrown);
        }
    }

    internal class TryTestException: Exception
    {
        public TryTestException(string message): base(message)
        {
        }
    }
}
