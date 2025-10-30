// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading.Tasks;
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

        [Fact]
        public void Try_FromResultOf_returns_value_on_success()
        {
            var t = Try.FromResultOf(() => 42);

            Assert.True(t.IsValue);
            Assert.Equal(42, t.Value);
            Assert.Null(t.Error);
        }

        [Fact]
        public void Try_FromResultOf_returns_error_on_exception()
        {
            var expected = new TryTestException("test error");
            int ThrowException()
            {
                throw expected;
            }
            var t = Try.FromResultOf(ThrowException);

            Assert.True(t.IsError);
            Assert.Same(expected, t.Error);
        }

        [Fact]
        public async Task Try_FromResultOf_async_returns_value_on_success()
        {
            var t = await Try.FromResultOf(async () =>
            {
                await Task.Delay(1);
                return "success";
            });

            Assert.True(t.IsValue);
            Assert.Equal("success", t.Value);
            Assert.Null(t.Error);
        }

        [Fact]
        public async Task Try_FromResultOf_async_returns_error_on_exception()
        {
            var expected = new TryTestException("async error");
            var t = await Try.FromResultOf<string>(async () =>
            {
                await Task.Delay(1);
                throw expected;
            });

            Assert.True(t.IsError);
            Assert.Same(expected, t.Error);
        }

        [Fact]
        public async Task Try_FromResultOf_async_propagates_cancellation()
        {
            await Assert.ThrowsAsync<OperationCanceledException>(
                async () =>
                    await Try.FromResultOf<int>(async () =>
                    {
                        await Task.Delay(1);
                        throw new OperationCanceledException("canceled");
                    })
            );
        }

        [Fact]
        public void Try_FromResultOf_captures_different_exception_types()
        {
            // ArgumentException
            int Throw1() => throw new ArgumentException("arg error");
            var t1 = Try.FromResultOf(Throw1);
            Assert.IsType<ArgumentException>(t1.Error);

            // InvalidOperationException
            int Throw2() => throw new InvalidOperationException("invalid op");
            var t2 = Try.FromResultOf(Throw2);
            Assert.IsType<InvalidOperationException>(t2.Error);

            // Custom exception
            int Throw3() => throw new TryTestException("custom");
            var t3 = Try.FromResultOf(Throw3);
            Assert.IsType<TryTestException>(t3.Error);
        }

        [Fact]
        public async Task Try_FromResultOf_async_captures_different_exception_types()
        {
            // ArgumentException
            var t1 = await Try.FromResultOf<int>(async () =>
            {
                await Task.Delay(1);
                throw new ArgumentException("arg error");
            });
            Assert.IsType<ArgumentException>(t1.Error);

            // InvalidOperationException
            var t2 = await Try.FromResultOf<int>(async () =>
            {
                await Task.Delay(1);
                throw new InvalidOperationException("invalid op");
            });
            Assert.IsType<InvalidOperationException>(t2.Error);

            // Custom exception
            var t3 = await Try.FromResultOf<int>(async () =>
            {
                await Task.Delay(1);
                throw new TryTestException("custom");
            });
            Assert.IsType<TryTestException>(t3.Error);
        }

        [Fact]
        public void Try_FromResultOf_handles_null_return_value()
        {
            var t = Try.FromResultOf(() => (string)null);

            Assert.True(t.IsValue);
            Assert.Null(t.Value);
            Assert.Null(t.Error);
        }

        [Fact]
        public async Task Try_FromResultOf_async_handles_null_return_value()
        {
            var t = await Try.FromResultOf(async () =>
            {
                await Task.Delay(1);
                return (string)null;
            });

            Assert.True(t.IsValue);
            Assert.Null(t.Value);
            Assert.Null(t.Error);
        }

        [Fact]
        public void TryT_ValueOrNull_returns_value_when_is_value()
        {
            var t = new Try<int>(42);

            Assert.Equal(42, t.ValueOrNull);
        }

        [Fact]
        public void TryT_ValueOrNull_returns_default_when_is_error()
        {
            var e = new TryTestException("error");
            var t = new Try<int>(e);

            Assert.Equal(0, t.ValueOrNull);
        }

        [Fact]
        public void TryT_ValueOrNull_returns_null_for_reference_type_when_is_error()
        {
            var e = new TryTestException("error");
            var t = new Try<string>(e);

            Assert.Null(t.ValueOrNull);
        }

        [Fact]
        public void TryT_ValueOrNull_returns_null_for_nullable_value_type_when_is_error()
        {
            var e = new TryTestException("error");
            var t = new Try<int?>(e);

            Assert.Null(t.ValueOrNull);
        }

        [Fact]
        public void TryT_ValueOrNull_returns_null_value_when_is_value()
        {
            var t = new Try<string>((string)null);

            Assert.Null(t.ValueOrNull);
        }

        [Fact]
        public void TryT_ValueOrNull_vs_Value_difference()
        {
            var e = new TryTestException("error");
            var t = new Try<int>(e);

            // ValueOrNull returns default without throwing
            Assert.Equal(0, t.ValueOrNull);

            // Value throws when there's an error
            var thrown = Assert.Throws<TryTestException>(() => t.Value);
            Assert.Same(e, thrown);
        }
    }

    internal class TryTestException : Exception
    {
        public TryTestException(string message)
            : base(message) { }
    }
}
