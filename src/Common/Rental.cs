// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Buffers;

namespace PasswordManagerAccess.Common
{
    internal readonly struct Rental: IDisposable
    {
        public byte[] Buffer { get; }

        public static Rental Rent(int size) => new Rental(ArrayPool<byte>.Shared.Rent(size));
        public static implicit operator byte[](Rental r) => r.Buffer;
        public static implicit operator ReadOnlySpan<byte>(Rental r) => r.Buffer.AsRoSpan();

        public static T With<T>(int size, Func<byte[], T> f)
        {
            using var rental = Rent(size);
            return f(rental);
        }

        public static void With(int size, Action<byte[]> f)
        {
            using var rental = Rent(size);
            f(rental);
        }

        public void Dispose()
        {
            ArrayPool<byte>.Shared.Return(Buffer);
        }

        private Rental(byte[] buffer)
        {
            Buffer = buffer;
        }
    }
}
