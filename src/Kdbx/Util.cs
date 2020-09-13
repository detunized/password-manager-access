// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kdbx
{
    internal static class Util
    {
        internal static byte[] ComputeBlockHmacKey(byte[] hmacKey, ulong blockIndex)
        {
            if (hmacKey.Length != 64)
                throw new InternalErrorException("HMAC key must be 64 bytes long");

            var io = new OutputSpanStream(stackalloc byte[8 + 64]);
            io.WriteUInt64(blockIndex);
            io.WriteBytes(hmacKey);

            return Crypto.Sha512(io.Span);
        }
    }
}
