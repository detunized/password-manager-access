// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class Poly1305Test
    {
        [Theory]
        [MemberData(nameof(Poly1305TestCases))]
        public void Poly1305_computes_tag(CryptoTestVectors.Poly1305TestVector v)
        {
            // TODO: We do not support arbitrary input length
            if (v.Input.Length % Poly1305.BlockSize != 0)
                return;

            var poly1305 = new Poly1305(v.Key);
            poly1305.Update(v.Input);

            // Span<byte[]> mac = stackalloc byte[16];
            // poly1305.Finish(mac);
        }

        public static IEnumerable<object[]> Poly1305TestCases = TestBase.ToMemberData(CryptoTestVectors.Poly1305TestVectors);
    }
}
