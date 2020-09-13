// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Kdbx;
using Xunit;

namespace PasswordManagerAccess.Test.Kdbx
{
    public class BlockStreamTest: TestBase
    {
        // TODO: We need test data with multiple block. At the moment it's quite difficult since
        //       the KeepPass clients generate files with 1MB blocks. We need to hack the program
        //       to generate much smaller blocks.
        [Fact]
        public void All_bytes_are_read_with_ReadAll()
        {
            using var ms = new MemoryStream(GetBinaryFixture("kdbx4-aes-aes", "kdbx"), writable: false);
            ms.Seek(271, SeekOrigin.Begin); // Skip header

            using var s = new BlockStream(ms, AesAesHmacKey.DecodeHex());
            var bytes = s.ReadAll();

            Assert.Equal(2112, bytes.Length);
        }

        //
        // Data
        //

        internal const string AesAesHmacKey = "b7091bd40ed02eb88585811747435c4ab2d68c3d355773da5f923bbe094bfa5c" +
                                              "fa29fef53e43c0df65fb99b061ffb63619745f0ca472a39bd47fc017ce352d4d";
    }
}
