// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.DropboxPasswords;
using Xunit;

namespace PasswordManagerAccess.Test.DropboxPasswords
{
    public class UtilTest
    {
        [Fact]
        public void WordListEn_has_2048_words()
        {
            Assert.Equal(2048, Util.WordListEn.Length);
        }

        [Fact]
        public void WordListEn_is_sorted()
        {
            Assert.Equal(Util.WordListEn, Util.WordListEn.OrderBy(x => x).ToArray());
        }

        [Fact]
        public void DeriveMasterKeyFromRecoveryWords_returns_master_key()
        {
            var key = Util.DeriveMasterKeyFromRecoveryWords(RecoveryWords);

            Assert.Equal(MasterKey, key);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(11)]
        [InlineData(13)]
        public void DeriveMasterKeyFromRecoveryWords_throws_on_invalid_number_of_words(int size)
        {
            Exceptions.AssertThrowsInternalError(
                () => Util.DeriveMasterKeyFromRecoveryWords(new string[size]),
                "Exactly 12 recovery words must be provided"
            );
        }

        [Fact]
        public void DeriveMasterKeyFromRecoveryWords_throws_on_invalid_word()
        {
            var words = RecoveryWords.Take(11).Append("blah-blah").ToArray();

            Exceptions.AssertThrowsInternalError(() => Util.DeriveMasterKeyFromRecoveryWords(words), "Recovery word 'blah-blah' is invalid");
        }

        [Fact]
        public void ConvertMasterKeyToEncryptionKey_returns_keyset_encryption_key()
        {
            var key = Util.ConvertMasterKeyToEncryptionKey(MasterKey);

            Assert.Equal(KeysetEncryptionKey, key);
        }

        [Fact]
        public void CalculateChecksum_returns_checksum()
        {
            var checksum = Util.CalculateChecksum(MasterKey);

            Assert.Equal(1, checksum);
        }

        //
        // Data
        //

        internal static readonly string[] RecoveryWords =
        {
            "foot",
            "wild",
            "noise",
            "behave",
            "plastic",
            "deny",
            "differ",
            "feed",
            "glove",
            "upgrade",
            "hand",
            "rotate",
        };

        internal static readonly byte[] MasterKey = "5aff62570a3a60754f72a563bdd5a35e".DecodeHex();
        internal static readonly byte[] KeysetEncryptionKey = "4a0a046a2d4e2ee312c550a54fe96b573133e0d5b34f09b985c2b02876b98e6f".DecodeHex();
    }
}
