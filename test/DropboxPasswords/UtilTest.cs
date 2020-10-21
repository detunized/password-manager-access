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
            Assert.Equal(Util.WordListEn,
                         Util.WordListEn.OrderBy(x => x).ToArray());
        }

        [Fact]
        public void RecoveryWordsToMasterKey_returns_key()
        {
            var key = Util.RecoveryWordsToMasterKey(RecoveryWords);
            Assert.Equal("5aff62570a3a60754f72a563bdd5a35e".DecodeHex(), key);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(11)]
        [InlineData(13)]
        public void RecoveryWordsToMasterKey_throws_on_invalid_number_of_words(int size)
        {
            Exceptions.AssertThrowsInternalError(() => Util.RecoveryWordsToMasterKey(new string[size]),
                                                 "Exactly 12 recovery words must be provided");
        }

        [Fact]
        public void RecoveryWordsToMasterKey_throws_on_invalid_word()
        {
            var words = RecoveryWords.Take(11).Append("blah-blah").ToArray();
            Exceptions.AssertThrowsInternalError(() => Util.RecoveryWordsToMasterKey(words),
                                                 "Recovery word 'blah-blah' is invalid");
        }

        //
        // Data
        //

        internal static readonly string[] RecoveryWords =
        {
            "foot", "wild", "noise", "behave", "plastic", "deny",
            "differ", "feed", "glove", "upgrade", "hand", "rotate",
        };
    }
}
