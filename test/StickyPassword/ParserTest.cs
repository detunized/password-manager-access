// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.IO;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.StickyPassword;
using Xunit;

namespace PasswordManagerAccess.Test.StickyPassword
{
    public class ParserTest
    {
        [Fact]
        public void ParseAccounts_returns_accounts()
        {
            var accounts = Parser.ParseAccounts(Db, Password, new DbProvider());

            Assert.NotEmpty(accounts);
            var a = accounts[0];

            Assert.Equal("Google", a.Name);
            Assert.Equal("https://google.com", a.Url);
            Assert.Equal("Good search", a.Notes);

            Assert.NotEmpty(a.Credentials);
            var c = a.Credentials[0];

            Assert.Equal("larry", c.Username);
            Assert.Equal("page", c.Password);
            Assert.Equal("", c.Description);
        }

        [Fact]
        public void ParseAccounts_throws_on_incorrect_password()
        {
            Exceptions.AssertThrowsBadCredentials(
                () => Parser.ParseAccounts(Db, "incorrect password", new DbProvider()),
                "Password verification failed"
            );
        }

        [Fact]
        public void ParseAccounts_throws_on_corrupted_database()
        {
            Exceptions.AssertThrowsInternalError(
                () => Parser.ParseAccounts(CorruptedDb, Password, new CorruptedDbProvider()),
                "Failed to open the SQLite database"
            );
        }

        [Fact]
        public void IsKeyCorrect_returns_true()
        {
            var key = Util.DeriveDbKey(Password, KeySalt);

            Assert.True(Parser.IsKeyCorrect(key, KeyVerification));
        }

        [Fact]
        public void IsKeyCorrect_return_false()
        {
            var key = Util.DeriveDbKey("Incorrect password", KeySalt);

            Assert.False(Parser.IsKeyCorrect(key, KeyVerification));
        }

        private class DbProvider : ISqliteProvider
        {
            public void Open(byte[] db)
            {
                Assert.Equal(Db, db);
            }

            public void Close() { }

            public IEnumerable<object[]> Query(string sql)
            {
                if (sql.StartsWith("select USER_ID, KEY, PASSWORD "))
                {
                    return new[]
                    {
                        new object[] { 1L, "ab3034fb5d428bda9292325e809b6c08".DecodeHex(), "c36129e96a29beec51da4b82f51ef85a".DecodeHex() },
                    };
                }

                if (sql.StartsWith("select ENTRY_ID, UDC_ENTRY_NAME, UDC_URL, UD_COMMENT "))
                {
                    return new[]
                    {
                        new object[]
                        {
                            1L,
                            "3424b5bf783f64d8588eaa8a6385a618".DecodeHex(),
                            "9a63cbee55039ec38737d6c7e80419a1594fc6bd633d188fb890a0747f84797af9398aee79020dbfd69400ce937c6062".DecodeHex(),
                            "4b8a3f8b336ac65a14d3376b2fc2ef7069f4cf8eb888f075f029e33060a4238d".DecodeHex(),
                        },
                    };
                }

                if (sql.StartsWith("select LOG.UDC_USERNAME, LOG.UD_PASSWORD, LOG.UDC_DESCRIPTION "))
                {
                    return new[]
                    {
                        new object[]
                        {
                            "20f61ca1ff49a53948e46d363db67331".DecodeHex(),
                            "ff8f18d2b0ff9013302bfe4e75d88af7".DecodeHex(),
                            "b384d316134d7caf90535d97ec5411a5".DecodeHex(),
                        },
                    };
                }

                Assert.True(false);
                return null;
            }
        }

        private class CorruptedDbProvider : ISqliteProvider
        {
            public void Open(byte[] db)
            {
                throw new SqliteProviderError("Failed to open the database");
            }

            public void Close() { }

            public IEnumerable<object[]> Query(string sql)
            {
                return null;
            }
        }

        //
        // Data
        //

        private const string Password = "Password123";
        private const string FixtureDir = "StickyPassword/Fixtures/";

        // TODO: This stuff is not really needed anymore.
        private const string DbFilename = FixtureDir + "db.sqlite";
        private const string CorruptedDbFilename = FixtureDir + "corrupted.sqlite";
        private static readonly byte[] Db = File.ReadAllBytes(DbFilename);
        private static readonly byte[] CorruptedDb = "not an sqlite databate".ToBytes();

        // The actual bytes from the user database
        private static readonly byte[] KeySalt = { 0x63, 0x51, 0xee, 0x97, 0x8c, 0x6e, 0xe0, 0xd8, 0x1e, 0x66, 0xdf, 0x61, 0x90, 0x3a, 0x5a, 0x88 };

        // The actual bytes from the user database
        private static readonly byte[] KeyVerification =
        {
            0x08,
            0xbc,
            0x5a,
            0x27,
            0x4d,
            0x4b,
            0xd6,
            0x42,
            0x9e,
            0xf5,
            0x9b,
            0x95,
            0x4d,
            0xd1,
            0x2b,
            0xfd,
        };
    }
}
