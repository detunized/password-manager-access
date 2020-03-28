// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using System.Linq;
using System.Text;
using PasswordManagerAccess.Common;
using SQLite;

namespace PasswordManagerAccess.StickyPassword
{
    internal static class Parser
    {
        // This function saves the database to a temporary file (since System.Data.SQLite
        // cannot handle in memory databases) and parses it, extracts all the account
        // information and decrypts the encrypted fields.
        public static Account[] ParseAccounts(byte[] db, string password)
        {
            // We're not handling the system errors here. It's way too many of them,
            // catching all the exceptions doesn't make sense. When any of those
            // exceptions is thrown it means something is wrong with the system,
            // it's not our error.
            var filename = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(filename, db);
                return ParseAccounts(filename, password);
            }
            finally
            {
                File.Delete(filename);
            }
        }

        //
        // Internal (accessed by the tests)
        //

        internal static Account[] ParseAccounts(string filename, string password)
        {
            try
            {
                using var db = new SQLiteConnection(filename, SQLiteOpenFlags.ReadOnly);

                var user = GetDefaultUser(db);
                var key = Util.DeriveDbKey(password, user.Salt);
                if (!IsKeyCorrect(key, user.Verification))
                    throw new ParseException(ParseException.FailureReason.IncorrectPassword,
                                             "Password verification failed");

                return GetAccounts(db, user, key);
            }
            catch (SQLiteException e)
            {
                throw new ParseException(ParseException.FailureReason.SqliteError,
                                         "Failed to parse the database",
                                         e);
            }
        }

        internal static bool IsKeyCorrect(byte[] key, byte[] verification)
        {
            var test = Util.Encrypt("VERIFY".ToBytes(), key);
            return test.SequenceEqual(verification);
        }

        //
        // Private
        //

        private static Db.User GetDefaultUser(SQLiteConnection db)
        {
            // "6400..." is "default\0" in UTF-16
            var r = db.Query<Db.User>(
                "select USER_ID, KEY, PASSWORD " +
                "from USER " +
                "where DATE_DELETED = 1 and USERNAME = x'640065006600610075006c0074000000'");

            return r[0];
        }

        private static Account[] GetAccounts(SQLiteConnection db, Db.User user, byte[] key)
        {
            var r = db.Query<Db.Entry>(
                "select ENTRY_ID, UDC_ENTRY_NAME, UDC_URL, UD_COMMENT " +
                "from ACC_ACCOUNT " +
                "where DATE_DELETED = 1 and USER_ID = ? and GROUP_TYPE = 2 " +
                "order by ENTRY_ID",
                user.Id);

            return r.Select(i => new Account(id: i.Id,
                                             name: DecryptTextField(i.Name, key),
                                             url: DecryptTextField(i.Url, key),
                                             notes: DecryptTextField(i.Comment, key),
                                             credentials: GetCredentialsForAccount(db, user, i.Id, key))).ToArray();
        }

        private static Credentials[] GetCredentialsForAccount(SQLiteConnection db,
                                                              Db.User user,
                                                              long accountId,
                                                              byte[] key)
        {
            var r = db.Query<Db.Credentials>(
                "select LOG.UDC_USERNAME, LOG.UD_PASSWORD, LOG.UDC_DESCRIPTION " +
                "from ACC_LOGIN LOG, ACC_LINK LINK " +
                "where LINK.DATE_DELETED = 1 and LINK.USER_ID = ? and LINK.ENTRY_ID = ? and LOG.LOGIN_ID = LINK.LOGIN_ID " +
                "order by LINK.LOGIN_ID",
                user.Id,
                accountId);

            return r.Select(i => new Credentials(username: DecryptTextField(i.Username, key),
                                                 password: DecryptTextField(i.Password, key),
                                                 description: DecryptTextField(i.Description, key))).ToArray();
        }

        private static string DecryptTextField(byte[] encrypted, byte[] key)
        {
            var bytes = Util.Decrypt(encrypted, key);
            return Encoding.Unicode.GetString(bytes).TrimEnd('\0');
        }
    }

    // Database models
    internal static class Db
    {
        public class User
        {
            [Column("USER_ID")]
            public long Id { get; set; }

            [Column("KEY")]
            public byte[] Salt { get; set; }

            [Column("PASSWORD")]
            public byte[] Verification { get; set; }
        }

        public class Entry
        {
            [Column("ENTRY_ID")]
            public long Id { get; set; }
            [Column("UDC_ENTRY_NAME")]
            public byte[] Name { get; set; }
            [Column("UDC_URL")]
            public byte[] Url { get; set; }
            [Column("UD_COMMENT")]
            public byte[] Comment { get; set; }
        }

        public class Credentials
        {
            [Column("UDC_USERNAME")]
            public byte[] Username { get; set; }
            [Column("UD_PASSWORD")]
            public byte[] Password { get; set; }
            [Column("UDC_DESCRIPTION")]
            public byte[] Description { get; set; }
        }
    }
}
