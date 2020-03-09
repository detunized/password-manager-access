// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PasswordManagerAccess.StickyPassword
{
    // TODO: Write more tests
    public static class Parser
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
                using (var db = new SQLiteConnection($"Data Source={filename};Version=3;"))
                {
                    db.Open();

                    var user = GetDefaultUser(db);
                    var key = Util.DeriveDbKey(password, user.Salt);
                    if (!IsKeyCorrect(key, user.Verification))
                        throw new ParseException(ParseException.FailureReason.IncorrectPassword,
                                                 "Password verification failed");

                    return GetAccounts(db, user, key);
                }
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
            var test = Util.EncryptAes256("VERIFY".ToBytes(), key, PaddingMode.PKCS7);
            return test.SequenceEqual(verification);
        }

        //
        // Private
        //

        private struct User
        {
            public User(long id, byte[] salt, byte[] verification)
            {
                Id = id;
                Salt = salt;
                Verification = verification;
            }

            public readonly long Id;
            public readonly byte[] Salt;
            public readonly byte[] Verification;
        }

        private static User GetDefaultUser(SQLiteConnection db)
        {
            // "6400..." is "default\0" in UTF-16
            var r = Sql(db, "select USER_ID, KEY, PASSWORD " +
                            "from USER " +
                            "where DATE_DELETED = 1 " +
                                "and USERNAME = x'640065006600610075006c0074000000'");

            return new User(id: (long)r[0]["USER_ID"],
                            salt: (byte[])r[0]["KEY"],
                            verification: (byte[])r[0]["PASSWORD"]);
        }

        private static Account[] GetAccounts(SQLiteConnection db, User user, byte[] key)
        {
            var r = Sql(db,
                "select ENTRY_ID, UDC_ENTRY_NAME, UDC_URL, UD_COMMENT " +
                "from ACC_ACCOUNT " +
                "where DATE_DELETED = 1 " +
                    $"and USER_ID = {user.Id} " +
                    "and GROUP_TYPE = 2 " +
                "order by ENTRY_ID");

            return r.Select(i =>
            {
                var id = (long)i["ENTRY_ID"];
                return new Account(
                    id: id,
                    name: DecryptTextField(i["UDC_ENTRY_NAME"], key),
                    url: DecryptTextField(i["UDC_URL"], key),
                    notes: DecryptTextField(i["UD_COMMENT"], key),
                    credentials: GetCredentialsForAccount(db, user, id, key));
            }).ToArray();
        }

        private static Credentials[] GetCredentialsForAccount(SQLiteConnection db, User user, long accountId, byte[] key)
        {
            var r = Sql(db,
                "select LOG.UDC_USERNAME, LOG.UD_PASSWORD, LOG.UDC_DESCRIPTION " +
                    "from ACC_LOGIN LOG, ACC_LINK LINK " +
                    "where LINK.DATE_DELETED = 1 " +
                        $"and LINK.USER_ID = {user.Id} " +
                        $"and LINK.ENTRY_ID = {accountId} " +
                        "and LOG.LOGIN_ID = LINK.LOGIN_ID " +
                    "order by LINK.LOGIN_ID");

            return r.Select(i => new Credentials(
                username: DecryptTextField(i["UDC_USERNAME"], key),
                password: DecryptTextField(i["UD_PASSWORD"], key),
                description: DecryptTextField(i["UDC_DESCRIPTION"], key)
            )).ToArray();
        }

        private static string DecryptTextField(object encrypted, byte[] key)
        {
            var bytes = Util.DecryptAes256((byte[])encrypted, key, PaddingMode.PKCS7);
            return Encoding.Unicode.GetString(bytes).TrimEnd('\0');
        }

        private static Dictionary<string, object>[] Sql(SQLiteConnection db, string sql)
        {
            var result = new List<Dictionary<string, object>>();

            using (var s = new SQLiteCommand(sql, db))
            using (var r = s.ExecuteReader())
            {
                while (r.Read())
                {
                    var row = new Dictionary<string, object>();
                    for (var i = 0; i < r.FieldCount; ++i)
                        row[r.GetName(i)] = r.GetValue(i);

                    result.Add(row);
                }
            }

            return result.ToArray();
        }
    }
}
