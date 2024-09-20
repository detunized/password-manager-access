// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Text;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.StickyPassword
{
    internal static class Parser
    {
        public static Account[] ParseAccounts(byte[] db, string password, ISqliteProvider provider)
        {
            try
            {
                CallSqlProvider(() => provider.Open(db), "Failed to open the SQLite database");
                return ParseAccounts(password, provider);
            }
            finally
            {
                CallSqlProvider(provider.Close, "Failed to close the SQLite database");
            }
        }

        //
        // Internal (accessed by the tests)
        //

        internal static Account[] ParseAccounts(string password, ISqliteProvider provider)
        {
            try
            {
                var user = GetDefaultUser(provider);
                var key = Util.DeriveDbKey(password, user.Salt);

                if (!IsKeyCorrect(key, user.Verification))
                    throw new BadCredentialsException("Password verification failed");

                return GetAccounts(user, key, provider);
            }
            catch (SqliteProviderError e)
            {
                throw new InternalErrorException("SQL query failed", e);
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

        private class User
        {
            public long Id;
            public byte[] Salt;
            public byte[] Verification;
        }

        private static void CallSqlProvider(Action action, string errorMessage)
        {
            try
            {
                action();
            }
            catch (SqliteProviderError e)
            {
                throw new InternalErrorException(errorMessage, e);
            }
        }

        private static User GetDefaultUser(ISqliteProvider provider)
        {
            // "6400..." is "default\0" in UTF-16
            var result = provider.Query(
                // .....0........1....2.......
                "select USER_ID, KEY, PASSWORD " + "from USER " + "where DATE_DELETED = 1 and USERNAME = x'640065006600610075006c0074000000'"
            );

            foreach (var row in result)
            {
                return new User()
                {
                    Id = GetColumn<long>(row, 0),
                    Salt = GetColumn<byte[]>(row, 1),
                    Verification = GetColumn<byte[]>(row, 2),
                };
            }

            throw new InternalErrorException("No users found in the vault database");
        }

        private static Account[] GetAccounts(User user, byte[] key, ISqliteProvider provider)
        {
            var result = provider.Query(
                // .....0.........1...............2........3.........
                "select ENTRY_ID, UDC_ENTRY_NAME, UDC_URL, UD_COMMENT "
                    + "from ACC_ACCOUNT "
                    + $"where DATE_DELETED = 1 and USER_ID = {user.Id} and GROUP_TYPE = 2 "
                    + "order by ENTRY_ID"
            );

            return result
                .Select(row =>
                {
                    var id = GetColumn<long>(row, 0);
                    return new Account(
                        id: id,
                        name: DecryptTextField(GetColumn<byte[]>(row, 1), key),
                        url: DecryptTextField(GetColumn<byte[]>(row, 2), key),
                        notes: DecryptTextField(GetColumn<byte[]>(row, 3), key),
                        credentials: GetCredentialsForAccount(user, id, key, provider)
                    );
                })
                .ToArray();
        }

        private static Credentials[] GetCredentialsForAccount(User user, long accountId, byte[] key, ISqliteProvider provider)
        {
            var result = provider.Query(
                // .....0.................1................2..................
                "select LOG.UDC_USERNAME, LOG.UD_PASSWORD, LOG.UDC_DESCRIPTION "
                    + "from ACC_LOGIN LOG, ACC_LINK LINK "
                    + $"where LINK.DATE_DELETED = 1 and LINK.USER_ID = {user.Id} and "
                    + $"LINK.ENTRY_ID = {accountId} and LOG.LOGIN_ID = LINK.LOGIN_ID "
                    + "order by LINK.LOGIN_ID"
            );

            return result
                .Select(row => new Credentials(
                    username: DecryptTextField(GetColumn<byte[]>(row, 0), key),
                    password: DecryptTextField(GetColumn<byte[]>(row, 1), key),
                    description: DecryptTextField(GetColumn<byte[]>(row, 2), key)
                ))
                .ToArray();
        }

        private static T GetColumn<T>(object[] row, int index)
        {
            if (row[index] is T x)
                return x;

            throw new InternalErrorException($"Unexpected type in query response (expected {typeof(T)}, got {row[index].GetType()})");
        }

        private static string DecryptTextField(byte[] encrypted, byte[] key)
        {
            var bytes = Util.Decrypt(encrypted, key);
            return Encoding.Unicode.GetString(bytes).TrimEnd('\0');
        }
    }
}
