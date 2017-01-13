// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;

namespace StickyPassword
{
    public static class Parser
    {
        public static void OpenDb(byte[] db)
        {
            var filename = Path.GetTempFileName();
            try
            {
                File.WriteAllBytes(filename, db);
                OpenDb(filename);
            }
            finally
            {
                File.Delete(filename);
            }
        }

        public static void OpenDb(string filename)
        {
            using (var db = new SQLiteConnection(string.Format("Data Source={0};Version=3;", filename)))
            {
                db.Open();
                var user = GetDefaultUser(db);
            }
        }

        //
        // Private
        //

        private struct User
        {
            public User(long id, byte[] salt, byte[] verification): this()
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
            var r = Sql(db,
                "select USER_ID, KEY, PASSWORD " +
                    "from USER " +
                    "where DATE_DELETED = 1 " +
                        "and USERNAME = x'640065006600610075006c0074000000'");

            return new User(id: (long)r[0]["USER_ID"],
                            salt: (byte[])r[0]["KEY"],
                            verification: (byte[])r[0]["PASSWORD"]);
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
