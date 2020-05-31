// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.StickyPassword;
using PasswordManagerAccess.StickyPassword.Ui;
using SQLitePCL;

namespace PasswordManagerAccess.Example.StickyPassword
{
    internal class TextUi: IUi
    {
        private const string ToCancel = "or just press ENTER to cancel";

        public Passcode ProvideEmailPasscode()
        {
            var passcode = GetAnswer($"Enter one-time PIN sent to your email address, 'r' to resend {ToCancel}");
            switch (passcode)
            {
            case "":
                return Passcode.Cancel;
            case "r":
            case "R":
                return Passcode.Resend;
            default:
                return new Passcode(passcode);
            }
        }

        private static string GetAnswer(string prompt)
        {
            Console.WriteLine(prompt);
            Console.Write("> ");
            var input = Console.ReadLine();

            return input == null ? "" : input.Trim();
        }
    }

    internal class SqliteProvider : ISqliteProvider
    {
        private string _filename = "";
        private sqlite3 _handle = null;

        public void Open(byte[] db)
        {
            Batteries_V2.Init();

            // Save the bytes to disk, since SQLite cannot open memory blobs, it has to be a file.
            try
            {
                _filename = Path.GetTempFileName();
                File.WriteAllBytes(_filename, db);
            }
            // We're not handling the system errors here. It's way too many of them. Catching all the exceptions
            // doesn't make sense. When any of those exceptions is thrown it means something is wrong with the
            // system, it's not our error. In general catching Exception is not a good practice, but in this case
            // it's just too much trouble.
            catch (Exception e)
            {
                throw new SqliteProviderError($"Failed to save the database to a file '{_filename}'", e);
            }

            // Open the db
            var openResultCode = raw.sqlite3_open_v2(_filename, out _handle, raw.SQLITE_OPEN_READONLY, null);
            if (openResultCode != raw.SQLITE_OK)
            {
                var message = raw.sqlite3_errstr(openResultCode).utf8_to_string();
                throw new SqliteProviderError($"Failed to open the database: '{message}'");
            }
        }

        public void Close()
        {
            // Close the db
            if (_handle != null)
            {
                raw.sqlite3_close_v2(_handle);
                _handle = null;
            }

            // Delete the file
            try
            {
                File.Delete(_filename);
            }
            catch
            {
                // Ignore errors
            }
            finally
            {
                _filename = "";
            }
        }

        public IEnumerable<object[]> Query(string sql)
        {
            sqlite3_stmt statement;
            if (raw.sqlite3_prepare_v2(_handle, sql, out statement) != raw.SQLITE_OK)
                throw new SqliteProviderError("Failed to prepare the query statement");

            try
            {
                var row = new List<object>();
                while (true)
                {
                    var result = raw.sqlite3_step(statement);
                    if (result == raw.SQLITE_DONE)
                        break;

                    if (result != raw.SQLITE_ROW)
                        throw new SqliteProviderError("Failed to query the database");

                    row.Clear();

                    var n = raw.sqlite3_column_count(statement);
                    for (var i = 0; i < n; i++)
                    {
                        switch (raw.sqlite3_column_type(statement, i))
                        {
                        case raw.SQLITE_INTEGER:
                            row.Add(raw.sqlite3_column_int64(statement, i));
                            break;
                        case raw.SQLITE_FLOAT:
                            row.Add(raw.sqlite3_column_double(statement, i));
                            break;
                        case raw.SQLITE_TEXT:
                            row.Add(raw.sqlite3_column_text(statement, i).utf8_to_string());
                            break;
                        case raw.SQLITE_BLOB:
                            row.Add(raw.sqlite3_column_blob(statement, i).ToArray());
                            break;
                        case raw.SQLITE_NULL:
                            row.Add(null);
                            break;
                        default:
                            throw new SqliteProviderError("Failed to query the database");
                        }
                    }

                    yield return row.ToArray();
                }
            }
            finally
            {
                raw.sqlite3_finalize(statement);
            }
        }
    }

    public static class Program
    {
        static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            var deviceId = config.ContainsKey("device-id")
                ? config["device-id"]
                : null;

            if (deviceId == null)
            {
                deviceId = Vault.GenerateRandomDeviceId();
                Console.WriteLine("A new unique ID is generated for this device: {0}", deviceId);
                Console.WriteLine("Please save this ID and reuse on subsequent calls from this device");
            }

            var deviceName = config.ContainsKey("device-name")
                ? config["device-name"]
                : "password-manager-access-stickypassword-example";

            try
            {
                var vault = Vault.Open(config["username"],
                                       config["password"],
                                       deviceId,
                                       deviceName,
                                       new TextUi(),
                                       new SqliteProvider());

                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var a = vault.Accounts[i];
                    Console.WriteLine("{0}: {1} {2} {3} {4}",
                                      i + 1,
                                      a.Id,
                                      a.Name,
                                      a.Url,
                                      a.Notes);

                    for (var j = 0; j < a.Credentials.Length; ++j)
                    {
                        var c = a.Credentials[j];
                        Console.WriteLine("  - {0}: {1}:{2} ({3})",
                                          j + 1,
                                          c.Username,
                                          c.Password,
                                          c.Description);
                    }
                }
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
