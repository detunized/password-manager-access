// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;

namespace PasswordManagerAccess.Common
{
    /// It's guaranteed that all the methods are called in the following sequence:
    ///
    ///   1. Open (only once)
    ///   2. Query (zero or more times, only when Open was successful)
    ///   3. Close (only once)
    ///
    /// The sequence is only executed once. The implementation doesn't have to worry about the library trying to open
    /// multiple databases through the same provider object. The sequence is terminated if Open or any of the Query
    /// methods fail (Close is always called).
    ///
    /// Every method must throw SqliteProviderError on any error, otherwise all the methods are expected to succeed.
    public interface ISqliteProvider
    {
        /// The `db` contains the SQLite database bytes received from the server. Since there's no way to validate the
        /// database, the implementation should expect the possibility of the database being invalid or corrupted.
        void Open(byte[] db);

        /// Close is guaranteed to be always called and only once.
        void Close();

        /// Returns rows as arrays of objects in the order returned by the SQLite. Allowed types are:
        ///   - null (SQLITE_NULL)
        ///   - long (SQLITE_INTEGER)
        ///   - double (SQLITE_FLOAT)
        ///   - string (SQLITE_TEXT)
        ///   - byte[] (SQLITE_BLOB)
        /// No other types are allowed and if seen an exception will be thrown.
        IEnumerable<object[]> Query(string sql);
    }
}

namespace PasswordManagerAccess.StickyPassword
{
    /// The only exception type expected to be thrown by the implementation of ISqliteProvider.
    public class SqliteProviderError : Exception
    {
        public SqliteProviderError(string message, Exception innerException = null)
            : base(message, innerException) { }
    }
}
