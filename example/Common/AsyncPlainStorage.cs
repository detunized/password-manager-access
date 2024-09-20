// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Example.Common
{
    public class AsyncPlainStorage : IAsyncSecureStorage
    {
        public AsyncPlainStorage()
            : this(new PlainStorage()) { }

        public AsyncPlainStorage(string filename)
            : this(new PlainStorage(filename)) { }

        public Task<string> LoadString(string name)
        {
            return Task.FromResult(_plainStorage.LoadString(name));
        }

        public Task StoreString(string name, string value)
        {
            _plainStorage.StoreString(name, value);
            return Task.CompletedTask;
        }

        //
        // Private
        //

        private AsyncPlainStorage(PlainStorage plainStorage)
        {
            _plainStorage = plainStorage;
        }

        private readonly PlainStorage _plainStorage;
    }
}
