// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace OnePassword
{
    internal class Keychain
    {
        public void Add(AesKey key)
        {
            _aes.Add(key.Id, key);
        }

        private Dictionary<string, AesKey> _aes = new Dictionary<string, AesKey>();
    }
}
