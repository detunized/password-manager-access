// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace OnePassword
{
    internal class AccountKey
    {
        public readonly string Format;
        public readonly string Uuid;
        public readonly string Key;

        public static AccountKey Parse(string str)
        {
            var s = str.ToUpperInvariant().Replace("-", "");
            if (s.Length < 2)
                throw ExceptionFactory.MakeInvalidOperation("Invalid account key: too short");

            var format = s.Substring(0, 2);
            switch (format)
            {
            case "A2":
                if (s.Length != 33)
                    throw ExceptionFactory.MakeInvalidOperation(
                        "Invalid account key: incorrect length for 'A2' format");
                break;
            case "A3":
                if (s.Length != 34)
                    throw ExceptionFactory.MakeInvalidOperation(
                        "Invalid account key: incorrect length for 'A3' format");
                break;
            default:
                throw ExceptionFactory.MakeInvalidOperation(
                    string.Format("Invalid account key: unknown format '{0}'", format));
            }

            return new AccountKey(format: format,
                                  uuid: s.Substring(2, 6),
                                  key: s.Substring(8));
        }

        public AccountKey(string format, string uuid, string key)
        {
            Format = format;
            Uuid = uuid;
            Key = key;
        }

        public byte[] Hash()
        {
            return Crypto.Hkdf(method: Format,
                               ikm: Key.ToBytes(),
                               salt: Uuid.ToBytes());
        }

        public byte[] CombineWith(byte[] bytes)
        {
            var h = Hash();
            if (h.Length != bytes.Length)
                throw ExceptionFactory.MakeInvalidOperation("Size doesn't match hash function");

            for (int i = 0; i < h.Length; ++i)
                h[i] ^= bytes[i];

            return h;
        }
    }
}
