// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OnePassword.Test
{
    internal class TestData
    {
        public const string SessionId = "TOZVTFIFBZGFDFNE5KSZFY7EZY";

        public static Session MakeSession(string id = SessionId)
        {
            return new Session(id: id,
                               keyFormat: "A3",
                               keyUuid: "FRN8GF",
                               srpMethod: "SRPg-4096",
                               keyMethod: "PBES2g-HS256",
                               iterations: 100000,
                               salt: "-JLqTVQLjQg08LWZ0gyuUA".Decode64());
        }
    }
}
