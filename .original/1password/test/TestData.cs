// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OnePassword.Test
{
    internal class TestData
    {
        public const string Username = "username";
        public const string Password = "password";
        public const string AccountKey = "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9";
        public const string Uuid = "rz64r4uhyvgew672nm4ncaqonq";
        public const string Domain = "my.1password.com";

        public static readonly ClientInfo ClientInfo = new ClientInfo(username: Username,
                                                                      password: Password,
                                                                      accountKey: AccountKey,
                                                                      uuid: Uuid,
                                                                      domain: Domain);

        public const string SessionId = "TOZVTFIFBZGFDFNE5KSZFY7EZY";
        public static readonly Session Session = MakeSession();

        public static readonly byte[] SessionKeyBytes =
            "1c45a129b9e96b2f2eae330e8fd3c2dbb9dbe71b696d19823f3fa031b3218aad".DecodeHex();

        public static readonly AesKey SesionKey = new AesKey(SessionId, SessionKeyBytes);

        public static Session MakeSession(string id = SessionId)
        {
            return new Session(id: id,
                               keyFormat: "A3",
                               keyUuid : "RTN9SA",
                               srpMethod: "SRPg-4096",
                               keyMethod: "PBES2g-HS256",
                               iterations: 100000,
                               salt: "-JLqTVQLjQg08LWZ0gyuUA".Decode64());
        }
    }
}
