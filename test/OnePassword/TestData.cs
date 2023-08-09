// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;

namespace PasswordManagerAccess.Test.OnePassword
{
    internal class TestData
    {
        public const string Username = "username";
        public const string Password = "password";
        public const string AccountKey = "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9";
        public const string DeviceUuid = "rz64r4uhyvgew672nm4ncaqonq";
        public const string Domain = "my.1password.com";
        public const string DeviceName = "device-name";
        public const string DeviceModel = "device-model";

        public static readonly Credentials Credentials = new Credentials
        {
            Username = Username,
            Password = Password,
            AccountKey = AccountKey,
            Domain = Domain,
            DeviceUuid = DeviceUuid,
       };

        public static readonly DeviceInfo DeviceInfo = new DeviceInfo
        {
            Name = DeviceName,
            Model = DeviceModel,
        };

        public const string SessionId = "TOZVTFIFBZGFDFNE5KSZFY7EZY";

        public static readonly SrpInfo SrpInfo = new SrpInfo(srpMethod: "SRPg-4096",
                                                             keyMethod: "PBES2g-HS256",
                                                             iterations: 100000,
                                                             salt: "-JLqTVQLjQg08LWZ0gyuUA".Decode64Loose());

        public static readonly byte[] SessionKeyBytes =
            "1c45a129b9e96b2f2eae330e8fd3c2dbb9dbe71b696d19823f3fa031b3218aad".DecodeHex();

        public static readonly AesKey SessionKey = new AesKey(SessionId, SessionKeyBytes);
    }
}
