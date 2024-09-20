// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.RoboForm;

namespace PasswordManagerAccess.Test.RoboForm
{
    internal static class TestData
    {
        public const string Username = "lastpass.ruby@gmail.com";
        public const string Password = "h74@aB$SCt9dTBQ3%rmAVN3oOmtGLt58Nix7!3z%vUO4Ni07rfjutHRbhJ9!SkOk";
        public const string DeviceId = "B57192ee77db5e5989c5ef7e091b119ea";
        public const string Nonce = "-DeHRrZjC8DZ_0e8RGsisg";

        public static readonly Client.Credentials Credentials = new Client.Credentials(Username, Password, DeviceId, Nonce);

        public const string EncodedAuthInfoHeader =
            "SibAuth sid=\"6Ag93Y02vihucO9IQl1fbg\",data=\"cj0tRGVIUnJaakM4RFpfMGU4UkdzaXNn"
            + "TTItdGpnZi02MG0tLUZCaExRMjZ0ZyxzPUErRnQ4VU02NzRPWk9PalVqWENkYnc9PSxpPTQwOTY=\"";

        public static readonly AuthInfo AuthInfo = new AuthInfo(
            sid: "6Ag93Y02vihucO9IQl1fbg",
            data: "r=-DeHRrZjC8DZ_0e8RGsisgM2-tjgf-60m--FBhLQ26tg,s=A+Ft8UM674OZOOjUjXCdbw==,i=4096",
            nonce: "-DeHRrZjC8DZ_0e8RGsisgM2-tjgf-60m--FBhLQ26tg",
            salt: "A+Ft8UM674OZOOjUjXCdbw==".Decode64(),
            iterationCount: 4096,
            isMd5: false
        );
    }
}
