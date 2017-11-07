// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace RoboForm.Test
{
    internal static class TestData
    {
        public const string Username = "lastpass.ruby@gmail.com";
        public const string Password = "h74@aB$SCt9dTBQ3%rmAVN3oOmtGLt58Nix7!3z%vUO4Ni07rfjutHRbhJ9!SkOk";
        public const string Nonce = "-DeHRrZjC8DZ_0e8RGsisg";

        public static readonly Client.AuthInfo AuthInfo = new Client.AuthInfo(
            sid: "6Ag93Y02vihucO9IQl1fbg",
            data: "cj0tRGVIUnJaakM4RFpfMGU4UkdzaXNnTTItdGpnZi02MG0tLUZCaExRMjZ0ZyxzPUErRnQ4VU0" +
                  "2NzRPWk9PalVqWENkYnc9PSxpPTQwOTY=",
            nonce: "-DeHRrZjC8DZ_0e8RGsisgM2-tjgf-60m--FBhLQ26tg",
            salt: "A+Ft8UM674OZOOjUjXCdbw==".Decode64(),
            iterationCount: 4096,
            isMd5: false);
    }
}
