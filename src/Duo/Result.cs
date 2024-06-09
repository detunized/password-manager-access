// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.Duo
{
    internal class Result
    {
        // This is returned what the V4 URL returns a redirect to the V1 api. This could happen when the traditional
        // prompt is enabled in the Duo admin panel.
        public static readonly Result RedirectToV1 = new Result("redirect-to-v1", false);

        public readonly string Passcode;
        public readonly bool RememberMe;

        public Result(string passcode, bool rememberMe)
        {
            Passcode = passcode;
            RememberMe = rememberMe;
        }
    }
}
