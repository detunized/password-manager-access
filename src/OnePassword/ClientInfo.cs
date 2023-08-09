// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OnePassword
{
    // TODO: Move this elsewhere
    public class ServiceAccount
    {
        public string Token { get; set; }
    }

    // TODO: Rename to ApplicationInfo?
    public class DeviceInfo
    {
        public string Uuid { get; set; }
        public string Name { get; set; }
        public string Model { get; set; }
    }
}
