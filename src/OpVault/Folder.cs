// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OpVault
{
    public class Folder
    {
        // Used to mark no folder situation not to use null and avoid crashes.
        public static Folder None = new Folder("", "");

        public string Id { get; private set; }
        public string Name { get; private set; }
        public Folder Parent { get; set; }

        static Folder()
        {
            // Make sure there are no nulls
            None.Parent = None;
        }

        public Folder(string id, string name)
        {
            Id = id;
            Name = name;
            Parent = None;
        }
    }
}
