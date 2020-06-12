// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.OpVault
{
    public class Folder
    {
        // `None` is used to mark "no folder" situation not to use null and avoid crashes.
        // It guaranteed to be exactly this instance, so it's ok to use reference compare to check for no parent:
        // if (folder.Parent == Folder.None) { ... }
        public static readonly Folder None = new Folder("", "");

        public string Id { get; }
        public string Name { get; }

        public Folder Parent
        {
            get => _parent ?? None;
            internal set => _parent = value;
        }

        //
        // Non-public
        //

        internal Folder(string id, string name)
        {
            Id = id;
            Name = name;
        }

        // `_parent` is nullable. The public `Parent` property hides the null value by returning `None` instead.
        private Folder _parent;
    }
}
