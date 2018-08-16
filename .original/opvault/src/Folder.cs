// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace OPVault
{
    public class Folder
    {
        public readonly string Id;
        public readonly string Name;

        public Folder(string id, string name)
        {
            Id = id;
            Name = name;
        }
    }
}
