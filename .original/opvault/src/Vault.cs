// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;

namespace OPVault
{
    public class Vault
    {
        internal static string MakeFilename(string path, string filename)
        {
            return Path.Combine(NormalizeSlashes(path), "default", NormalizeSlashes(filename));
        }

        internal static string NormalizeSlashes(string path)
        {
            // TODO: Test on non Windows based platforms
            return path.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        }
    }
}
