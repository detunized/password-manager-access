// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.OpVault;
using Xunit;

namespace PasswordManagerAccess.Test.OpVault
{
    public class Opdata01Test
    {
        [Fact]
        public void Decrypt_base64_returns_plaintext()
        {
            Assert.Equal(256, Opdata01.Decrypt(TestBlob, TestKey).Length);
        }

        [Fact]
        public void Decrypt_bytes_returns_plaintext()
        {
            Assert.Equal(256, Opdata01.Decrypt(TestBlob.Decode64(), TestKey).Length);
        }

        [Fact]
        public void Decrypt_throws_short_input()
        {
            var e = Assert.Throws<ParseException>(() => Opdata01.Decrypt(new byte[63], TestKey));
            Assert.Contains("too short", e.Message);
        }

        [Fact]
        public void Decrypt_throws_on_invalid_signature()
        {
            var blob = TestBlob.Decode64();
            blob[0] += 1;

            var e = Assert.Throws<ParseException>(() => Opdata01.Decrypt(blob, TestKey));
            Assert.Contains("invalid signature", e.Message);
        }

        [Fact]
        public void Decrypt_throws_on_mismatching_tag()
        {
            var blob = TestBlob.Decode64();
            blob[blob.Length - 1] += 1;

            var e = Assert.Throws<ParseException>(() => Opdata01.Decrypt(blob, TestKey));
            Assert.Contains("tag doesn't match", e.Message);
        }

        //
        // Data
        //

        private const string TestBlob = "b3BkYXRhMDEAAQAAAAAAALWgCJgau7XXb4yfb1yXFwpI30CyMvo1TS" +
                                        "q+S8Yq0uEmmNRv7jmZ6+k4FS/74ZlaPEJiVATgYtUmf7qaWgGNK23j" +
                                        "0/MCGUYdArvW6WXSYy6Bpf+tWCEN2f+qVZunyzzrSCLRwRRqeOdYjI" +
                                        "AOEcsPUDzHUj8GZT6+vz//oFjHE4S5Z6782vgnr+pDwb2Upmy1/E7G" +
                                        "rI32hCMR7nQnjtPEJMx10gsfgvHeiH6/3YoRksoxanf/C7l++27yPA" +
                                        "V8PXmMhQx90TEG0P/z55I1hbCpcgBWZzKzDVUzWSvghUIe7gVW9ObN" +
                                        "UoorpyTaBxE8A8yVyee2f6aYCp6yLMbe088NbDzGiI3audNJRjVNl/" +
                                        "NOTA6ZGr4c6FtUugKnuqApgD3K3e65VBKdsZ0Z3ur37oVy78BmPTMl" +
                                        "DOPPXIQZhhP/TnC4";

        private static readonly KeyMac TestKey = new KeyMac("a7HZUoTh0E9I7LCTF3AHDRQXGEbcnQuUMv" +
                                                            "6Vcvv7e13IOFMfmCJORzufhnDVeB4cDrxn" +
                                                            "TsPFYMTvpHboE8MPGg==");
    }
}
