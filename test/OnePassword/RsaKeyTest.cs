// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class RsaKeyTest : TestBase
    {
        [Fact]
        public void Parse_parses_sha1_json_and_returns_key()
        {
            var key = RsaKey.Parse(RsaSha1KeyData);
            Assert.Equal("szerdhg2ww2ahjo4ilz57x7cce", key.Id);
        }

        [Fact]
        public void Parse_parses_sha256_json_and_returns_key()
        {
            var key = RsaKey.Parse(RsaSha256KeyData);
            Assert.Equal("sfaijsnbchbtznlar7mx6yrhae", key.Id);
        }

        [Fact]
        public void Decrypt_decrypts_OAEP_SHA1_encrypted_ciphertext()
        {
            var enc = new Encrypted(
                KeyId: "szerdhg2ww2ahjo4ilz57x7cce",
                Scheme: "RSA-OAEP",
                Container: "b5+jwk+json",
                Iv: null,
                Ciphertext: (
                    "plF49e+3R0IpxBqWinosrPxWS8GdzKULvo4myIS1Gam5LCl1TmvvtntAiwOaL+/x8Ie7JApxksrpzrg9UAIaJeO"
                    + "JcoSzPA/hT4nn2jnglWLt+Dwz6RiEyQXhHqnyEOZ56RhNrVR8qKrnApUX2J/FWmrSYXQduIM2xbbx1LQwCGJJxC"
                    + "Hp/pFf3Eb0fwtaw2AB5QEF5uTXOnOY+NYaPUJLKTX63uas+uPGUtdJP66WT15zHEK/WRx4ekafJvIjueSTaiceq"
                    + "+IVXc5niMzTMYvRb5rIEiNm3WSX7EteqaU9T46ytm9748ILQNeuGSjzIqhO4H7mO47/e8wdEh3WZk8Alg=="
                ).Decode64()
            );
            var plain = Sha1Key.Decrypt(enc);
            Assert.Equal("All your base are belong to us".ToBytes(), plain);
        }

        [Fact]
        public void Decrypt_decrypts_OAEP_SHA256_encrypted_ciphertext()
        {
            var enc = new Encrypted(
                KeyId: "sfaijsnbchbtznlar7mx6yrhae",
                Scheme: "RSA-OAEP-256",
                Container: "b5+jwk+json",
                Iv: null,
                Ciphertext: (
                    "R2wRx7neV9M/hMyWhr6heE43Q48xL+6lZuy9k03+G0FVPmXsVPRK4q7nWq6UDVwcj42nxMychMKfurCuecLEd+h"
                    + "5zum9Py9y6r702GnymQAl0ReM6NyjxW2m1YOp6zFVlqa69Tptn+ewOD1Fqr14yJTgVtcSJCKjQxI0ALrFst/tMv"
                    + "OjMFFtYPCsQ3oC0ka7kDnjbikOD0AL7Q6/19Nilr3C/TjQdNRC1Y3c5sKtyDZj++OkwgB2nac1V9IfLbpum5nqQ"
                    + "im4UBOwE8f1axTDSYtKLJ31rr+z5bHxraUMzz96BnOmIzsZ2jj0fHrZBsBUs1L5Bg5XmGwHTz01z4HQ9A=="
                ).Decode64()
            );
            var plain = Sha256Key.Decrypt(enc);
            Assert.Equal("All your base are belong to us".ToBytes(), plain);
        }

        [Fact]
        public void Decrypt_throws_on_mismatching_key_id()
        {
            var enc = new Encrypted(KeyId: "invalid-id", Scheme: "RSA-OAEP", Container: "b5+jwk+json", Iv: null, Ciphertext: "ciphertext".ToBytes());
            Exceptions.AssertThrowsInternalError(() => Sha1Key.Decrypt(enc), "Mismatching key id");
        }

        //
        // Data
        //

        private RsaKey Sha1Key => RsaKey.Parse(RsaSha1KeyData);
        private RsaKey Sha256Key => RsaKey.Parse(RsaSha256KeyData);

        private Model.RsaKey RsaSha1KeyData { get; }
        private Model.RsaKey RsaSha256KeyData { get; }

        public RsaKeyTest()
        {
            RsaSha1KeyData = ParseFixture<Model.RsaKey>("rsa-key", useSystemJson: true);
            RsaSha256KeyData = ParseFixture<Model.RsaKey>("rsa-key-oaep-256", useSystemJson: true);
        }
    }
}
