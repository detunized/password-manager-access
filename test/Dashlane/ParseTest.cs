// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using System.Xml.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class ParseTest
    {
        [Fact]
        public void ParseEncryptedBlob_parses_kwc3_blob()
        {
            var blob = Salt32.Concat("KWC3".ToBytes()).Concat(Content).ToArray();
            var parsed = Parse.ParseEncryptedBlob(blob);

            Assert.Equal(Content, parsed.Ciphertext);
            Assert.Equal(Salt32, parsed.Salt);
            Assert.Empty(parsed.Iv);
            Assert.Empty(parsed.Hash);

            var config = parsed.CryptoConfig;
            Assert.IsType<Parse.Pbkdf2Config>(config.KdfConfig);
            Assert.Equal(Parse.CryptoConfig.CipherModeType.Cbc, config.CipherMode);
            Assert.Equal(Parse.CryptoConfig.IvGenerationModeType.EvpByteToKey, config.IvGenerationMode);
            Assert.Equal(Parse.CryptoConfig.SignatureModeType.None, config.SignatureMode);

            var pbkdf2 = (Parse.Pbkdf2Config)config.KdfConfig;
            Assert.Equal(Parse.Pbkdf2Config.HashMethodType.Sha1, pbkdf2.HashMethod);
            Assert.Equal(10204, pbkdf2.Iterations);
            Assert.Equal(32, pbkdf2.SaltLength);
            Assert.Equal("pbkdf2", pbkdf2.Name);
        }

        [Fact]
        public void ParseEncryptedBlob_throws_on_kwc5_blob()
        {
            var blob = Iv16
                .Concat("16 bytes padding".ToBytes())
                .Concat("KWC5".ToBytes())
                .Concat(Hash32)
                .Concat(Content)
                .ToArray();

            Exceptions.AssertThrowsUnsupportedFeature(() => Parse.ParseEncryptedBlob(blob), "KWC5");
        }

        [Fact]
        public void ParseEncryptedBlob_parses_flexible_blob_with_argon2d()
        {
            var blob = "$1$argon2d$16$3$32768$2$aes256$cbchmac$16$".ToBytes()
                .Concat(Salt16)
                .Concat(Iv16)
                .Concat(Hash32)
                .Concat(Content)
                .ToArray();
            var parsed = Parse.ParseEncryptedBlob(blob);

            Assert.Equal(Content, parsed.Ciphertext);
            Assert.Equal(Salt16, parsed.Salt);
            Assert.Equal(Iv16, parsed.Iv);
            Assert.Equal(Hash32, parsed.Hash);

            var config = parsed.CryptoConfig;
            Assert.IsType<Parse.Argon2dConfig>(config.KdfConfig);
            Assert.Equal(Parse.CryptoConfig.CipherModeType.CbcHmac, config.CipherMode);
            Assert.Equal(Parse.CryptoConfig.IvGenerationModeType.Data, config.IvGenerationMode);
            Assert.Equal(Parse.CryptoConfig.SignatureModeType.HmacSha256, config.SignatureMode);

            var argon2d = (Parse.Argon2dConfig)config.KdfConfig;
            Assert.Equal(32768, argon2d.MemoryCost);
            Assert.Equal(3, argon2d.TimeCost);
            Assert.Equal(2, argon2d.Parallelism);
            Assert.Equal(16, argon2d.SaltLength);
            Assert.Equal("argon2d", argon2d.Name);
        }

        [Fact]
        public void ParseEncryptedBlob_parses_flexible_blob_with_pbkdf2()
        {
            var blob = "$1$pbkdf2$16$200000$sha256$aes256$cbchmac$16$".ToBytes()
                .Concat(Salt16)
                .Concat(Iv16)
                .Concat(Hash32)
                .Concat(Content)
                .ToArray();
            var parsed = Parse.ParseEncryptedBlob(blob);

            Assert.Equal(Content, parsed.Ciphertext);
            Assert.Equal(Salt16, parsed.Salt);
            Assert.Equal(Iv16, parsed.Iv);
            Assert.Equal(Hash32, parsed.Hash);

            var config = parsed.CryptoConfig;
            Assert.IsType<Parse.Pbkdf2Config>(config.KdfConfig);
            Assert.Equal(Parse.CryptoConfig.CipherModeType.CbcHmac, config.CipherMode);
            Assert.Equal(Parse.CryptoConfig.IvGenerationModeType.Data, config.IvGenerationMode);
            Assert.Equal(Parse.CryptoConfig.SignatureModeType.HmacSha256, config.SignatureMode);

            var pbkdf2 = (Parse.Pbkdf2Config)config.KdfConfig;
            Assert.Equal(Parse.Pbkdf2Config.HashMethodType.Sha256, pbkdf2.HashMethod);
            Assert.Equal(200000, pbkdf2.Iterations);
            Assert.Equal(16, pbkdf2.SaltLength);
            Assert.Equal("pbkdf2", pbkdf2.Name);
        }

        [Fact]
        public void ParseEncryptedBlob_throws_on_unknown_encryption_type()
        {
            var blob = Salt32.Concat("blah".ToBytes()).Concat(Content).ToArray();
            Assert.Throws<NotImplementedException>(() => Parse.ParseEncryptedBlob(blob));
        }

        [Fact]
        public void ParseEncryptedBlob_throws_on_too_short_blob()
        {
            var e = Assert.Throws<ArgumentException>(() => Parse.ParseEncryptedBlob(new byte[] {13, 37}));
            Assert.Equal("Blob is too short\r\nParameter name: blob", e.Message);
        }

        [Fact]
        public void DecryptBlob_returns_decrypted_content_from_kwc3_blob()
        {
            Assert.Equal(Content, Parse.DecryptBlob(Blob, Password));
        }

        [Fact]
        public void DecryptBlob_throws_on_incorrect_password()
        {
            Exceptions.AssertThrowsBadCredentials(() => Parse.DecryptBlob(Blob, "Incorrect password"),
                                                  "The password is incorrect");
        }

        [Fact]
        public void DecryptBlob_throws_on_non_ascii_password()
        {
            Exceptions.AssertThrowsUnsupportedFeature(() => Parse.DecryptBlob(Blob, "\x80\x90\xA0"),
                                                      "Non ASCII passwords");
        }

        [Fact]
        public void ComputeEncryptionKey_returns_correct_result()
        {
            var key = Parse.ComputeEncryptionKey(
                Password.ToBytes(),
                Salt32,
                new Parse.CryptoConfig(
                    new Parse.Pbkdf2Config(Parse.Pbkdf2Config.HashMethodType.Sha1, 10204, 32),
                    Parse.CryptoConfig.CipherModeType.Cbc,
                    Parse.CryptoConfig.IvGenerationModeType.EvpByteToKey,
                    Parse.CryptoConfig.SignatureModeType.None));
            Assert.Equal("OAIU9FREAugcAkNtoeoUithzi2qXJQc6Gfj5WgPD0mY=".Decode64(), key);
        }

        [Fact]
        public void PasswordToBytes_throws_on_non_ascii_password()
        {
            Exceptions.AssertThrowsUnsupportedFeature(() => Parse.PasswordToBytes("\x80\x90\xA0"),
                                                      "Non ASCII passwords");
        }

        [Fact]
        public void DeriveEncryptionKeyAndIv_computes_key_and_iv()
        {
            var keyIv = Parse.DeriveEncryptionKeyAndIv("OAIU9FREAugcAkNtoeoUithzi2qXJQc6Gfj5WgPD0mY=".Decode64(),
                                                       Salt32);

            Assert.Equal("6HA2Rq9GTeKzAc1imNjvyaXBGW4zRA5wIr60Vbx/o8w=".Decode64(), keyIv.Key);
            Assert.Equal("fCk2EkpIYGn05JHcVfR8eQ==".Decode64(), keyIv.Iv);
        }

        [Fact]
        public void Decrypt_decrypts_ciphertext()
        {
            var plaintext = Parse.Decrypt("TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                                          "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                                          "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64());
            Assert.Equal(Content, plaintext);
        }

        [Fact]
        public void Decrypt_throws_on_incorrect_encryption_key()
        {
            Exceptions.AssertThrowsBadCredentials(() => Parse.Decrypt(
                "TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI=".Decode64(),
                "YFuiAVZgOD2K+s6y8yaMOw==".Decode64(),
                "Incorrect key must be 32 bytes!!".ToBytes()),
                "The password is incorrect");
        }

        [Fact]
        public void Inflate_decompresses_data()
        {
            Assert.Equal(Content, Parse.Inflate("c8zJUajMLy1SSEosTlVILEpVSErNyc9LVyjJVygtBgA=".Decode64()));
        }

        [Fact]
        public void ExtractAccountsFromXml_extracts_accounts_at_different_levels()
        {
            var xml = @"
                <KWAuthentifiant>
                    <KWDataItem key='Id'><![CDATA[1]]></KWDataItem>
                    <KWDataItem key='Title'><![CDATA[dude]]></KWDataItem>
                    <KWDataItem key='Login'><![CDATA[jeffrey.lebowski]]></KWDataItem>
                    <KWDataItem key='Password'><![CDATA[logjammin]]></KWDataItem>
                    <KWDataItem key='Url'><![CDATA[https://dude.com]]></KWDataItem>
                    <KWDataItem key='Note'><![CDATA[Get a new rug!]]></KWDataItem>
                </KWAuthentifiant>
                <KWAuthentifiant>
                    <KWDataItem key='Id'><![CDATA[2]]></KWDataItem>
                    <KWDataItem key='Title'><![CDATA[walter]]></KWDataItem>
                    <KWDataItem key='Login'><![CDATA[walter.sobchak]]></KWDataItem>
                    <KWDataItem key='Password'><![CDATA[worldofpain]]></KWDataItem>
                    <KWDataItem key='Url'><![CDATA[https://nam.com]]></KWDataItem>
                    <KWDataItem key='Note'><![CDATA[Don't roll on Shabbos!]]></KWDataItem>
                </KWAuthentifiant>";

            Assert.Empty(Parse.ExtractAccountsFromXml("<root />"));
            Assert.Equal(2, Parse.ExtractAccountsFromXml("<root>" + xml + "</root>").Length);
            Assert.Equal(2, Parse.ExtractAccountsFromXml("<root><subroot>" + xml + "</subroot></root>").Length);
        }

        [Fact]
        public void ParseAccount_returns_account()
        {
            var e = XDocument.Parse(
                @"<KWAuthentifiant>
                    <KWDataItem key='Id'><![CDATA[1]]></KWDataItem>
                    <KWDataItem key='Title'><![CDATA[dude]]></KWDataItem>
                    <KWDataItem key='Login'><![CDATA[jeffrey.lebowski]]></KWDataItem>
                    <KWDataItem key='Password'><![CDATA[logjammin]]></KWDataItem>
                    <KWDataItem key='Url'><![CDATA[https://dude.com]]></KWDataItem>
                    <KWDataItem key='Note'><![CDATA[Get a new rug!]]></KWDataItem>
                </KWAuthentifiant>");
            var account = Parse.ParseAccount(e.Root);

            Assert.Equal("1", account.Id);
            Assert.Equal("dude", account.Name);
            Assert.Equal("jeffrey.lebowski", account.Username);
            Assert.Equal("logjammin", account.Password);
            Assert.Equal("https://dude.com", account.Url);
            Assert.Equal("Get a new rug!", account.Note);
        }

        [Fact]
        public void ParseAccount_returns_account_with_all_defaults()
        {
            var e = XDocument.Parse("<KWAuthentifiant></KWAuthentifiant>");
            var account = Parse.ParseAccount(e.Root);

            Assert.Equal("", account.Id);
            Assert.Equal("", account.Name);
            Assert.Equal("", account.Username);
            Assert.Equal("", account.Password);
            Assert.Equal("", account.Url);
            Assert.Equal("", account.Note);
        }


        [Fact]
        public void GetValueForKeyOrDefault_returns_value_when_present()
        {
            var e = XDocument.Parse("<root><KWDataItem key='key'>value</KWDataItem></root>");

            Assert.Equal("value", Parse.GetValueForKeyOrDefault(e.Root, "key", "default"));
        }

        [Fact]
        public void GetValueForKeyOrDefault_returns_default_value_when_not_present()
        {
            var e = XDocument.Parse("<root><KWDataItem key='key'>value</KWDataItem></root>");

            Assert.Equal("default", Parse.GetValueForKeyOrDefault(e.Root, "not-a-key", "default"));
        }

        [Fact]
        public void ExtractEncryptedAccounts_returns_accounts()
        {
            var blob = "c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHRLV0MzAxW0NQiQrbiEe4yl26Ga" +
                       "gNu1edW/lK/INVrdUkE1+nmpiTZHlNkKKSK5NXbWGuztnk3256De1/2GtaUXjTKOMYvh" +
                       "eV3TJJZWHKHEbSBHJ63OXH/svTCBm1yncDDcqWicVOjQwzP5C4oTmRB9jCAE9A7kx8bZ" +
                       "jz2VQaAAxbKWwCFCSrzFXB22R6DwH+rpnKshrcHiflI8Fy2o000mU1XRhk1yFNqYZkiJ" +
                       "BH0N3aJR7AkqRRALhUaLsMgYWsCxPqD9dP0dsp7A03htUKllVMfjfRexwJfJGi2ezSUv" +
                       "egGVt3k=";

            Assert.Equal(2, Parse.ExtractEncryptedAccounts(blob.Decode64(), Password).Length);
        }

        //
        // Data
        //

        private const string Password = "password";
        private static readonly byte[] Salt16 = "saltsaltsaltsalt".ToBytes();
        private static readonly byte[] Salt32 = "saltsaltsaltsaltsaltsaltsaltsalt".ToBytes();
        private static readonly byte[] Iv16 = "iviviviviviviviv".ToBytes();
        private static readonly byte[] Hash32 = "hashhashhashhashhashhashhashhash".ToBytes();
        private static readonly byte[] Content = "All your base are belong to us".ToBytes();
        private static readonly byte[] Blob =
            ("c2FsdHNhbHRzYWx0c2FsdHNhbHRzYWx0c2FsdHNhbHRLV0MzxDNg8kGh5" +
            "rSYkNvXzzn+3xsCKXSKgGhb2pGnbuqQo32blVfJpurp7jj8oSnzxa66").Decode64();

        // TODO: Use this!
        private const string FlexibleBlobArgon2 = "JDEkYXJnb24yZCQxNiQzJDMyNzY4JDIkYWVzMjU2J" +
            "GNiY2htYWMkMTYk8Ik8hP3t6nuDctDDdgSfor7v7ZK13ba1dofrlEojOg0a8GKMz8dn6GHsViM7t3qv" +
            "2BzAnAehDZmzJp27mOiDAyQVBDoGmoNMd53EoMUZ+0aSCTY1gYQdCPvEC/7HGqjbj4gSf/ONuf2OSg5" +
            "TwcQ1twbq2tlGyohUuj3qZ5s+eC9HJCpWHAzhFqODnqQBBM3zdkkFOxWXx8P6oGP5G4fOFgzvaGrlAD" +
            "jh+bEd/wwAIZIz2IZ6QpYBU7I+dRJh2C2/3Bx/ZY6qqjoehtFu1k0St4gKMGS42X8gnLbquSRmMRIzC" +
            "bx035b05Z4lglfA9SJUrQBZTVzo+doct3zpud8mZa4bwTNIj0aji+d5BEtDPma862LTglDL5FjJ83Uo" +
            "vR0M6M8WO8qRW2bJHa063Q7zA6VrZKqptK2yZeez6DGyo7uIDvv9HKDNIYcH71aZH5MPFth6tPc7NiX" +
            "lVy0VBkE55kA+RCHWZ1PTZwTQQWtCQPlNONq6m+YQSCq3tXr6TkZ4zGYneRejyuiBI3NFNhQEdw==";
    }
}
