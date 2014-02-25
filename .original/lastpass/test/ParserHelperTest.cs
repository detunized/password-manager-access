// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class ParserHelperTest
    {
        [Test]
        public void ParseAccount_returns_account()
        {
            WithBlob(reader => {
                var accounts = ParserHelper.ExtractChunks(reader).Where(i => i.Id == "ACCT").ToArray();
                for (var i = 0; i < accounts.Length; ++i)
                {
                    var account = ParserHelper.Parse_ACCT(accounts[i], TestData.EncryptionKey);
                    Assert.True(account.Url.StartsWith(TestData.Accounts[i].Url));
                }
            });
        }

        [Test]
        public void Parse_PRIK_returns_private_key()
        {
            var chunk = new ParserHelper.Chunk("PRIK", "98F3F5518AE7C03EBBF195A616361619033509FB1FFA0408E883B7C5E80381F8C8A343925DDA78FB06A14324BEC77EAF63290D381F54763A2793FE25C3247FC029022687F453426DE96A9FB34CEB55C02764FB41E5E1619226FE47FA7EA40B410973132F7AB2DE2D7F08C181C7D56BBF92CD4D44BC7DEE4253DEC36C77D28E306F41B8BB26B0EDB97BADCEE912D3671C22339036FC064F5AF60D3545D47B82636BBA1896ECDCF5EBE99A1061EFB8FBBD6C3500EA06A28BB8863F413702D9C05B9A54120F1BEFA0D98A48E82622A36DBD79772B5E4AD957045DC2B97311983592A357037DDA172C284B4FEC7DF8962A11B42079D6F943C8F9C0FEDFEA0C43A362B550E217715FD82D9F3BB168A006B0880B1F3660076158FE8CF6B706CF2FEAA1A731D1F68B1BC20E7ADE15097D2CD84606B4B0756DFE25DAF110D62841F4426573A676B904972B31AD7B02093C536341E1DA943F1AFF88DF2005BD04C6897FB6F9E307DA1C2BD219AB39F911FF90C6B1EA658C72C67C1EADC36CD5202654B4E199A88F13DCE1148CC04F81485896627BB1DB5C73969520CC66652492383930E33AFD57BE171F4BA25016EC9C3662F5B054101E381565433E46CB9FD517B59AE8A5CE7D11005282E551E9DCAA1996763E41B49677F906F122AAB76E852F35B31F397B70949D5F6C8DAA244AF16E9D48E0801E5C6D3FCEAFD2C3E157968B3E796C87E1F3FFF86B62FE5263D1A597E3906BF697C019F1F543D7BB1E11B08837B47F4528E4B47EB77508CFC0581B2A005383D0A238EA5BDE2E2602E0D2408B139735F4BAF8D6CF260BBC81833A85F14C5746AC6081B878486F5A4BD23B821F3F5F6BDAC8A9B57E25E24EDB8D701F01AE142D63A8A7D0F1CC8FAFF5F0320551CEB29BDB6907C57E38602927AD7240003FEB238AC5437FE4BAD11BB5038CA74D539523A167B8EBB1210608EB7DA53B4155D05B87D21848E58905EFA550EA5A51E0A68D5FF0F9E0CC0D5105DD98BE9E2C41362794A71A573CCA87B57147115B86FC8A6BB1778CED1920787271C75D69C5D63CD798915BF8F9877808F841F9269B2EA8090E11F6C89FDB537F341142CA29BAC761E1CF9D58FFB0C44A26E5EF7FA14142C8A84BC9304A221D5F961DB41B5925B06823A12A6F8950E47325021A747A02A28FDAE65997EBDF5D2BDBCA7C8D689AE186A9FE85A170B76EE92595C9E33639C99307C377FA4DA975E191810E993CDC0A33EE494B0EE8A1B6A9408285012967C17A8CB5EE8E7973CF9186A98000FE00F1CC76420089C6BDCE9E39D403C320DF11351597FF8B231689389CCE12844289FEFE468BFCAEE9A2CFB1A8DD066AEC974DA9C8530C9A17593E25DC89934E056B178329C4BBF7113657677AB25EE66A1E1D92F62154B2451B37727F05B3AC0F2501F7A95845C9BE210D411028C27A9AD4B0E831A6C46D26883A8AA2D1E2BD3E8E122A6FC21CECB7AE2B91C6FCFA793C5CAFF653C6670D914A29EAD81CD5C29FFB048C81CC80EDD693B4D8091B2D5DE88EA04211AC551F406B713278BD14667E437C610953D6186C2986BA60361C2013395E8EA9D14CD00EC5C61147BE03D8965B5376DF32E2C3740128398E0D47900C888FD0D1F7D583808AFBC0712806E11462B37815C20692FB38E61CC0B1AAF66A8549826A1F5FFFF2436B0B9F9EDFF4F5B59B362AA1D25A4E3C398EB18445483F8419BD1511A5177E9C4B7034375A2D91B95153535E6CD5F023F4EED0E15B5415A3B7A77E390AA698DF00F4FD897B0454C00959AF0CB54B272DE63968815B971C44B2736AC737FAE6A19F544907833F13C6F424D30E3B85054A4402EC94079C1473C20BE4C1B33525486BB098EF960082DB4DF5FE9CAF71681B03CB2D4BE7382FF0C03F18144DE554256591773DC3F381116955233FDA7223D71C402E558783F221E25A94FECD350654A9CD8EE8C39E4B1CFBA0D5FD46891527F2D0FC9EA61584A76D5999719811B2BAFC99769E6911733ED389A731C327CB5D7BB6D79CE030D3285586C6681FC8C110EFE30CEE883FFEF5FB511B4421863E2A15F8CDCFA7B84B9311215B23093DE3B5E7F4CFCCE60BE7857B7442B8FCC3E43C46C4BFA3E9ABD2F479F6BD8D3F3D36C0FAC1F4D72FBE96C644AB56F73CAF956D5544B2EB9C589ED30FF30BB03D09DB455764EF4A33C24F93170A98A21455826390B13A8F338A820EC08D6E9F562282C2F815BB57CE511AB6B0DE75EFA63F28C6D0B25298CDAAC76742D5353B26B77C1533B4DFE2D95F3E89315C0D806A90FCDFDC31CE04A9E29937680D32D8B503352388109C1F5F41E8496302E13A61917F70A9AA3C5ECDBD88163E3CF0580C5EB1382BB66194AC0983BAA16B4D220756F4B7E3DDFFC5BF343FA7E31D14FED4409AD0FE9BBE01AF79DA4852253CBF166FDCA90E894B5267A502F7334706F8C767EC861324CC7734352D76DB007E25105E7994CF91D79532221316F4DE56BAE4351D3E3C6549FBFEF13BBE2636071794AD9EC3787B4A71E5438B86C35865ECF2EA5980318F82D8B113C0EC8FEE41C243E0A1A09F373A0CF546FA18E1EC7DB4842A6B8B03D115654222B87DA6034EFDE2224DBD23AB104BF3723856C03DB639BA073F2CC8E4AB05BAADDB5DEACC1874F4D6F86B95710019114DACBFE48FEF2AE2DF27356B5C17948B26A41FD1A8F07E8068E176F995910C373886DB47D26C2FE5CD97AAF1829EBC1EEBA4D88343A322E810385138F51F0E5149183699C405E49ED13C2889A22742893A52567B0F7D4A3BC9F4DC6D29F713AA7FB4EF6B135F92F598404A80E7D6515CE234AFA68A4B562AF203162C60D578F0D00E302958174E1A712FD449D257C6AA5F56E4DBD0363573931463BC910858AF1EC40C1F4A7BE27DE8E170D4AACF6C34B0CDE15190FD81FA5676136A4D73E2AA4BBFBB8E7C1178EF47362188D9288E822B10BBF2C8BE075A5BD1D3E1F08108BA8C4E6FB173DCECB5771E9D8AE4CD776EA3409DF30FA2252D3C3769AF12177F4A1929DC8E74D5AEAC94CF94EEBA0E9AC012C57B40A8BB57530C25846B841005767B9AABE436D4590977FDDA519B9B284CF8B8922A0E8B659ECE3745A95800EE1B3DDD33E0FF230C0528BC7A4CB80604411E59E08775A42C634E93BA9C77D015659AC912F43694F774E94050E4B3BF84290368D5AFD7F043BDCA3BD0CC8C0E267069B6F1386AE1D9C8B5512AAAA292FDA9CA07E27BAF983E1E25A11732797425F2BB396B302E0782BA183D4BC1F682365774520EAC8A321C7A0BD08027021EA0063D471E0AD1E1469AD803C311D3FBF50B5538265D4262B6716D90E89A8C906D08533D6500006BF1B8ABAAFE1CA3AFDD1A19ACABE5B86A804D36AE27163CAF390FD266D5FFEFFC7CE6FEF9458E4AF0C4108E32EFD11C19751B1D9883E803F7C2E1A5786F33851A7CA3772ECD7CB0E9782A7D30E0A9FD09EED361B774A277C618C995FD7F7634E7DB3834690B58DDFF6B721157D0EC02".ToBytes());
            var encryptionKey = "v4uHomAR0tAXC3fA5Nfq7DjyJxuvYErMSCcZIWZKjpM=".Decode64();
            Assert.NotNull(ParserHelper.Parse_PRIK(chunk, encryptionKey));
        }

        [Test]
        public void ReadChunk_returns_first_chunk()
        {
            WithBlob(reader => {
                var chunk = ParserHelper.ReadChunk(reader);
                Assert.AreEqual("LPAV", chunk.Id);
                Assert.AreEqual(3, chunk.Payload.Length);
                Assert.AreEqual(11, reader.BaseStream.Position);
            });
        }

        [Test]
        public void ReadChunk_reads_all_chunks()
        {
            WithBlob(reader => {
                while (reader.BaseStream.Position < reader.BaseStream.Length)
                    ParserHelper.ReadChunk(reader);

                Assert.AreEqual(reader.BaseStream.Length, reader.BaseStream.Position);
            });
        }

        [Test]
        public void ExtractChunks_returns_all_chunks()
        {
            WithBlob(reader => {
                var chunks = ParserHelper.ExtractChunks(reader);
                var ids = chunks.Select(i => i.Id).Distinct().ToArray();
                Assert.AreEqual(TestData.ChunkIds, ids);
            });
        }

        [Test]
        public void ReadItem_returns_first_item()
        {
            WithBlob(reader => {
                var chunks = ParserHelper.ExtractChunks(reader);

                var account = chunks.Find(i => i.Id == "ACCT");
                Assert.NotNull(account);

                ParserHelper.WithBytes(account.Payload, chunkReader => {
                    var item = ParserHelper.ReadItem(chunkReader);
                    Assert.NotNull(item);
                });
            });
        }

        [Test]
        public void SkipItem_skips_empty_item()
        {
            WithHex("00000000", reader => {
                ParserHelper.SkipItem(reader);
                Assert.AreEqual(4, reader.BaseStream.Position);
            });
        }

        [Test]
        public void SkipItem_skips_non_empty_item()
        {
            WithHex("00000004DEADBEEF", reader => {
                ParserHelper.SkipItem(reader);
                Assert.AreEqual(8, reader.BaseStream.Position);
            });
        }

        [Test]
        public void ReadId_returns_id()
        {
            var expectedId = "ABCD";
            ParserHelper.WithBytes(expectedId.ToBytes(), reader => {
                var id = ParserHelper.ReadId(reader);
                Assert.AreEqual(expectedId, id);
                Assert.AreEqual(4, reader.BaseStream.Position);
            });
        }

        [Test]
        public void ReadSize_returns_size()
        {
            WithHex("DEADBEEF", reader => {
                var size = ParserHelper.ReadSize(reader);
                Assert.AreEqual(0xDEADBEEF, size);
                Assert.AreEqual(4, reader.BaseStream.Position);
            });
        }

        [Test]
        public void ReadPayload_returns_payload()
        {
            var expectedPayload = "FEEDDEADBEEF".DecodeHex();
            var size = expectedPayload.Length;
            ParserHelper.WithBytes(expectedPayload, reader => {
                var payload = ParserHelper.ReadPayload(reader, (uint)size);
                Assert.AreEqual(expectedPayload, payload);
                Assert.AreEqual(size, reader.BaseStream.Position);
            });
        }

        [Test]
        public void DecryptAes256EcbPlain()
        {
            var tests = new Dictionary<string, string> {
                {"", ""},
                {"0123456789", "8mHxIA8rul6eq72a/Gq2iw=="},
                {"All your base are belong to us", "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM="}
            };

            foreach (var i in tests)
                Assert.AreEqual(i.Key, ParserHelper.DecryptAes256EcbPlain(i.Value.Decode64(), _encryptionKey));
        }

        [Test]
        public void DecryptAes256EcbBase64()
        {
            var tests = new Dictionary<string, string> {
                {"", ""},
                {"0123456789", "8mHxIA8rul6eq72a/Gq2iw=="},
                {"All your base are belong to us", "BNhd3Q3ZVODxk9c0C788NUPTIfYnZuxXfkghtMJ8jVM="}
            };

            foreach (var i in tests)
                Assert.AreEqual(i.Key, ParserHelper.DecryptAes256EcbBase64(i.Value.ToBytes(), _encryptionKey));
        }

        [Test]
        public void DecryptAes256CbcPlain()
        {
            var tests = new Dictionary<string, string> {
                {"", ""},
                {"0123456789", "IQ+hiIy0vGG4srsHmXChe3ehWc/rYPnfiyqOG8h78DdX"},
                {"All your base are belong to us", "IcokDWmjOkKtLpZehWKL6666Uj6fNXPpX6lLWlou+1Lrwb+D3ymP6BAwd6C0TB3hSA=="}
            };

            foreach (var i in tests)
                Assert.AreEqual(i.Key, ParserHelper.DecryptAes256CbcPlain(i.Value.Decode64(), _encryptionKey));
        }

        [Test]
        public void DecryptAes256CbcBase64()
        {
            var tests = new Dictionary<string, string> {
                {"", ""},
                {"0123456789", "!6TZb9bbrqpocMaNgFjrhjw==|f7RcJ7UowesqGk+um+P5ug=="},
                {"All your base are belong to us", "!YFuiAVZgOD2K+s6y8yaMOw==|TZ1+if9ofqRKTatyUaOnfudletslMJ/RZyUwJuR/+aI="}
            };

            foreach (var i in tests)
                Assert.AreEqual(i.Key, ParserHelper.DecryptAes256CbcBase64(i.Value.ToBytes(), _encryptionKey));
        }

        private static void WithBlob(Action<BinaryReader> action)
        {
            ParserHelper.WithBytes(TestData.Blob, action);
        }

        private static void WithHex(string hex, Action<BinaryReader> action)
        {
            ParserHelper.WithBytes(hex.DecodeHex(), action);
        }

        private static readonly byte[] _encryptionKey = "OfOUvVnQzB4v49sNh4+PdwIFb9Fr5+jVfWRTf+E2Ghg=".Decode64();
    }
}
