// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class ChaCha20Test
    {
        [Fact]
        public void Ctor_throws_on_invalid_key_size()
        {
            Exceptions.AssertThrowsInternalError(() => new ChaCha20(new byte[1337], new byte[12]), "Key must be 32 bytes");
        }

        [Fact]
        public void Ctor_throws_on_invalid_nonce_size()
        {
            Exceptions.AssertThrowsInternalError(() => new ChaCha20(new byte[32], new byte[1337]), "Nonce must be 12 bytes");
        }

        // Test vectors from https://github.com/golang/crypto/blob/master/chacha20/vectors_test.go
        [Theory]
        [InlineData("b6a3a89de64abf3aae9cf1a207c768101e80e472925d16ce8f02e761573dac82", "1733d194b3a2b6063600fe3f", "", "")]
        [InlineData("2be077349f80bf45faa1f427e81d90dbdc90a1d8d4212c1dacf2bd870000bfdf", "ddfa69041ecc3feeb077cf45", "23dbad0780", "415a3e498d")]
        [InlineData(
            "254c12e973a3d14fbbf7457964f0d5ee5d18c42913cf9a3c67a3944c532c2c7c",
            "496b2a516daff98da5a23653",
            "f518831fab69c054a6",
            "cfe40f63f81391484b"
        )]
        [InlineData(
            "205082fc0b41a45cd085527d9d1c0a16410b47152a743436faa74ae67ae60bca",
            "9e7a69ca17672f6b209285b7",
            "805fad1d62951537aeed9859",
            "47bd303f93c3ce04bce44710"
        )]
        [InlineData(
            "ef2d6344a720e4a58f2ac10f159ab76314e37d3316bf2fb857bc043127927c67",
            "b33dedcd7f0a77359bdeae06",
            "f4e8a7577affb841cf48392cf5df",
            "f445c0fb7e3d5bfdab47090ddee6"
        )]
        [InlineData(
            "a831bd347ef40828f9198b9d8396f54d48435831454aa734a274e10ddcc7d429",
            "b1508a348092cc4ace14608d",
            "1179b71ec4dc34bd812f742b5a0b27",
            "cc7f80f333c647d6e592e4f7ecc834"
        )]
        [InlineData(
            "ed793ce92b1689ce66836a117f65dcec981dc85b522f5dffbb3e1f172f3f7750",
            "034775c821c58891a6e88cac",
            "7bd94943d55392d0311c413ac755ce0347872ba3",
            "c43665de15136af232675d9d5dbbeca77f3c542a"
        )]
        [InlineData(
            "b3d542358ffd7b1ff8ab3810ece814729356d0edbd63e66006d5e5e8a223a9ee",
            "cb55869aa56e9d6e5e70ad5d",
            "1505f669acc5ad9aaa0e993ba8c24e744d13655e1f",
            "26cad1ccf4cf4c49b267ab7be10bc2ffa3ba66bc86"
        )]
        [InlineData(
            "d6b18ae2473d3be8ca711267ffbc77b97644f6a2b4791d31d0910d180c6e1aec",
            "a42c203f86fc63000ea16072",
            "20070523ddb4ebf0d5f20fd95aacf47fb269ebadda6879638a",
            "5ce972624cb2b7e7c28f5b865ba08c887911b4f5e361830a4b"
        )]
        [InlineData(
            "bba26ce4efb56ad06b96e2b02d0cdd549ad81588a9306c421e0f5b0175ae4b25",
            "ea7186cf2fdf728d8a535a8b",
            "d10f8050c1186f92e26f351db36490d82ea677498562d8d4f487a0a4058adf",
            "f30c11bc553b2baf6870760d735680897c9fee168f976b2a33ef395fdbd4fc"
        )]
        [InlineData(
            "a76d5c79dcaab18c9a3542a0272eea95c45382122f59bcaa10e8910371d941f6",
            "3a98bed189a35a0fe1c726fa",
            "e88dc380b7d45a4a762c34f310199587867516fac4a2634022b96a9f862e17714d17",
            "aac98ba3821399e55a5eab5862f7f1bfc63637d700125878c2b17151f306c9aec80e"
        )]
        [InlineData(
            "f78c6fa82b1ab48d5631e0e0598aad3dbad1e4b338fbf6759d7094dbf334dbc3",
            "b8f4f598731d183f2e57f45b",
            "b0fcf0a731e2902787309697db2384e1cda07b60002c95355a4e261fb601f034b2b3",
            "b6c8c40ddda029a70a21c25f724cc90c43f6edc407055683572a9f5e9690a1d571bb"
        )]
        [InlineData(
            "a0076c332ba22e4a462f87a8285e7ba43f5e64be91651c377a23dcd28095c592",
            "18ae8972507ebe7e7691817d",
            "cf9ec6fa3f0a67488adb5598a48ed916729a1e416d206f9675dfa9fd6585793f274f363bbca348b3",
            "bb7ed8a199aa329dcd18736ce705804ffae8c3e2ba341ae907f94f4672d57175df25d28e16962fd6"
        )]
        [InlineData(
            "2e4c1a78e255ab2743af4a8101ab0b0ae02ce69dd2032b47e818eedf935b858b",
            "de8131fd263e198b99c7eb0b",
            "be9a8211d68642310724eda3dd02f63fcc03a101d9564b0ecee6f4ecececcb0099bb26aabee46b1a2c0416b4ac269e",
            "3152f317cf3626e26d02cff9392619ea02e22115b6d43d6dd2e1177c6bb3cb71c4a90c3d13b63c43e03605ec98d9a1"
        )]
        [InlineData(
            "3277fc62f46cf0ced55ef4a44f65962f6e952b9ff472b542869cb55b4f78e435",
            "f62fb0273e6110a5d8228b21",
            "495343a257250f8970f791f493b89d10edba89806b88aaaeb3b5aefd078ba7b765746164bce653f5e6c096dd8499fb76d97d77",
            "62c01f426581551b5b16e8b1a3a23c86bcdd189ab695dbea4bf811a14741e6ebbb0261ef8ae47778a6be7e0ef11697b891412c"
        )]
        [InlineData(
            "8f7a652b5d5767fe61d256aa979a1730f1fffcae98b68e9b5637fe1e0c45eab4",
            "637ab99d4802f50f56dfb6f2",
            "e37fbbd3fe37ce5a99d18e5dcb0dafe7adf8b596528708f7d310569ab44c251377f7363a390c653965e0cb8dd217464b3d8f79c1",
            "b07d4c56fb83a49e8d9fc992e1230bb5086fecbd828cdbc7353f61b1a3cec0baf9c5bf67c9da06b49469a999ba3b37916ec125be"
        )]
        [InlineData(
            "e7d8148613049bdefab4482a44e7bdcb5edc5dad3ed8449117d6d97445db0b23",
            "38ecdfc1d303757d663c3e9a",
            "9efab614388a7d99102bcc901e3623d31fd9dd9d3c3338d086f69c13e7aa8653f9ce76e722e5a6a8cbbbee067a6cb9c59aa9b4b4c518bbed",
            "829d9fe74b7a4b3aeb04580b41d38a156ffbebba5d49ad55d1b0370f25abcd41221304941ad8e0d5095e15fbd839295bf1e7a509a807c005"
        )]
        [InlineData(
            "74e7fc53bf534b9a3441615f1494c3a3727ca0a81123249399ecae435aeb6d21",
            "1c52e2c7b4995479d76c94c7",
            "03b5d7ab4bd8c9a4f47ec122cbeb595bd1a0d58de3bb3dcc66c4e288f29622d6863e846fdfb27a90740feb03a4761c6017250bc0f129cc65d19680ab9d6970",
            "83db55d9eb441a909268311da67d432c732ad6bda0a0dae710d1bce040b91269deb558a68ced4aa5760ca0b9c5efc84e725f297bdbdadbc368bea4e20261c5"
        )]
        [InlineData(
            "393e211f141d26562c7cfc15c5ccfe21c58456a9060560266bc0dcdab010c8f2",
            "a1f0411d78773b7ca5ee9169",
            "2f4da518578a2a82c8c855155645838ca431cdf35d9f8562f256746150580ca1c74f79b3e9ae78224573da8b47a4b3cc63fbed8d4e831a6b4d796c124d87c78a66e5",
            "6fc086ded3d1d5566577ccd9971e713c1126ec52d3894f09ab701116c7b5abda959cbb207f4468eb7b6a6b7e1b6d2bc6047f337499d63522f256ee751b91f84f70b6"
        )]
        public void ProcessBytes_returns_encrypted_bytes(string keyHex, string nonceHex, string inputHex, string expectedHex)
        {
            var input = inputHex.DecodeHex();
            var size = input.Length;
            var output = new byte[size];
            new ChaCha20(keyHex.DecodeHex(), nonceHex.DecodeHex()).ProcessBytes(input, 0, size, output, 0);

            Assert.Equal(expectedHex.DecodeHex(), output);
        }

        [Fact]
        public void ProcessBytes_works_correctly_with_any_length()
        {
            var input = "f518831fab69c054a6".DecodeHex();
            var expected = "cfe40f63f81391484b".DecodeHex();

            for (var size = 0; size < input.Length; ++size)
            {
                var output = new byte[size];
                new ChaCha20(
                    "254c12e973a3d14fbbf7457964f0d5ee5d18c42913cf9a3c67a3944c532c2c7c".DecodeHex(),
                    "496b2a516daff98da5a23653".DecodeHex()
                ).ProcessBytes(input.Sub(0, size), 0, size, output, 0);

                Assert.Equal(expected.Sub(0, size), output);
            }
        }

        [Fact]
        public void ProcessBytes_respects_input_offset_and_size()
        {
            var input = "f518831fab69c054a6".DecodeHex();
            var expected = "cfe40f63f81391484b".DecodeHex();

            for (var padding = 0; padding < 64; ++padding)
            {
                var actualInput = new byte[padding]
                    .Concat(input)
                    .ToArray();
                for (var size = 0; size < input.Length; ++size)
                {
                    var output = new byte[size];
                    new ChaCha20(
                        "254c12e973a3d14fbbf7457964f0d5ee5d18c42913cf9a3c67a3944c532c2c7c".DecodeHex(),
                        "496b2a516daff98da5a23653".DecodeHex()
                    ).ProcessBytes(actualInput, padding, size, output, 0);

                    Assert.Equal(expected.Sub(0, size), output);
                }
            }
        }

        [Fact]
        public void ProcessBytes_respects_output_offset()
        {
            var input = "f518831fab69c054a6".DecodeHex();
            var expected = "cfe40f63f81391484b".DecodeHex();

            for (var padding = 0; padding < 64; ++padding)
            {
                var output = new byte[padding + input.Length];
                new ChaCha20(
                    "254c12e973a3d14fbbf7457964f0d5ee5d18c42913cf9a3c67a3944c532c2c7c".DecodeHex(),
                    "496b2a516daff98da5a23653".DecodeHex()
                ).ProcessBytes(input, 0, input.Length, output, padding);

                Assert.Equal(new byte[padding].Concat(expected), output);
            }
        }

        [Theory]
        [InlineData(0, 1, 0)]
        [InlineData(0, 0, 1)]
        [InlineData(1, 1, 1)]
        [InlineData(13, 6, 8)]
        [InlineData(13, 8, 6)]
        [InlineData(13, -1, 0)]
        [InlineData(13, 0, -1)]
        [InlineData(13, 1337, 0)]
        [InlineData(13, 0, 1337)]
        [InlineData(13, 1337, 1337)]
        public void ProcessBytes_throws_on_invalid_input_buffer_size_offset(int bufferSize, int offset, int size)
        {
            Exceptions.AssertThrowsInternalError(
                () => new ChaCha20(new byte[32], new byte[12]).ProcessBytes(new byte[bufferSize], offset, size, new byte[Math.Max(0, size)], 0),
                "Input buffer is too short"
            );
        }

        [Theory]
        [InlineData(0, 1, 0)]
        [InlineData(0, 0, 1)]
        [InlineData(1, 1, 1)]
        [InlineData(13, 6, 8)]
        [InlineData(13, 8, 6)]
        [InlineData(13, -1, 0)]
        [InlineData(13, 1337, 0)]
        [InlineData(13, 0, 1337)]
        [InlineData(13, 1337, 1337)]
        public void ProcessBytes_throws_on_invalid_output_buffer_size_offset(int bufferSize, int offset, int size)
        {
            Exceptions.AssertThrowsInternalError(
                () => new ChaCha20(new byte[32], new byte[12]).ProcessBytes(new byte[size], 0, size, new byte[bufferSize], offset),
                "Output buffer is too short"
            );
        }
    }
}
