// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace PasswordBox
{
    class SjclAes
    {
        private static readonly byte[] SboxTable;
        private static readonly byte[] InverseSboxTable;
        private static readonly uint[,] EncodeTable;
        private static readonly uint[,] DecodeTable;

        private readonly uint[] _encryptionKey;
        private readonly uint[] _decryptionKey;

        static SjclAes()
        {
            var doubleTable = ComputeDoubleTable();
            var trippleTable = ComputeTrippleTable(doubleTable);
            SboxTable = ComputeSboxTable(doubleTable, trippleTable);
            InverseSboxTable = ComputeInverseSboxTable(SboxTable);
            EncodeTable = ComputeEncodeTable(doubleTable, SboxTable);
            DecodeTable = ComputeDecodeTable(doubleTable, SboxTable);
        }

        public SjclAes(byte[] key)
        {
            _encryptionKey = ScheduleEncryptionKey(key, SboxTable);
            _decryptionKey = ScheduleDecryptionKey(_encryptionKey, SboxTable, DecodeTable);
        }

        public SjclQuad Encrypt(SjclQuad plaintext)
        {
            return Crypt(plaintext, true);
        }

        public SjclQuad Decrypt(SjclQuad ciphertext)
        {
            return Crypt(ciphertext, false);
        }

        private SjclQuad Crypt(SjclQuad input, bool encrypting)
        {
            var key = encrypting ? _encryptionKey : _decryptionKey;

            var a = input[                 0] ^ key[0];
            var b = input[encrypting ? 1 : 3] ^ key[1];
            var c = input[                 2] ^ key[2];
            var d = input[encrypting ? 3 : 1] ^ key[3];

            var innerRoundCount = key.Length / 4 - 2;
            var keyIndex = 4;
            var table = encrypting ? EncodeTable : DecodeTable;
            var sbox = encrypting ? SboxTable : InverseSboxTable;

            var output = new SjclQuad(0, 0, 0, 0);

            // Inner rounds
            for (var i = 0; i < innerRoundCount; i++)
            {
                var a2 = (table[0, (a >> 24)      ]) ^
                         (table[1, (b >> 16) & 255]) ^
                         (table[2, (c >>  8) & 255]) ^
                         (table[3, (d      ) & 255]) ^
                         (key[keyIndex]            );

                var b2 = (table[0, (b >> 24)      ]) ^
                         (table[1, (c >> 16) & 255]) ^
                         (table[2, (d >>  8) & 255]) ^
                         (table[3, (a      ) & 255]) ^
                         (key[keyIndex + 1]        );

                var c2 = (table[0, (c >> 24)      ]) ^
                         (table[1, (d >> 16) & 255]) ^
                         (table[2, (a >>  8) & 255]) ^
                         (table[3, (b      ) & 255]) ^
                         (key[keyIndex + 2]        );

                var d2 = (table[0, (d >> 24)      ]) ^
                         (table[1, (a >> 16) & 255]) ^
                         (table[2, (b >>  8) & 255]) ^
                         (table[3, (c      ) & 255]) ^
                         (key[keyIndex + 3]        );

                a = a2;
                b = b2;
                c = c2;
                d = d2;

                keyIndex += 4;
            }

            // Last round
            for (var i = 0; i < 4; i++)
            {
                var index = encrypting ? i : 3 & -i;
                output[index] = ((uint)sbox[(a >> 24)      ] << 24) ^
                                ((uint)sbox[(b >> 16) & 255] << 16) ^
                                ((uint)sbox[(c >>  8) & 255] <<  8) ^
                                ((uint)sbox[(d      ) & 255]      ) ^
                                (key[keyIndex]                    );
                var t = a;
                a = b;
                b = c;
                c = d;
                d = t;

                ++keyIndex;
            }

            return output;
        }

        internal static byte[] ComputeDoubleTable()
        {
            var table = new byte[256];
            for (var i = 0; i < 256; ++i)
                table[i] = (byte)((i << 1) ^ (i >> 7) * 283);

            return table;
        }

        internal static byte[] ComputeTrippleTable(byte[] doubleTable)
        {
            var table = new byte[256];
            for (var i = 0; i < 256; ++i)
                table[doubleTable[i] ^ i] = (byte)i;

            return table;
        }

        internal static byte[] ComputeSboxTable(byte[] doubleTable, byte[] trippleTable)
        {
            var table = new byte[256];

            var x = 0;
            var x2 = 0;
            var xInv = 0;

            for (var i = 0; i < 256; ++i)
            {
                var s = xInv ^ (xInv << 1) ^ (xInv << 2) ^ (xInv << 3) ^ (xInv << 4);
                table[x] = (byte)((s >> 8) ^ (s & 255) ^ 99);

                x2 = Math.Max((int)doubleTable[x], 1);
                xInv = Math.Max((int)trippleTable[xInv], 1);
                x ^= x2;
            }

            return table;
        }

        internal static byte[] ComputeInverseSboxTable(byte[] sboxTable)
        {
            var table = new byte[256];
            for (var i = 0; i < 256; ++i)
                table[sboxTable[i]] = (byte)i;

            return table;
        }

        internal static uint[,] ComputeEncodeTable(byte[] doubleTable, byte[] sboxTable)
        {
            var table = new uint[4, 256];
            uint x = 0;

            for (var i = 0; i < 256; ++i)
            {
                uint s = sboxTable[x];
                uint enc = ((uint)doubleTable[s] * 0x101) ^ (s * 0x1010100);

                for (var j = 0; j < 4; ++j)
                {
                    enc = (enc << 24) ^ (enc >> 8);
                    table[j, x] = enc;
                }

                x ^= Math.Max((uint)doubleTable[x], 1);
            }

            return table;
        }

        internal static uint[,] ComputeDecodeTable(byte[] doubleTable, byte[] sboxTable)
        {
            var table = new uint[4, 256];
            uint x = 0;

            for (var i = 0; i < 256; ++i)
            {
                uint x2 = doubleTable[x];
                uint x4 = doubleTable[x2];
                uint x8 = doubleTable[x4];
                uint dec = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);

                for (var j = 0; j < 4; ++j)
                {
                    dec = (dec << 24) ^ (dec >> 8);
                    table[j, sboxTable[x]] = dec;
                }

                x ^= Math.Max(x2, 1);
            }

            return table;
        }

        internal static uint[] ScheduleEncryptionKey(byte[] key, byte[] sboxTable)
        {
            var keyLength = key.Length;
            if (keyLength != 16 && keyLength != 24 && keyLength != 32)
                throw new Exception(string.Format("Invalid key length ({0})", keyLength)); // TODO: Use custom exception!

            var keyLength4 = keyLength / 4;
            var encKeyLength = keyLength4 * 4 + 28;
            var encKey = new uint[encKeyLength];
            uint rcon = 1;

            for (var i = 0; i < keyLength4; ++i)
                encKey[i] = BitConverter.ToUInt32(key, i * 4).FromBigEndian();

            for (var i = keyLength4; i < encKeyLength; ++i)
            {
                var t = encKey[i - 1];

                // Apply sbox
                if (i % keyLength4 == 0 || (keyLength4 == 8 && i % keyLength4 == 4))
                {
                    t = (uint)((sboxTable[(t >> 24)      ] << 24) ^
                               (sboxTable[(t >> 16) & 255] << 16) ^
                               (sboxTable[(t >>  8) & 255] <<  8) ^
                               (sboxTable[(t      ) & 255]      ));

                    // Shift rows and add rcon
                    if (i % keyLength4 == 0)
                    {
                        t = (t << 8) ^ (t >> 24) ^ (rcon << 24);
                        rcon = (rcon << 1) ^ (rcon >> 7) * 283;
                    }
                }

                encKey[i] = encKey[i - keyLength4] ^ t;
            }

            return encKey;
        }

        internal static uint[] ScheduleDecryptionKey(uint[] encKey, byte[] sboxTable, uint[,] decodeTable)
        {
            var decKey = new uint[encKey.Length];

            var i = encKey.Length;
            for (var j = 0; i != 0; ++j, --i)
            {
                var t = encKey[(j & 3) != 0 ? i : i - 4];
                if (i <= 4 || j < 4)
                {
                    decKey[j] = t;
                }
                else
                {
                    decKey[j] = decodeTable[0, sboxTable[(t >> 24)      ]] ^
                                decodeTable[1, sboxTable[(t >> 16) & 255]] ^
                                decodeTable[2, sboxTable[(t >>  8) & 255]] ^
                                decodeTable[3, sboxTable[(t      ) & 255]];
                }
            }

            return decKey;
        }

        internal static SjclQuad[] ToQuads(uint[] abcds)
        {
            if (abcds.Length % 4 != 0)
                throw new ArgumentException("Length must be a multiple of 4", "abcds");

            var quads = new SjclQuad[abcds.Length / 4];
            for (var i = 0; i < quads.Length; ++i)
                quads[i] = new SjclQuad(abcds, i * 4);

            return quads;
        }
    }
}
