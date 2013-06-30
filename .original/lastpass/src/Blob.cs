namespace LastPass
{
    public class Blob
    {
        public Blob(byte[] bytes, byte[] encryptionKey)
        {
            Bytes = bytes;
            EncryptionKey = encryptionKey;
        }

        public byte[] Bytes { get; private set; }
        public byte[] EncryptionKey { get; private set; }
    }
}