namespace LastPass
{
    public class Blob
    {
        public Blob(byte[] bytes, int keyIterationCount)
        {
            Bytes = bytes;
            KeyIterationCount = keyIterationCount;
        }

        public byte[] Bytes { get; private set; }
        public int KeyIterationCount { get; private set; }
    }
}