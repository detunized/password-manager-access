namespace LastPass
{
    class Session
    {
        public Session(string id, int keyIterationCount)
        {
            Id = id;
            KeyIterationCount = keyIterationCount;
        }

        public string Id { get; private set; }
        public int KeyIterationCount { get; private set; }
    }
}