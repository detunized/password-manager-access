using NUnit.Framework;

namespace LastPass.Test
{
    [TestFixture]
    class ParserTest
    {
        [Test]
        public void Parser_doesnt_throw()
        {
            Parser.Parse(new Blob(TestData.Blob, 1));
        }
    }
}
