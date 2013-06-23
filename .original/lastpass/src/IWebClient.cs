using System.Collections.Specialized;

namespace LastPass
{
    public interface IWebClient
    {
        byte[] UploadValues(string address, NameValueCollection data);
    }
}