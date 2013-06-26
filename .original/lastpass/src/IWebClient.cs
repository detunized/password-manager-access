using System.Collections.Specialized;
using System.Net;

namespace LastPass
{
    public interface IWebClient
    {
        byte[] UploadValues(string address, NameValueCollection data);
        byte[] DownloadData(string address);
        WebHeaderCollection Headers { get; }
    }
}