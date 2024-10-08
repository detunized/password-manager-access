namespace PasswordManagerAccess.LastPass
{
    // TODO: Rename to Options
    public class ParserOptions
    {
        public static ParserOptions Default { get; } = new ParserOptions();

        // When is is enabled the library attempts to convert the secure notes that look like accounts into accounts.
        // Other types of notes are discarded. If you want to have all the secure notes return in a form of accounts,
        // set this to false.
        public bool ParseSecureNotesToAccount { get; set; } = true;

        // When enabled the library will log the requests and responses to the ISecureLogger interface.
        // In addition to that when an exception is thrown, the log entries will be attached to the exception.
        public bool LoggingEnabled { get; set; } = false;
    }
}
