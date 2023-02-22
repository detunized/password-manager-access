namespace PasswordManagerAccess.LastPass
{
    public class ParserOptions
    {
        public static ParserOptions Default { get; } = new ParserOptions();

        // When is is enabled the library attempts to convert the secure notes that look like accounts into accounts.
        // Other types of notes are discarded. If you want to have all the secure notes return in a form of accounts,
        // set this to false.
        public bool ParseSecureNotesToAccount { get; set; } = true;
    }
}
