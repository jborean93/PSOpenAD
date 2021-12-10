using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PSOpenAD
{
    public class TemporaryEnvironment : IDisposable
    {
        [DllImport("libc")]
        private static extern void setenv(string name, string value);

        [DllImport("libc")]
        private static extern void unsetenv(string name);

        private Dictionary<string, string> Environment { get; set; }

        public TemporaryEnvironment(Dictionary<string, string> environment)
        {
            Environment = environment;

            foreach (KeyValuePair<string, string> kvp in Environment)
                setenv(kvp.Key, kvp.Value);
        }

        public void Dispose()
        {
            foreach (KeyValuePair<string, string> kvp in Environment)
                unsetenv(kvp.Key);

            GC.SuppressFinalize(this);
        }

        ~TemporaryEnvironment()
        {
            Dispose();
        }
    }
}
