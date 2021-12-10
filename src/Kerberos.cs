using System;
using System.Collections;
using System.Diagnostics;

namespace PSOpenAD
{
    public static class Kerberos
    {
        public static void Kinit(string username, string password, string ccname)
        {
            ProcessStartInfo psi = new ProcessStartInfo()
            {
                FileName = "kinit",
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.ArgumentList.Add(username);
            psi.Environment["KRB5CCNAME"] = ccname;
            foreach (DictionaryEntry kvp in Environment.GetEnvironmentVariables())
                psi.Environment[(string)kvp.Key] = kvp.Value?.ToString() ?? "";

            Process proc = Process.Start(psi);
            proc.StandardInput.WriteLine(password);

            proc.WaitForExit();
        }
    }
}
