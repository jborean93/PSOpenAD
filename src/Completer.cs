using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Language;

namespace PSOpenAD;

internal class ServerCompleter : IArgumentCompleter
{
    public IEnumerable<CompletionResult> CompleteArgument(string commandName, string parameterName,
        string wordToComplete, CommandAst commandAst, IDictionary fakeBoundParameters)
    {
        if (String.IsNullOrWhiteSpace(wordToComplete))
            wordToComplete = "";

        HashSet<Uri> emitted = new();
        foreach (OpenADSession session in GlobalState.Sessions)
        {
            if ((session.Uri.ToString().StartsWith(wordToComplete, true, CultureInfo.InvariantCulture) ||
                session.Uri.Host.StartsWith(wordToComplete, true, CultureInfo.InvariantCulture)) &&
                emitted.Add(session.Uri))
            {
                yield return new CompletionResult(session.Uri.ToString());
            }
        }
    }
}

internal class PropertyCompleter : IArgumentCompleter
{
    public IEnumerable<CompletionResult> CompleteArgument(string commandName, string parameterName,
        string wordToComplete, CommandAst commandAst, IDictionary fakeBoundParameters)
    {
        if (String.IsNullOrWhiteSpace(wordToComplete))
            wordToComplete = "";

        string className;
        switch (commandName)
        {
            case "Get-OpenADComputer":
                className = "computer";
                break;

            case "Get-OpenADUser":
                className = "person";
                break;

            case "Get-OpenADGroup":
                className = "group";
                break;

            case "Get-OpenADServiceAccount":
                className = "msDS-GroupManagedServiceAccount";
                break;

            default:
                className = "top";
                break;
        }

        if (GlobalState.ClassDefintions.ContainsKey(className))
        {
            ObjectClass info = GlobalState.ClassDefintions[className];
            foreach (string must in info.Must)
            {
                if (must.StartsWith(wordToComplete, true, CultureInfo.InvariantCulture))
                {
                    yield return new CompletionResult(must);
                }
            }

            foreach (string may in info.May)
            {
                if (may.StartsWith(wordToComplete, true, CultureInfo.InvariantCulture))
                {
                    yield return new CompletionResult(may);
                }
            }
        }
    }
}
