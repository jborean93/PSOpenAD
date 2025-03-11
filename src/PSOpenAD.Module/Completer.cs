using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Management.Automation;
using System.Management.Automation.Language;

namespace PSOpenAD.Module;

internal class ServerCompleter : IArgumentCompleter
{
    public IEnumerable<CompletionResult> CompleteArgument(string commandName, string parameterName,
        string wordToComplete, CommandAst commandAst, IDictionary fakeBoundParameters)
    {
        if (string.IsNullOrWhiteSpace(wordToComplete))
            wordToComplete = "";

        HashSet<Uri> emitted = new();
        foreach (OpenADSession session in GlobalState.GetFromTLS().Sessions)
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
        if (string.IsNullOrWhiteSpace(wordToComplete))
            wordToComplete = "";

        string className = GetClassNameForCommand(commandName);

        HashSet<string>? classAttributes = GlobalState.GetFromTLS().SchemaMetadata?.GetClassAttributesInformation(className);
        if (classAttributes != null)
        {
            foreach (string attribute in classAttributes)
            {
                if (attribute.StartsWith(wordToComplete, true, CultureInfo.InvariantCulture))
                {
                    yield return new CompletionResult(attribute);
                }
            }
        }
    }

    /// <summary>Get the object class used for the cmdlet attribute validation.</summary>
    /// <remarks>
    /// This is not perfect as most cmdlets filter by an objectCategory which can be more specific than an
    /// objectCategory. Unfortunately the schema metadata doesn't dontain the data required to build a mapping of
    /// objectCategory and the valid attributes so we use the next best thing. An example of where this doesn't work
    /// as well as I would like is for the "person" class. The Get-OpenADUser cmdlet filters by
    /// '(objectCategory=person)' which excludes computer objects. The computer object class is a subtype of the person
    /// object class which means attributes that are only valid for computers will be returned. Not even the AD cmdlets
    /// check for this so it's a best effort attempt.
    /// </remarks>
    /// <returns>The objectClass that is used for the cmdlet.</returns>
    public static string GetClassNameForCommand(string command) => command switch
    {
        "Get-OpenADComputer" => "computer",
        "Get-OpenADUser" => "person",
        "Get-OpenADGroup" => "group",
        "Get-OpenADGroupMember" => "person",
        "Get-OpenADServiceAccount" => "msDS-GroupManagedServiceAccount",
        _ => "top",
    };
}
