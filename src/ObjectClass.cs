using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace PSOpenAD;

internal enum ClassKind
{
    Inherited,
    Abstract,
    Structural,
    Auxiliary,
}

internal sealed class ObjectClassDefinition
{
    /*
    Regex to parse the ABNF defined at RFC 4512  4.1.1
    https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.1

    ObjectClassDescription = LPAREN WSP
        numericoid                 ; object identifier
        [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
        [ SP "DESC" SP qdstring ]  ; description
        [ SP "OBSOLETE" ]          ; not active
        [ SP "SUP" SP oids ]       ; superior object classes
        [ SP kind ]                ; kind of class
        [ SP "MUST" SP oids ]      ; attribute types
        [ SP "MAY" SP oids ]       ; attribute types
        extensions WSP RPAREN

    kind = "ABSTRACT" / "STRUCTURAL" / "AUXILIARY"
    */
    private const string SCHEMA_PATTERN = @"^\(\ *
(?<oid>[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)
(?:\ NAME\ (?:                          # Can be a single quoted string or a list inside ().
    '(?<name>[a-zA-Z][a-zA-Z0-9\-]*)'
  |
    \(\ *
      (?<nameList>
        '[a-zA-Z][a-zA-Z0-9\-]*'
        (?:\ '[a-zA-Z][a-zA-Z0-9\-]*')*
      )
    \ *\)
  )
)?
(?:\ DESC\ '(?<desc>[^']*)')?
(?:\ (?<obsolete>OBSOLETE))?
(?:\ SUP\ (?:                           # Can be a string, OID or list inside () of both separated by $
    (?<supStr>[a-zA-Z][a-zA-Z0-9\-]*)
  |
    \(\ *
      (?<supStrList>
        [a-zA-Z][a-zA-Z0-9\-]*
        (?:\ \$\ [a-zA-Z][a-zA-Z0-9\-]*)*
      )
    \ *\)
  |
    (?<supOid>[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)
  |
    \(\ *
      (?<supOidList>
        [0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*
        (?:\ \$\ [0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)*
      )
    \ *\)
  )
)?
(?:\ (?<kind>ABSTRACT|STRUCTURAL|AUXILIARY))?
(?:\ MUST\ (?:                          # Can be a string, OID or list inside () of both separated by $
    (?<mustStr>[a-zA-Z][a-zA-Z0-9\-]*)
  |
    \(\ *
      (?<mustStrList>
        [a-zA-Z][a-zA-Z0-9\-]*
        (?:\ \$\ [a-zA-Z][a-zA-Z0-9\-]*)*
      )
    \ *\)
  |
    (?<mustOid>[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)
  |
    \(\ *
      (?<mustOidList>
        [0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*
        (?:\ \$\ [0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)*
      )
    \ *\)
  )
)?
(?:\ MAY\ (?:                           # Can be a string, OID or list inside () of both separated by $
    (?<mayStr>[a-zA-Z][a-zA-Z0-9\-]*)
  |
    \(\ *
      (?<mayStrList>
        [a-zA-Z][a-zA-Z0-9\-]*
        (?:\ \$\ [a-zA-Z][a-zA-Z0-9\-]*)*
      )
    \ *\)
  |
    (?<mayOid>[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)
  |
    \(\ *
      (?<mayOidList>
        [0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*
        (?:\ \$\ [0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)*
      )
    \ *\)
  )
)?
# Technically there can be extensions but this isn't used by this library
.*\)$";

    public string OID { get; set; }
    public string? Name { get; set; }
    public string? Description { get; set; }
    public bool Obsolete { get; set; }
    public List<string> SuperClasses { get; } = new List<string>();
    public ClassKind Kind { get; set; }
    public List<string> Must { get; } = new List<string>();
    public List<string> May { get; } = new List<string>();

    public ObjectClassDefinition(string definition)
    {
        Match match = Regex.Match(definition, SCHEMA_PATTERN,
            RegexOptions.Compiled | RegexOptions.IgnorePatternWhitespace);
        if (!match.Success)
            throw new ArgumentException("Failed to decode objectClasses definition");

        OID = match.Groups["oid"].Value;

        if (match.Groups["name"].Success)
        {
            Name = match.Groups["name"].Value;
        }
        else if (match.Groups["nameList"].Success)
        {
            Name = match.Groups["nameList"].Value.Trim('\'').Split("' '")[0];
        }

        Description = match.Groups["desc"].Success ? match.Groups["desc"].Value : null;
        Obsolete = match.Groups["obsolete"].Success;

        switch (match.Groups["kind"].Value)
        {
            case "ABSTRACT":
                Kind = ClassKind.Abstract;
                break;
            case "STRUCTURAL":
                Kind = ClassKind.Structural;
                break;
            case "AUXILIARY":
                Kind = ClassKind.Auxiliary;
                break;
            default:
                Kind = ClassKind.Inherited;
                break;
        }

        SuperClasses = ParseOidList(match, "sup");
        Must = ParseOidList(match, "must");
        May = ParseOidList(match, "may");
    }

    private static List<string> ParseOidList(Match match, string id)
    {
        string stringSingleId = $"{id}Str";
        string oidSingleId = $"{id}Oid";
        string stringListId = $"{id}StrList";
        string oidListId = $"{id}OidList";

        if (match.Groups[stringSingleId].Success)
        {
            return new List<string>() { match.Groups[stringSingleId].Value };
        }
        else if (match.Groups[oidSingleId].Success)
        {
            return new List<string>() { match.Groups[oidSingleId].Value };
        }
        else if (match.Groups[stringListId].Success)
        {
            return match.Groups[stringListId].Value.Split(" $ ").ToList();
        }
        else if (match.Groups[oidListId].Success)
        {
            return match.Groups[oidListId].Value.Split(" $ ").ToList();
        }
        else
        {
            return new List<string>();
        }
    }
}
