using System;
using System.Text.RegularExpressions;

namespace PSOpenAD
{
    internal enum AttributeTypeUsage
    {
        Unknown,
        UserApplications,
        DirectoryOperation,
        DistributedOperation,
        DsaOperation,

    }

    internal class AttributeTypes
    {
        /*
        Regex to parse the ABNF defined at RFC 4512  4.1.2
        https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.2

        AttributeTypeDescription = LPAREN WSP
            numericoid                    ; object identifier
            [ SP "NAME" SP qdescrs ]      ; short names (descriptors)
            [ SP "DESC" SP qdstring ]     ; description
            [ SP "OBSOLETE" ]             ; not active
            [ SP "SUP" SP oid ]           ; supertype
            [ SP "EQUALITY" SP oid ]      ; equality matching rule
            [ SP "ORDERING" SP oid ]      ; ordering matching rule
            [ SP "SUBSTR" SP oid ]        ; substrings matching rule
            [ SP "SYNTAX" SP noidlen ]    ; value syntax
            [ SP "SINGLE-VALUE" ]         ; single-value
            [ SP "COLLECTIVE" ]           ; collective
            [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
            [ SP "USAGE" SP usage ]       ; usage
            extensions WSP RPAREN         ; extensions

        usage = "userApplications"     /  ; user
                "directoryOperation"   /  ; directory operational
                "distributedOperation" /  ; DSA-shared operational
                "dSAOperation"            ; DSA-specific operational
        */
        private const string SCHEMA_PATTERN = @"^\(\ *
(?<oid>[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)
(?:\ NAME\ (?:
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
(?:\ SUP\ (?:
    (?<supStr>[a-zA-Z][a-zA-Z0-9\-]*)
  |
    (?<supOid>[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)
  )
)?
(?:\ EQUALITY\ (?:
    (?<equalityStr>[a-zA-Z][a-zA-Z0-9\-]*)
  |
    (?<equalityOid>[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)
  )
)?
(?:\ ORDERING\ (?:
    (?<orderingStr>[a-zA-Z][a-zA-Z0-9\-]*)
  |
    (?<orderingOid>[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)
  )
)?
(?:\ SUBSTR\ (?:
    (?<substrStr>[a-zA-Z][a-zA-Z0-9\-]*)
  |
    (?<substrOid>[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)
  )
)?
# The RFC does not state the syntax is quoted but it is for AD
# I cannot find any references to this but it's needed to parse the value
(?:\ SYNTAX\ '?(?<syntax>[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*)'?
  (?:{(?<syntaxLen>\d+)})?
)?
(?:\ (?<singleValue>SINGLE-VALUE))?
(?:\ (?<collective>COLLECTIVE))?
(?:\ (?<noUserModification>NO-USER-MODIFICATION))?
(?:\ (?<usage>userApplications|directoryOperation|distributedOperation|dSAOperation))?
.*\)$";

        public string OID { get; set; }
        public string? Name { get; set; }
        public string? Description { get; set; }
        public bool Obsolete { get; set; }
        public string? SuperType { get; set; }
        public string? Equality { get; set; }
        public string? Ordering { get; set; }
        public string? Substrings { get; set; }
        public string? Syntax { get; set; }
        public int? SyntaxLength { get; set; }
        public bool SingleValue { get; set; }
        public bool Collective { get; set; }
        public bool NoUserModification { get; set; }
        public AttributeTypeUsage Usage { get; set; }

        public AttributeTypes(string definition)
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

            if (match.Groups["supStr"].Success)
                SuperType = match.Groups["supStr"].Value;
            else if (match.Groups["supOid"].Success)
                SuperType = match.Groups["supOid"].Value;

            if (match.Groups["equalityStr"].Success)
                Equality = match.Groups["equalityStr"].Value;
            else if (match.Groups["equalityOid"].Success)
                Equality = match.Groups["equalityOid"].Value;

            if (match.Groups["orderingStr"].Success)
                Ordering = match.Groups["orderingStr"].Value;
            else if (match.Groups["orderingOid"].Success)
                Ordering = match.Groups["orderingOid"].Value;

            if (match.Groups["substrStr"].Success)
                Substrings = match.Groups["substrStr"].Value;
            else if (match.Groups["substrOid"].Success)
                Substrings = match.Groups["substrOid"].Value;

            Syntax = match.Groups["syntax"].Success ? match.Groups["syntax"].Value : null;

            if (match.Groups["syntaxLen"].Success)
                SyntaxLength = Int32.Parse(match.Groups["syntaxLen"].Value);
            else
                SyntaxLength = null;

            SingleValue = match.Groups["singleValue"].Success;
            Collective = match.Groups["collective"].Success;
            NoUserModification = match.Groups["noUserModification"].Success;

            switch (match.Groups["usage"].Value)
            {
                case "directoryOperation":
                    Usage = AttributeTypeUsage.DirectoryOperation;
                    break;
                case "distributedOperation":
                    Usage = AttributeTypeUsage.DistributedOperation;
                    break;
                case "dSAOperation":
                    Usage = AttributeTypeUsage.DsaOperation;
                    break;
                default:
                    Usage = AttributeTypeUsage.UserApplications;
                    break;
            }
        }
    }
}
