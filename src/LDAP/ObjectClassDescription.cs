using System;
using System.Collections.Generic;
using System.Text;

namespace PSOpenAD.LDAP;

/// <summary>The object class kind.</summary>
public enum ObjectClassKind
{
    /// <summary>Abstract object class.</summary>
    Abstract,

    /// <summary>Structural object class.</summary>
    Structural,

    /// <summary>Auxiliary object class.</summary>
    Auxiliary,
}

/// <summary>Definition of an object class.</summary>
/// <remarks>
/// The ABNF notation of an ObjectClassDescription is:
///     ObjectClassDescription = LPAREN WSP
///         numericoid                 ; object identifier
///         [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
///         [ SP "DESC" SP qdstring ]  ; description
///         [ SP "OBSOLETE" ]          ; not active
///         [ SP "SUP" SP oids ]       ; superior object classes
///         [ SP kind ]                ; kind of class
///         [ SP "MUST" SP oids ]      ; attribute types
///         [ SP "MAY" SP oids ]       ; attribute types
///         extensions WSP RPAREN
///
///     kind = "ABSTRACT" / "STRUCTURAL" / "AUXILIARY"
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.1">RFC 4512 4.1.1. Object Class Definitions</see>
public class ObjectClassDescription
{
    /// <summary>The object identifier assigned to this object class.</summary>
    public string OID { get; set; }

    /// <summary>Short names (descriptors) identifying this object class.</summary>
    public string[] Names { get; set; } = Array.Empty<string>();

    /// <summary>The short descriptive string.</summary>
    public string? Description { get; set; }

    /// <summary>Indicates this object class is not active.</summary>
    public bool Obsolete { get; set; }

    /// <summary>The OID that specifies the direct superclass of this object class.</summary>
    public string[] SuperTypes { get; set; } = Array.Empty<string>();

    /// <summary>The kind of the object class.</summary>
    public ObjectClassKind Kind { get; set; }

    /// <summary>Set of required attribute types.</summary>
    public string[] Must { get; set; } = Array.Empty<string>();

    /// <summary>Set of allowed attribute types.</summary>
    public string[] May { get; set; } = Array.Empty<string>();

    /// <summary>Custom extensions of this object class.</summary>
    public Dictionary<string, string[]> Extensions { get; set; } = new();

    public ObjectClassDescription(string definition)
    {
        ReadOnlySpan<char> data = definition.AsSpan();
        if (data.Length < 2 || data[0] != '(')
        {
            throw new FormatException("Invalid ObjectClassDescription value does not start with '('");
        }
        data = data[1..];

        AbnfDecoder.TryParseWSP(data, out var _, out var read);
        data = data[read..];

        if (!AbnfDecoder.TryParseNumericOid(data, out var numericOid, out read))
        {
            throw new FormatException("Invalid ObjectClassDescription value has no numericoid value");
        }
        OID = numericOid;
        data = data[read..];

        List<(string, TryReadOptionalField)> fields = new()
        {
            ("NAME", TryReadNameField),
            ("DESC", TryReadDescField),
            ("OBSOLETE", TryReadObsoleteField),
            ("SUP", TryReadSupField),
            ("ABSTRACT", TryReadAbstractField),
            ("STRUCTURAL", TryReadStructuralField),
            ("AUXILIARY", TryReadAuxiliaryField),
            ("MUST", TryReadMustField),
            ("MAY", TryReadMayField),
        };
        foreach ((string field, TryReadOptionalField reader) in fields)
        {
            if (!AbnfDecoder.TryParseSP(data, out var _, out read))
            {
                break;
            }

            if (data[read..].StartsWith(field))
            {
                data = data[read..];

                if (reader(data[field.Length..], out read))
                {
                    data = data[(field.Length + read)..];
                }
                else
                {
                    throw new FormatException($"Invalid ObjectClassDescription {field} value is invalid");
                }
            }
        }

        AbnfDecoder.TryParseExtensions(data, out var parsedExtensions, out read);
        if (read > 0)
        {
            Extensions = parsedExtensions;
            data = data[read..];
        }

        AbnfDecoder.TryParseWSP(data, out var _, out read);
        data = data[read..];

        if (data.Length != 1 || data[0] != ')')
        {
            throw new FormatException("Invalid ObjectClassDescription value does not end with ')'");
        }
    }

    public override string ToString()
    {
        StringBuilder sb = new StringBuilder();
        sb.Append($"( {OID}");

        if (Names.Length == 1)
        {
            sb.Append($" NAME '{Names[0]}'");
        }
        else if (Names.Length > 1)
        {
            string names = string.Join("' '", Names);
            sb.Append($" NAME ( '{names}' )");
        }

        if (!string.IsNullOrWhiteSpace(Description))
        {
            string desc = AbnfEncoder.EncodeQDString(Description);
            sb.Append($" DESC {desc}");
        }

        if (Obsolete)
        {
            sb.Append(" OBSOLETE");
        }

        if (SuperTypes.Length > 0)
        {
            string value = AbnfEncoder.EncodeOids(SuperTypes);
            sb.Append($" SUP {value}");
        }

        switch (Kind)
        {
            case ObjectClassKind.Abstract:
                sb.Append(" ABSTRACT");
                break;

            case ObjectClassKind.Structural:
                sb.Append(" STRUCTURAL");
                break;

            case ObjectClassKind.Auxiliary:
                sb.Append(" AUXILIARY");
                break;
        }

        if (Must.Length > 0)
        {
            string value = AbnfEncoder.EncodeOids(Must);
            sb.Append($" MUST {value}");
        }

        if (May.Length > 0)
        {
            string value = AbnfEncoder.EncodeOids(May);
            sb.Append($" MAY {value}");
        }

        foreach (KeyValuePair<string, string[]> ext in Extensions)
        {
            string value = AbnfEncoder.EncodeQDStrings(ext.Value);
            sb.Append($" {ext.Key} {value}");
        }

        sb.Append(" )");
        return sb.ToString();
    }

    private delegate bool TryReadOptionalField(ReadOnlySpan<char> data, out int charConsumed);

    private bool TryReadNameField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;

        if (!AbnfDecoder.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (AbnfDecoder.TryParseQDescrs(data, out var names, out read))
        {
            Names = names;
            charConsumed += read;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadDescField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;

        if (!AbnfDecoder.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (AbnfDecoder.TryParseQDString(data, out var desc, out read))
        {
            Description = desc;
            charConsumed += read;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadObsoleteField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;
        Obsolete = true;
        return true;
    }

    private bool TryReadSupField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOidsField(data, out var oids, out charConsumed))
        {
            SuperTypes = oids;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadAbstractField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;
        Kind = ObjectClassKind.Abstract;
        return true;
    }

    private bool TryReadStructuralField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;
        Kind = ObjectClassKind.Structural;
        return true;
    }

    private bool TryReadAuxiliaryField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;
        Kind = ObjectClassKind.Auxiliary;
        return true;
    }

    private bool TryReadMustField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOidsField(data, out var oids, out charConsumed))
        {
            Must = oids;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadMayField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOidsField(data, out var oids, out charConsumed))
        {
            May = oids;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadOidsField(ReadOnlySpan<char> data, out string[] oids, out int charConsumed)
    {
        oids = Array.Empty<string>();
        charConsumed = 0;

        if (!AbnfDecoder.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (AbnfDecoder.TryParseOids(data, out oids, out read))
        {
            charConsumed += read;
            return true;
        }
        else
        {
            return false;
        }
    }
}
