using System.Collections.Generic;

namespace PSOpenAD;

/// <summary>
/// Drives the page-by-page decision logic used to complete a range-limited multivalued
/// attribute, without performing any of the searching itself. AD truncates a multivalued
/// attribute at MaxValRange and renames it in the response (member becomes
/// "member;range=0-1499"); this accumulator decides what to request next and when to stop
/// - recognizing the final page, stopping on a missing or empty page, and the runaway-
/// server guard - so those decisions are unit-testable without a live directory. The
/// caller performs each follow-up search itself and feeds the result back through
/// AddPage.
/// </summary>
internal sealed class RangedAttributeAccumulator
{
    /// <summary>Stops requesting further pages from a server that never sends a final one.</summary>
    public const int MaxPages = 1000;

    private readonly List<byte[]> _values;
    private int _high;
    private int _pagesRequested;

    /// <summary>The plain attribute name, with any range option stripped.</summary>
    public string BaseName { get; }

    /// <summary>True once the final page has been seen, or paging has stopped for any other reason.</summary>
    public bool IsComplete { get; private set; }

    /// <summary>True while another follow-up request should be issued.</summary>
    public bool NeedsNextPage => !IsComplete && _pagesRequested < MaxPages;

    /// <summary>All values accumulated so far.</summary>
    public byte[][] Values => _values.ToArray();

    public RangedAttributeAccumulator(string baseName, byte[][] firstPageValues, int high, bool isFinal)
    {
        BaseName = baseName;
        _values = new List<byte[]>(firstPageValues);
        _high = high;
        IsComplete = isFinal;
    }

    /// <summary>The attribute name to request next, e.g. "member;range=1500-*".</summary>
    public string NextRequest()
    {
        _pagesRequested++;
        return RangedAttribute.NextRequest(BaseName, _high);
    }

    /// <summary>
    /// Feeds back the result of the follow-up request. Pass null for pageName when the
    /// server returned no attribute matching BaseName at all. Stops paging - without error,
    /// exactly as a genuine final page would - on a missing page or one carrying zero
    /// values.
    /// </summary>
    public void AddPage(string? pageName, byte[][]? pageValues)
    {
        if (pageName is null || pageValues is null || pageValues.Length == 0)
        {
            IsComplete = true;
            return;
        }

        _values.AddRange(pageValues);

        if (RangedAttribute.TryParse(pageName, out _, out _, out _high, out bool isFinal))
        {
            IsComplete = isFinal;
        }
        else
        {
            // The caller only ever passes back a name it already matched via TryParse
            // when it located the page, so this shouldn't happen. Stop rather than loop.
            IsComplete = true;
        }
    }
}
