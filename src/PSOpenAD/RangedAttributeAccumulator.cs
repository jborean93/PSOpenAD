using System.Collections.Generic;

namespace PSOpenAD;

/// <summary>
/// Drives the page-by-page decisions for completing a range-limited multivalued attribute
/// (AD renames member to "member;range=0-1499" once it truncates at MaxValRange). The
/// caller performs each follow-up search and feeds the result back through AddPage.
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

    /// <summary>True once the final page has been seen. False if paging stopped for any other reason, including MaxPages.</summary>
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
