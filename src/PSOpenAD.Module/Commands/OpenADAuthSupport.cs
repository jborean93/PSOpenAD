using System.Management.Automation;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsCommon.Get, "OpenADAuthSupport"
)]
[OutputType(typeof(AuthenticationProvider))]
public class GetOpenADAuthSupport : PSCmdlet
{
    protected override void EndProcessing()
    {
        foreach (AuthenticationProvider provider in GlobalState.GetFromTLS().Providers.Values)
            WriteObject(provider);
    }
}
