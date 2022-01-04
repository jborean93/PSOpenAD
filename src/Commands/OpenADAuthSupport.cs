using System;
using System.Formats.Asn1;
using System.Management.Automation;

namespace PSOpenAD.Commands
{
    [Cmdlet(
        VerbsCommon.Get, "OpenADAuthSupport"
    )]
    [OutputType(typeof(AuthenticationProvider))]
    public class GetOpenADAuthSupport : PSCmdlet
    {
        protected override void EndProcessing()
        {
            foreach (AuthenticationProvider provider in GlobalState.Providers.Values)
                WriteObject(provider);
        }
    }
}
