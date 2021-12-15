using System;

using System.Management.Automation;

namespace PSOpenAD.Commands
{
    public class OpenADClientInfo
    {
        public bool SupportsChannelBindings => ClientCapabilities.SupportsChannelBindings;
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADClientInfo"
    )]
    [OutputType(typeof(OpenADClientInfo))]
    public class GetOpenADClientInfo : PSCmdlet
    {
        protected override void EndProcessing()
        {
            WriteObject(new OpenADClientInfo());
        }
    }
}
