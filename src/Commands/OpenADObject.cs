using System;
using System.Management.Automation;

namespace PSOpenAD.Commands
{
    [Cmdlet(
        VerbsCommon.Get, "OpenADObject"
    )]
    public class GetOpenADObject : PSCmdlet
    {
        protected override void ProcessRecord()
        {
            WriteObject("Test");
        }
    }
}
