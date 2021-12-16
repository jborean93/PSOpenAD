using System;
using System.Management.Automation;

namespace PSOpenAD.Commands
{
    public enum SearchScope
    {
        Base,
        OneLevel,
        Subtree,
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADObject",
        DefaultParameterSetName = "Identity"
    )]
    public class GetOpenADObject : PSCmdlet
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Identity"
        )]
        public string Identity { get; set; } = "";

        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "LDAPFilter"
        )]
        public string LDAPFilter { get; set; } = "";

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true
        )]
        public OpenADSession? Session { get; set; }

        [Parameter()]
        public string[] Property { get; set; } = Array.Empty<string>();

        [Parameter()]
        public string SearchBase { get; set; } = "";

        [Parameter()]
        public SearchScope SearchScope { get; set; } = SearchScope.Subtree;


        [Parameter()]
        public SwitchParameter IncludeDeletedObjects { get; set; }

        protected override void ProcessRecord()
        {
            WriteObject("Test");
        }
    }
}
