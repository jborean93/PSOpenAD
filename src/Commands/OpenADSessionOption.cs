using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

namespace PSOpenAD.Commands
{
    [Cmdlet(
        VerbsCommon.New, "OpenADSessionOption"
    )]
    [OutputType(typeof(OpenADSessionOptions))]
    public class NewOpenADSessionOption : PSCmdlet
    {
        [Parameter()]
        public SwitchParameter NoEncryption { get; set; }

        [Parameter()]
        public SwitchParameter NoSigning { get; set; }

        [Parameter()]
        public SwitchParameter NoChannelBinding { get; set; }

        [Parameter()]
        public SwitchParameter SkipCertificateCheck { get; set; }

        protected override void EndProcessing()
        {
            WriteObject(new OpenADSessionOptions()
            {
                NoEncryption = NoEncryption,
                NoSigning = NoSigning,
                NoChannelBinding = NoChannelBinding,
                SkipCertificateCheck = SkipCertificateCheck,
            });
        }
    }
}
