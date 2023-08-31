using System;
using System.Management.Automation;
using System.Security.Cryptography.X509Certificates;

namespace PSOpenAD.Module.Commands;

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

    [Parameter()]
    public Int32 ConnectTimeout { get; set; } = 180000;

    [Parameter()]
    public Int32 OperationTimeout { get; set; } = 180000;

    [Parameter()]
    public string? TracePath { get; set; }

    [Parameter()]
    public X509Certificate? ClientCertificate { get; set; }

    protected override void EndProcessing()
    {
        string? tracePath = null;
        if (!string.IsNullOrWhiteSpace(TracePath))
        {
            tracePath = GetUnresolvedProviderPathFromPSPath(TracePath);
        }

        WriteObject(new OpenADSessionOptions()
        {
            NoEncryption = NoEncryption,
            NoSigning = NoSigning,
            NoChannelBinding = NoChannelBinding,
            SkipCertificateCheck = SkipCertificateCheck,
            ConnectTimeout = ConnectTimeout,
            OperationTimeout = OperationTimeout,
            TracePath = tracePath,
            ClientCertificate = ClientCertificate,
        });
    }
}
