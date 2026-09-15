using PSOpenAD.LDAP;
using System;
using System.Formats.Asn1;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class SecurityDescriptorFlagsControlTests
{
    [Test]
    public async Task ControlTypeIsTheSdFlagsOid()
    {
        SecurityDescriptorFlagsControl control = new(true, SecurityDescriptorFlags.Dacl);

        await Assert.That(control.ControlType).IsEqualTo("1.2.840.113556.1.4.801");
        await Assert.That(control.Criticality).IsTrue();
    }

    [Test]
    public async Task DaclOnlyEncodesAsSequenceWithInteger4()
    {
        // SEQUENCE { INTEGER 4 } wrapped in the control's OCTET STRING value.
        SecurityDescriptorFlagsControl control = new(true, SecurityDescriptorFlags.Dacl);

        AsnWriter writer = new(AsnEncodingRules.BER);
        control.ToBytes(writer);
        byte[] encoded = writer.Encode();

        // The encoded control must contain the value SEQUENCE { INTEGER 4 } = 30 03 02 01 04
        string hex = Convert.ToHexString(encoded);
        await Assert.That(hex).Contains("30030201" + "04");
    }

    [Test]
    public async Task CombinedFlagsEncodeAsTheirSum()
    {
        // Owner (1) | Group (2) | Dacl (4) = 7
        SecurityDescriptorFlagsControl control = new(
            true, SecurityDescriptorFlags.Owner | SecurityDescriptorFlags.Group | SecurityDescriptorFlags.Dacl);

        AsnWriter writer = new(AsnEncodingRules.BER);
        control.ToBytes(writer);

        string hex = Convert.ToHexString(writer.Encode());
        await Assert.That(hex).Contains("30030201" + "07");
    }
}
