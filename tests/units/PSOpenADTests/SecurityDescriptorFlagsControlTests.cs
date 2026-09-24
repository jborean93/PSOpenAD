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
        // SEQUENCE { OCTET STRING "1.2.840.113556.1.4.801", BOOLEAN true,
        //            OCTET STRING { SEQUENCE { INTEGER 4 } } }
        const string EXPECTED =
            "30220416312E322E3834302E3131333535362E312E342E3830310101FF04053003020104";
        SecurityDescriptorFlagsControl control = new(true, SecurityDescriptorFlags.Dacl);

        AsnWriter writer = new(AsnEncodingRules.BER);
        control.ToBytes(writer);
        byte[] encoded = writer.Encode();

        string hex = Convert.ToHexString(encoded);
        await Assert.That(hex).IsEqualTo(EXPECTED);
    }
}
