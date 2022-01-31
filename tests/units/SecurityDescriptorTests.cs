using PSOpenAD.Security;
using System;
using Xunit;

namespace PSOpenADTests;

public static class SecurityDescriptorTests
{
    [Fact]
    public static void ParseRawSecurityDescriptor()
    {
        const string b64Data = "AQAUnBQFAAAwBQAAFAAAAKAAAAAEAIwAAwAAAAJAFAAgAAwAAQEAAAAAAAEAAAAAB1o4ACAAAAADAAAAvjsO8/Cf0RG2AwAA+ANnwaV6lr/mDdARooUAqgAwSeIBAQAAAAAAAQAAAAAHWjgAIAAAAAMAAAC/Ow7z8J/REbYDAAD4A2fBpXqWv+YN0BGihQCqADBJ4gEBAAAAAAABAAAAAAQAdAQYAAAABQA8ABAAAAADAAAAAEIWTMAg0BGnaACqAG4FKRTMKEg3FLxFmwetbwFeXygBAgAAAAAABSAAAAAqAgAABQA8ABAAAAADAAAAAEIWTMAg0BGnaACqAG4FKbp6lr/mDdARooUAqgAwSeIBAgAAAAAABSAAAAAqAgAABQA8ABAAAAADAAAAECAgX6V50BGQIADAT8LUzxTMKEg3FLxFmwetbwFeXygBAgAAAAAABSAAAAAqAgAABQA8ABAAAAADAAAAECAgX6V50BGQIADAT8LUz7p6lr/mDdARooUAqgAwSeIBAgAAAAAABSAAAAAqAgAABQA8ABAAAAADAAAAQMIKvKl50BGQIADAT8LUzxTMKEg3FLxFmwetbwFeXygBAgAAAAAABSAAAAAqAgAABQA8ABAAAAADAAAAQMIKvKl50BGQIADAT8LUz7p6lr/mDdARooUAqgAwSeIBAgAAAAAABSAAAAAqAgAABQA8ABAAAAADAAAAQi+6WaJ50BGQIADAT8LTzxTMKEg3FLxFmwetbwFeXygBAgAAAAAABSAAAAAqAgAABQA8ABAAAAADAAAAQi+6WaJ50BGQIADAT8LTz7p6lr/mDdARooUAqgAwSeIBAgAAAAAABSAAAAAqAgAABQA8ABAAAAADAAAA+IhwA+EK0hG0IgCgyWj5ORTMKEg3FLxFmwetbwFeXygBAgAAAAAABSAAAAAqAgAABQA8ABAAAAADAAAA+IhwA+EK0hG0IgCgyWj5Obp6lr/mDdARooUAqgAwSeIBAgAAAAAABSAAAAAqAgAABQA4ADAAAAABAAAAf3qWv+YN0BGihQCqADBJ4gEFAAAAAAAFFQAAADEvZKEn/RZlSSD3IwUCAAAFACwAEAAAAAEAAAAdsalGrmBaQLfo/4pY1FbSAQIAAAAAAAUgAAAAMAIAAAUALAAwAAAAAQAAAByatm0ilNERrr0AAPgDZ8EBAgAAAAAABSAAAAAxAgAABQAsADAAAAABAAAAYrwFWMm9KESl4oVqD0wYXgECAAAAAAAFIAAAADECAAAFACwAlAACAAIAAAAUzChINxS8RZsHrW8BXl8oAQIAAAAAAAUgAAAAKgIAAAUALACUAAIAAgAAALp6lr/mDdARooUAqgAwSeIBAgAAAAAABSAAAAAqAgAABQAoAAABAAABAAAAUxpyqy8e0BGYGQCqAEBSmwEBAAAAAAABAAAAAAUAKAAAAQAAAQAAAFMacqsvHtARmBkAqgBAUpsBAQAAAAAABQoAAAAFAigAMAEAAAEAAADeR+aRb9lwS5VX1j/088zYAQEAAAAAAAUKAAAAAAAkAL8BDgABBQAAAAAABRUAAAAxL2ShJ/0WZUkg9yMAAgAAAAAkAL8BDgABBQAAAAAABRUAAAAxL2ShJ/0WZUkg9yMHAgAAAAAYAL8BDwABAgAAAAAABSAAAAAgAgAAAAAUAJQAAgABAQAAAAAABQsAAAAAABQA/wEPAAEBAAAAAAAFEgAAAAEFAAAAAAAFFQAAADEvZKEn/RZlSSD3IwACAAABBQAAAAAABRUAAAAxL2ShJ/0WZUkg9yMAAgAA";
        byte[] data = Convert.FromBase64String(b64Data);

        CommonSecurityDescriptor sd = new(data);

        Assert.Equal(new SecurityIdentifier("S-1-5-21-2707697457-1696005415-603398217-512"), sd.Owner);
        Assert.Equal(new SecurityIdentifier("S-1-5-21-2707697457-1696005415-603398217-512"), sd.Group);
        Assert.Equal("SystemAcl RevisionDS AceCount 3", sd.SystemAcl?.ToString());
        Assert.Equal("DiscretionaryAcl RevisionDS AceCount 24", sd.DiscretionaryAcl?.ToString());
        Assert.Equal(data.Length, sd.BinaryLength);

        byte[] actual = new byte[sd.BinaryLength];
        sd.GetBinaryForm(actual, 0);
    }

    [Fact]
    public static void WriteEmptySD()
    {
        const string expected = "AQAAAAAAAAAAAAAAAAAAAAAAAAA=";
        CommonSecurityDescriptor sd = new();

        byte[] actual = new byte[sd.BinaryLength];
        sd.GetBinaryForm(actual, 0);

        Assert.Equal(20, actual.Length);
        Assert.Equal(expected, Convert.ToBase64String(actual));
    }

    [Fact]
    public static void GetBindaryFormTooSmall()
    {
        CommonSecurityDescriptor sd = new();
        byte[] raw = new byte[0];

        var ex = Assert.Throws<ArgumentException>(() => sd.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBindaryFormTooSmallForFlags()
    {
        CommonSecurityDescriptor sd = new();
        byte[] raw = new byte[2];

        var ex = Assert.Throws<ArgumentException>(() => sd.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }
}
