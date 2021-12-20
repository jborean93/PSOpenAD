using System;
using System.Collections.Generic;
using System.Linq;

namespace PSOpenAD
{
    public class OpenADObject
    {
        public string DistinguishedName { get => (string)Properties["distinguishedName"]; }
        public string Name { get => (string)Properties["name"]; }
        public string ObjectClass { get => (string)((object[])Properties["objectClass"]).Last(); }
        public Guid ObjectGuid { get => new Guid((byte[])Properties["objectGUID"]); }
        public Dictionary<string, object> Properties { get; }

        public OpenADObject(Dictionary<string, object> properties)
        {
            Properties = properties;
        }
    }
}
