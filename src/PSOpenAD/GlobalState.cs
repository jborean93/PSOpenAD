using System;
using System.Collections.Generic;
using System.Management.Automation.Runspaces;
using System.Runtime.CompilerServices;
using System.Threading;

namespace PSOpenAD;

internal class RunspaceSpecificStorage<T>
{
    private readonly ConditionalWeakTable<Runspace, Lazy<T>> _map = [];

    private readonly Func<T> _factory;

    private readonly LazyThreadSafetyMode _mode = LazyThreadSafetyMode.ExecutionAndPublication;

    public RunspaceSpecificStorage(Func<T> factory)
    {
        _factory = factory;
    }

    public T GetFromTLS()
        => GetForRunspace(Runspace.DefaultRunspace);

    public T GetForRunspace(Runspace runspace)
    {
        return _map.GetValue(
            runspace,
            _ => new Lazy<T>(() => _factory(), _mode))
            .Value;
    }
}

internal class GlobalState
{
    private static readonly RunspaceSpecificStorage<GlobalState> _state = new(() => new());

    private GlobalState() { }

    /// <summary>Client authentication provider details.</summary>
    public Dictionary<AuthenticationMethod, AuthenticationProvider> Providers = [];

    /// <summary>List of sessions that have been opened by the client.</summary>
    public List<OpenADSession> Sessions = [];

    /// <summary>Keeps the current session count used to uniquely identify each new session.</summary>
    public int SessionCounter = 1;

    /// <summary>Information about LDAP classes and their attributes.</summary>
    public SchemaMetadata? SchemaMetadata;

    /// <summary>The GSSAPI/SSPI provider that is used.</summary>
    public GssapiProvider GssapiProvider;

    /// <summary>The default domain controller hostname to use when none was provided.</summary>
    public Uri? DefaultDC;

    /// <summary>If the default DC couldn't be detected this stores the details.</summary>
    public string? DefaultDCError;

    public static GlobalState GetFromTLS() => _state.GetFromTLS();
}
