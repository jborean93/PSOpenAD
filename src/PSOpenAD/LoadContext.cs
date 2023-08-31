using System.IO;
using System.Reflection;
using System.Runtime.Loader;

namespace PSOpenAD;

public class LoadContext : AssemblyLoadContext
{
    private static LoadContext? _instance;
    private static object _sync = new object();

    private Assembly _thisAssembly;
    private AssemblyName _thisAssemblyName;
    private Assembly _moduleAssembly;
    private string _assemblyDir;

    private LoadContext(string mainModulePathAssemblyPath)
        : base (name: nameof(PSOpenAD), isCollectible: false)
    {
        _assemblyDir = Path.GetDirectoryName(mainModulePathAssemblyPath) ?? "";
        _thisAssembly = typeof(LoadContext).Assembly;
        _thisAssemblyName = _thisAssembly.GetName();
        _moduleAssembly = LoadFromAssemblyPath(mainModulePathAssemblyPath);
    }

    protected override Assembly? Load(AssemblyName assemblyName)
    {
        if (AssemblyName.ReferenceMatchesDefinition(_thisAssemblyName, assemblyName))
        {
            return _thisAssembly;
        }

        string asmPath = Path.Join(_assemblyDir, $"{assemblyName.Name}.dll");
        if (File.Exists(asmPath))
        {
            return LoadFromAssemblyPath(asmPath);
        }
        else
        {
            return null;
        }
    }

    public static Assembly Initialize()
    {
        LoadContext? instance = _instance;
        if (instance is not null)
        {
            return instance._moduleAssembly;
        }

        lock (_sync)
        {
            if (_instance is not null)
            {
                return _instance._moduleAssembly;
            }

            string assemblyPath = typeof(LoadContext).Assembly.Location;
            string modulePath = Path.Combine(
                Path.GetDirectoryName(assemblyPath)!,
                $"{Path.GetFileNameWithoutExtension(assemblyPath)}.Module.dll"
            );
            _instance = new LoadContext(modulePath);
            return _instance._moduleAssembly;
        }
    }
}
