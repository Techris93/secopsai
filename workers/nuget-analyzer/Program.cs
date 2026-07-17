using System.IO.Compression;
using System.Text.Json;
using Mono.Cecil;

// This worker reads .NET metadata only. It never loads an assembly for
// execution, resolves package dependencies, invokes constructors, or runs a
// package installer.
if (args.Length != 1)
{
    Console.Error.WriteLine("usage: NuGetAnalyzer <package.nupkg>");
    return 2;
}

var packagePath = Path.GetFullPath(args[0]);
if (!File.Exists(packagePath) || new FileInfo(packagePath).Length > 50 * 1024 * 1024)
{
    Console.Error.WriteLine("package must be a regular file no larger than 50 MiB");
    return 2;
}

var assemblies = new List<object>();
using var archive = ZipFile.OpenRead(packagePath);
foreach (var entry in archive.Entries)
{
    var lower = entry.FullName.ToLowerInvariant();
    if (!lower.EndsWith(".dll") && !lower.EndsWith(".exe")) continue;
    if (entry.Length > 20 * 1024 * 1024 || entry.FullName.Contains("..", StringComparison.Ordinal)) continue;
    try
    {
        using var source = entry.Open();
        using var memory = new MemoryStream();
        source.CopyTo(memory);
        memory.Position = 0;
        using var assembly = AssemblyDefinition.ReadAssembly(memory, new ReaderParameters { ReadSymbols = false, InMemory = true });
        var module = assembly.MainModule;
        var methods = module.Types
            .SelectMany(type => type.Methods.Select(method => new { type = type.FullName, name = method.Name, is_static = method.IsStatic }))
            .Take(2000)
            .ToArray();
        var references = module.AssemblyReferences.Select(reference => reference.FullName).Take(500).ToArray();
        var p_invokes = module.Types
            .SelectMany(type => type.Methods.Where(method => method.IsPInvokeImpl).Select(method => new { type = type.FullName, name = method.Name, library = method.PInvokeInfo?.Module?.Name }))
            .Take(500)
            .ToArray();
        assemblies.Add(new { path = entry.FullName, sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(ReadEntry(entry))).ToLowerInvariant(), assembly = assembly.Name?.FullName, target_framework = module.RuntimeVersion, types = module.Types.Select(type => type.FullName).Take(2000), methods, references, p_invokes, loaded = false, executed = false });
    }
    catch (Exception error)
    {
        assemblies.Add(new { path = entry.FullName, loaded = false, executed = false, error = error.GetType().Name });
    }
}

Console.WriteLine(JsonSerializer.Serialize(new
{
    schema_version = "secopsai.research.analysis-result.v1",
    tool = "Mono.Cecil",
    tool_version = "0.11.6",
    execution_performed = false,
    assemblies
}));

static byte[] ReadEntry(ZipArchiveEntry entry)
{
    using var source = entry.Open();
    using var memory = new MemoryStream();
    source.CopyTo(memory);
    return memory.ToArray();
}
