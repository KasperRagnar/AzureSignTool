using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;

namespace AzureSign.Engines
{
    public static class PluginLoader
    {
        public static IReadOnlyList<ISigningEngine> LoadEnginesFromDirectory(string directory)
        {
            var engines = new List<ISigningEngine>();
            if (!Directory.Exists(directory))
            {
                return engines;
            }

            foreach (string dll in Directory.GetFiles(directory, "*.dll", SearchOption.TopDirectoryOnly))
            {
                engines.AddRange(LoadEnginesFromAssembly(dll));
            }

            return engines;
        }

        public static IReadOnlyList<ISigningEngine> LoadEnginesFromAssembly(string assemblyPath)
        {
            var engines = new List<ISigningEngine>();
            try
            {
                var assembly = Assembly.LoadFrom(assemblyPath);
                foreach (Type type in assembly.GetExportedTypes())
                {
                    if (!type.IsAbstract && !type.IsInterface && typeof(ISigningEngine).IsAssignableFrom(type))
                    {
                        if (Activator.CreateInstance(type) is ISigningEngine engine)
                        {
                            engines.Add(engine);
                        }
                    }
                }
            }
            catch
            {
                // Skip assemblies that cannot be loaded or inspected
            }

            return engines;
        }
    }
}
