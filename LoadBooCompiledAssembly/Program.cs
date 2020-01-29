using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using Boo.Lang.Compiler;
using Boo.Lang.Compiler.IO;
using Boo.Lang.Compiler.Pipelines;

namespace LoadBooCompiledAssembly
{
    class Program
    {
        static void Main(string[] args)
        {
            
            AppDomain ad = AppDomain.CreateDomain("Test");
            Console.WriteLine("new AppDomain \"Test\" was created");

            // Loader lives in another AppDomain
            Loader loader = (Loader)ad.CreateInstanceAndUnwrap(
                typeof(Loader).Assembly.FullName,
                typeof(Loader).FullName);



            //loader.LoadAssembly(Properties.Resources.KatzAssembly);

            //loader.ExecuteStaticMethod("KatzAssembly.Katz", "ExecInternal");

            Console.WriteLine("Press enter to clear Appdomain");
            Console.ReadLine();
            AppDomain.Unload(ad);
            ad = null;
            GC.Collect();
            GC.WaitForFullGCComplete();
            Console.WriteLine("Appdomain cleared");
            Console.ReadLine();
            
            BooCompiler compiler = new BooCompiler();
            compiler.Parameters.Input.Add(new FileInput(@"..\..\script.boo"));
            
            compiler.Parameters.Pipeline = new CompileToMemory();
            compiler.Parameters.Ducky = true;
            compiler.Parameters.GenerateInMemory = true;

            

            CompilerContext context = compiler.Run();
            //Note that the following code might throw an error if the Boo script had bugs.
            //Poke context.Errors to make sure.
            if (context.GeneratedAssembly != null)
            {
                Type scriptModule = context.GeneratedAssembly.GetType("ScriptModule");
                MethodInfo stringManip = scriptModule.GetMethod("stringManip");
                string output = (string)stringManip.Invoke(null, new object[] { "Tag" });
                Console.WriteLine(output);
            }
            else
            {
                foreach (CompilerError error in context.Errors)
                    Console.WriteLine(error);
            }
        }
    }
    class Loader : MarshalByRefObject
    {
        private Assembly _assembly;

        public override object InitializeLifetimeService()
        {
            return null;
        }

        public void LoadAssembly(string path)
        {
            _assembly = Assembly.Load(AssemblyName.GetAssemblyName(path));
        }

        public void LoadAssembly(byte[] bytes)
        {
            _assembly = Assembly.Load(bytes);
        }


        public object ExecuteStaticMethod(string typeName, string methodName, params object[] parameters)
        {
            Type type = _assembly.GetType(typeName);
            // TODO: this won't work if there are overloads available
            MethodInfo method = type.GetMethod(
                methodName,
                BindingFlags.Static | BindingFlags.Public);
            return method.Invoke(null, parameters);
        }
    }
}
