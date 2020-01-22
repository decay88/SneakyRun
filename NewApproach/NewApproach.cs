﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NewApproach
{
    class NewApproach
    {


        static void Main(string[] args)
        {
            AppDomain ad = AppDomain.CreateDomain("Test");
            Console.WriteLine("new AppDomain \"Test\" was created");
            byte[] mimi = loadFile(@"..\..\..\KatzAssembly\bin\Debug\KatzAssembly.dll");

            // Loader lives in another AppDomain
            Loader loader = (Loader)ad.CreateInstanceAndUnwrap(
                typeof(Loader).Assembly.FullName,
                typeof(Loader).FullName);           

            //loader.LoadAssembly(@"E:\Users\RODCHENKO\Documents\GitHub\Seatbelt\Seatbelt\bin\Debug\Seatbelt.dll");
            loader.LoadAssembly(loadFile(@"..\..\..\KatzAssembly\bin\Debug\KatzAssembly.dll"));
            Console.WriteLine("Assembly was loaded into new \"Test\" AppDomain");
            //loader.ExecuteStaticMethod("Seatbelt.Program","ListUserFolders");

            var t = Task.Run(() => {
                loader.ExecuteStaticMethod("KatzAssembly.Katz", "ExecInternal");
            });

            t.Wait();
            t.Dispose();
            Console.WriteLine("Press enter to clear Appdomain");
            Console.ReadLine();
            AppDomain.Unload(ad);
            ad = null;            
            GC.Collect();
            GC.WaitForFullGCComplete();
            Console.WriteLine("Appdomain cleared");
            Console.ReadLine();
        }

        static byte[] loadFile(string filename)
        {
            FileStream fs = new FileStream(filename, FileMode.Open);
            byte[] buffer = new byte[(int)fs.Length];
            fs.Read(buffer, 0, buffer.Length);
            fs.Close();

            return buffer;
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

            public void LoadAssembly(byte [] bytes)
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
}