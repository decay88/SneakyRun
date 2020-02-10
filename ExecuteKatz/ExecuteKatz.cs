using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace ExecuteKatz
{
    class ExecuteKatz
    {
        static void Main(string[] args)
        {
            Console.WriteLine( NonInteractiveKatz.NonInteractiveKatz.Coffee());
            //KatzAssembly.Katz.Exec();
            Console.ReadLine();
        }
    }
}
