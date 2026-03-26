using System;

namespace SecurityLogAnalyzer;

class Program
{
    static void Main()
    {
        Console.WriteLine("Security Log Analyzer v1.0");
        Console.WriteLine("1. Generate logs");
        Console.WriteLine("2. Analyze logs");
        Console.WriteLine("Enter choice (1/2):");
        string choice = Console.ReadLine()!;

        if (choice == "1")
        {
            Generator.GenerateLogs();
        }
        else if (choice == "2")
        {
            Analyzer.RunAnalysis();
        }
        else
        {
            Console.WriteLine("Invalid choice.");
        }

        Console.WriteLine("Press any key to exit...");
        Console.ReadKey();
    }
}
