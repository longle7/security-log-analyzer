using System.Text.Json;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLogAnalyzer;  // Matches your project

public class Analyzer
{
    public static void RunAnalysis()
    {
        Console.WriteLine("Loading 1M logs...");

        // Starting timer
        var sw = System.Diagnostics.Stopwatch.StartNew();

        string json = File.ReadAllText("logs.json");
        var logs = JsonSerializer.Deserialize<List<LogEntry>>(json)!;

        var failedLogins = logs.Where(l => l.Event == "failed_login").ToList();
        var ipGroups = failedLogins.GroupBy(l => l.Ip)
                                  .Select(g => new { Ip = g.Key, Events = g.OrderBy(l => l.Timestamp).ToList() });

        var alerts = new List<string>();
        foreach (var group in ipGroups)
        {
            var events = group.Events;
            for (int i = 0; i < events.Count - 9; i++)
            {
                var window = events.Skip(i).Take(10);
                var firstTime = window.First().Timestamp;
                var lastTime = window.Last().Timestamp;

                if ((lastTime - firstTime).TotalMinutes <= 60)
                {
                    alerts.Add($"ALERT: Brute-force on {group.Ip}: 10+ fails in {(lastTime - firstTime):mm\\:ss}");
                    break;
                }
            }
        }

        Console.WriteLine($"Found {alerts.Count} brute-force alerts:");
        foreach (var alert in alerts.Take(20))
        {
            Console.WriteLine(alert);
        }

        File.WriteAllText("alerts.csv", string.Join("\n", alerts));
        Console.WriteLine("\nFull alerts → alerts.csv");

        sw.Stop();
        Console.WriteLine($"\nProcessed 1M logs in {sw.ElapsedMilliseconds}ms ({sw.ElapsedMilliseconds / 1000.0:F1}s)");
        Console.WriteLine($"Alert rate: {alerts.Count / (sw.ElapsedMilliseconds / 1000.0):F0}/sec");
    }
}

// Keep LogEntry here too
public class LogEntry
{
    public int Id { get; set; }
    public string Ip { get; set; } = "";
    public string Event { get; set; } = "";
    public DateTime Timestamp { get; set; }
}
