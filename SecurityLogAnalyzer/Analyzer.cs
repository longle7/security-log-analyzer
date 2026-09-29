using System.Text.Json;
using System.Text.RegularExpressions;


namespace SecurityLogAnalyzer;

public class Analyzer
{

    // Constants
    private const int constWindowLen = 10;
    public static void RunAnalysis()
    {
        Console.WriteLine("Loading 1M logs...");

        // Starting timer
        var sw = System.Diagnostics.Stopwatch.StartNew();

        // Reading the file that contains log information - each log entry has the properties as the LogEntry class
        string json = File.ReadAllText("logs.json");

        // logs is a list of indiv log entry from the json provided
        var logs = JsonSerializer.Deserialize<List<LogEntry>>(json)!;

        // failedLogins contains failed logins where the event in the current log == "failed_login"
        var failedLogins = logs.Where(l => l.Event == "failed_login").ToList();

        // groups the failed logins by IP address - well have about 254 IGrouping<string, LogEntry> objects
        // EX:  Group 1: Key="192.168.1.42" → 847 failed logins from this IP

        // the .Select takes each raw group and transforms it into a clean object:
        // for each IP in the in the .GroupBy sort the timestamps oldest -> newest
        // EX:  ipGroups[0] = { Ip: "192.168.1.42", Events: [10:00am, 10:02am, 10:05am, ..., 10:23am] }
        //      ipGroups[1] = { Ip: "192.168.1.99", Events: [9:45am, 9:47am, ..., 11:02am] }
        var ipGroups = failedLogins.GroupBy(l => l.Ip)
                                  .Select(g => new { Ip = g.Key, Events = g.OrderBy(l => l.Timestamp).ToList() });

        var alerts = new List<string>();
        foreach (var group in ipGroups)
        {
            // group consist of {string ip, <List>LogEntry events}
            // group.Events = [10:00, 10:02, 10:05, ..., 10:50]
            var events = group.Events;
            // sliding window start position
            // events.Count - constWindowLen ensures each window has constWindowLen events
            // IP "192.168.1.5": 3 failed logins → Count=3 → 3-10=-7 → loop skips → safe, no alert
            // IP "192.168.1.42": 847 fails → 847 - 10 = 837 → 838 windows checked
            for (int i = 0; i <= events.Count - constWindowLen; i++)
            {
                // Using direct indexing 
                var firstTime = events[i].Timestamp; // Earliest in the window
                var lastTime = events[i + constWindowLen - 1].Timestamp; // Latest in window

                if ((lastTime - firstTime).TotalMinutes <= 60) // if there are 10 fails in less than 1 hour
                {
                    // Send the alert
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

    // Format: <timestamp> [SECURITY] User '<user>' <action, may be multi-word> from <ip>
    private static readonly Regex SecurityLinePattern =
        new(@"^(\S+) \[SECURITY\] User '([^']*)' (.+) from (\S+)$", RegexOptions.Compiled);

    public static SecurityEvent? ParseLogLine(string line)
    {
        // Returns null for non-security or malformed lines instead of throwing
        var match = SecurityLinePattern.Match(line.Trim());
        if (!match.Success) return null;

        return new SecurityEvent
        {
            Timestamp = match.Groups[1].Value,
            User = match.Groups[2].Value,
            Action = match.Groups[3].Value,
            IP = match.Groups[4].Value
        };
    }
}

public class LogEntry
{
    public int Id { get; set; }
    public string Ip { get; set; } = "";
    public string Event { get; set; } = "";
    public DateTime Timestamp { get; set; }
}

public class SecurityEvent
{
    public string Timestamp { get; set; } = "";
    public string User { get; set; } = "";
    public string Action { get; set; } = "";
    public string IP { get; set; } = "";
}
