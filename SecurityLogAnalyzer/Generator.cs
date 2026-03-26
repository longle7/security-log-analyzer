using System.Text.Json;

namespace SecurityLogAnalyzer;

public static class Generator
{
    public static void GenerateLogs()
    {
        var random = new Random();
        var logs = new List<object>();

        for (int i = 0; i < 1_000_000; i++)
        {
            var log = new
            {
                Id = i,
                Ip = $"192.168.1.{random.Next(1, 255)}",
                Event = random.Next(0, 5) == 0 ? "failed_login" : "login",
                Timestamp = DateTime.UtcNow.AddSeconds(-random.Next(0, 3600))
            };
            logs.Add(log);
        }

        var json = JsonSerializer.Serialize(logs);
        File.WriteAllText("logs.json", json);

        Console.WriteLine("Generated 1,000,000 logs to logs.json");
    }
}
