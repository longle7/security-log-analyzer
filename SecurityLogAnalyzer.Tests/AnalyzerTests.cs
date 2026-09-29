using SecurityLogAnalyzer;

public class AnalyzerTests
{
    [Fact]
    public void ParseLogLine_ValidLine_ReturnsSecurityEvent()
    {
        var line = "2025-03-26T16:05:30Z [SECURITY] User 'admin' failed login from 192.168.1.100";
        var result = Analyzer.ParseLogLine(line);

        Assert.NotNull(result);
        Assert.Equal("admin", result.User);
        Assert.Equal("failed login", result.Action);
        Assert.Equal("192.168.1.100", result.IP);
    }
    [Fact]
    public void ParseLogLine_InvalidLine_ReturnsNull()
    {
        var line = "invalid log line";
        var result = Analyzer.ParseLogLine(line);

        Assert.Null(result);
    }

    [Fact]
    public void ParseLogLine_NonSecurityLine_ReturnsNull()
    {
        var line = "2025-03-26T16:05:30Z [INFO] Application started";
        var result = Analyzer.ParseLogLine(line);

        Assert.Null(result);
    }
}