using System.IO;
using System.Text.Json;

namespace LarsonTech.Encryption.Test;

public class TestConfig
{
    public string? Thumbprint { get; set; }

    private static readonly Lazy<TestConfig> Config = new Lazy<TestConfig>(
        () =>
        {
            var json = File.ReadAllText("appSettings.json");
            var config = JsonSerializer.Deserialize<TestConfig>(json);
            return config ?? new TestConfig { };
        });

    public static TestConfig Instance => Config.Value;
}