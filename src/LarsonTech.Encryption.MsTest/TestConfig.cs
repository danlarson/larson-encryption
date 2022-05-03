using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Bct.Common.Encryption.MsTest
{
    public class TestConfig
    {
        public string? Thumbprint { get; set; }

        private static readonly Lazy<TestConfig> Config = new Lazy<TestConfig>(
            () =>
            {
                var dir = System.Reflection.Assembly.GetExecutingAssembly().Location;
                var json = File.ReadAllText("appSettings.json");
                var config = JsonSerializer.Deserialize<TestConfig>(json);
                return config ?? new TestConfig{};
            });

        public static TestConfig Instance => Config.Value;
    }
}
