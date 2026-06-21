using Ravelin.Shared;

namespace Ravelin.Tests;

public class ApiInfoTests
{
    [Fact]
    public void ApiInfo_uses_value_equality()
    {
        var a = new ApiInfo("Ravelin", "Tracker", "1.0.0", "Development");
        var b = new ApiInfo("Ravelin", "Tracker", "1.0.0", "Development");

        // Records compare by value — the shared contract behaves as expected.
        Assert.Equal(a, b);
    }

    [Fact]
    public void ApiInfo_exposes_its_members()
    {
        var info = new ApiInfo("Ravelin", "Tracker", "1.2.3", "Production");

        Assert.Equal("Ravelin", info.Name);
        Assert.Equal("1.2.3", info.Version);
        Assert.Equal("Production", info.Environment);
    }
}
