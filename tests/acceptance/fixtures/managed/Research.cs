using System.Runtime.InteropServices;
namespace ResearchFixture;
public static class Policy
{
    public const int RetryLimit = 7;
    public static int CalculateCost(int count) => count < 10 ? count * 12 : count * 9 + 17;
    public static byte DecodeByte(byte encoded) => (byte)(encoded ^ 0x5a);
    [DllImport("kernel32.dll", EntryPoint = "GetTickCount")]
    public static extern uint NativeClock();
}
