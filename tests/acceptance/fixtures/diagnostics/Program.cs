using System.Runtime.CompilerServices;
sealed class BusinessState
{
    public string Job = "owned-report";
    public int Pending = 37;
}
static class Program
{
    public static object Held = new BusinessState();
    [MethodImpl(MethodImplOptions.NoInlining)]
    static void WaitForRelease()
    {
        Console.WriteLine("READY " + Environment.ProcessId);
        while (true) Thread.Sleep(100);
    }
    static void Main()
    {
        Console.WriteLine(((BusinessState)Held).Pending);
        WaitForRelease();
    }
}
