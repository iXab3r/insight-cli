// MIT; temporary process-owned DOS object alias. Files remain under profile AppData.
using System;using System.ComponentModel;using System.IO;using System.Runtime.InteropServices;
namespace Insight.WindowsJob {
 internal sealed class DirectoryAlias:IDisposable {
  [StructLayout(LayoutKind.Sequential)] struct Unicode {public ushort Length,MaximumLength;public IntPtr Buffer;}
  [StructLayout(LayoutKind.Sequential)] struct Attributes {public int Length;public IntPtr RootDirectory,ObjectName;public uint Flags;public IntPtr Security,Quality;}
  [DllImport("ntdll.dll")] static extern int NtCreateSymbolicLinkObject(out IntPtr handle,uint access,ref Attributes attributes,ref Unicode target);
  [DllImport("ntdll.dll")] static extern uint RtlNtStatusToDosError(int status);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  IntPtr handle;public readonly string Path;
  public DirectoryAlias(string directory,string nonce){
   string name=@"\??\insight-cli-"+nonce,target=directory.StartsWith(@"\\?\UNC\",StringComparison.OrdinalIgnoreCase)?@"\??\UNC\"+directory.Substring(8):directory.StartsWith(@"\\?\",StringComparison.Ordinal)?@"\??\"+directory.Substring(4):directory.StartsWith(@"\\",StringComparison.Ordinal)?@"\??\UNC\"+directory.Substring(2):@"\??\"+directory;
   var nameBuffer=Marshal.StringToHGlobalUni(name);var targetBuffer=Marshal.StringToHGlobalUni(target);var namePointer=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Unicode)));
   try{
    var nameValue=new Unicode{Length=checked((ushort)(name.Length*2)),MaximumLength=checked((ushort)(name.Length*2+2)),Buffer=nameBuffer};Marshal.StructureToPtr(nameValue,namePointer,false);
    var targetValue=new Unicode{Length=checked((ushort)(target.Length*2)),MaximumLength=checked((ushort)(target.Length*2+2)),Buffer=targetBuffer};var attributes=new Attributes{Length=Marshal.SizeOf(typeof(Attributes)),ObjectName=namePointer,Flags=0x40};
    // No OBJ_PERMANENT or inherited handle: owner death removes the alias automatically.
    int status=NtCreateSymbolicLinkObject(out handle,0xf0001,ref attributes,ref targetValue);if(status<0)throw new Win32Exception((int)RtlNtStatusToDosError(status));Path=@"\\.\insight-cli-"+nonce+@"\";
   }finally{Marshal.FreeHGlobal(namePointer);Marshal.FreeHGlobal(targetBuffer);Marshal.FreeHGlobal(nameBuffer);}
  }
  public string File(string name)=>Path+name;
  public void Dispose(){if(handle!=IntPtr.Zero){CloseHandle(handle);handle=IntPtr.Zero;}}
 }
}
