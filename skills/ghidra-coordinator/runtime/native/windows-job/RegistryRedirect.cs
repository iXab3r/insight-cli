// MIT; inject only the reviewed registry shim into the child handle returned by our own CreateProcess.
using System;using System.ComponentModel;using System.IO;using System.Runtime.InteropServices;using System.Security.Cryptography;using System.Text;
namespace Insight.WindowsJob {
 internal sealed class RegistryRedirect:IDisposable {
  [StructLayout(LayoutKind.Sequential)] struct Security {public int Size;public IntPtr Descriptor;public int Inherit;}
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegLoadAppKey(string file,out IntPtr key,uint rights,uint options,uint reserved);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern int RegCreateKeyEx(IntPtr root,string name,int reserved,string type,int options,uint rights,ref Security security,out IntPtr key,out int disposition);
  [DllImport("advapi32.dll")] static extern int RegCloseKey(IntPtr key);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibrary(string file);
  [DllImport("kernel32.dll",CharSet=CharSet.Ansi,SetLastError=true)] static extern IntPtr GetProcAddress(IntPtr module,string name);
  [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
  [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate bool PrepareProcess(IntPtr process);
  [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
  IntPtr hive,user,module;FileStream held;PrepareProcess prepare;readonly string shim,ack,nonce;
  static void Check(int code){if(code!=0)throw new Win32Exception(code);}
  public RegistryRedirect(string root,string source,string expected,string nonce){
   this.nonce=nonce;shim=Path.Combine(root,"registry-shim.dll");ack=Path.Combine(root,"registry-isolated.bin");
   try{
    if(expected==null||expected.Length!=64)throw new ArgumentException("Registry shim identity is missing");
    using(var original=new FileStream(source,FileMode.Open,FileAccess.Read,FileShare.Read)){
     string actual;using(var hash=SHA256.Create())actual=BitConverter.ToString(hash.ComputeHash(original)).Replace("-","").ToLowerInvariant();if(actual!=expected)throw new InvalidOperationException("Registry shim differs from its reviewed build");original.Position=0;
     using(var copy=new FileStream(shim,FileMode.CreateNew,FileAccess.Write,FileShare.None)){original.CopyTo(copy);copy.Flush(true);}
    }
    held=new FileStream(shim,FileMode.Open,FileAccess.Read,FileShare.Read);
    module=LoadLibrary(shim);if(module==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());var entry=GetProcAddress(module,"InsightPrepareProcess");if(entry==IntPtr.Zero)throw new InvalidOperationException("Owned registry loader entry is unavailable");prepare=Marshal.GetDelegateForFunctionPointer<PrepareProcess>(entry);
    Check(RegLoadAppKey(Path.Combine(root,"user-settings.hive"),out hive,0xf003f,0,0));
    var security=new Security{Size=Marshal.SizeOf(typeof(Security)),Inherit=1};int disposition;Check(RegCreateKeyEx(hive,"user",0,null,0,0xf003f,ref security,out user,out disposition));
    Environment.SetEnvironmentVariable("INSIGHT_PRIVATE_HKCU_HANDLE",user.ToInt64().ToString("X"));Environment.SetEnvironmentVariable("INSIGHT_PRIVATE_HKCU_ACK",ack);Environment.SetEnvironmentVariable("INSIGHT_PRIVATE_HKCU_NONCE",nonce);
   }catch{Dispose();throw;}
  }
  public void Prepare(IntPtr process,uint pid){if(!prepare(process))throw new Win32Exception(Marshal.GetLastWin32Error());}
  public void Verify(IntPtr process,uint pid){
   for(int i=0;i<100;i++){
    byte[] proof=null;try{proof=File.ReadAllBytes(ack);}catch(IOException){}
    if(proof!=null&&proof.Length==48){if(BitConverter.ToUInt32(proof,0)!=0x49484b31||BitConverter.ToUInt32(proof,4)!=pid||Encoding.ASCII.GetString(proof,12,36)!=nonce)throw new InvalidOperationException("Owned registry initialization receipt is invalid");Check((int)BitConverter.ToUInt32(proof,8));return;}
    uint code;if(GetExitCodeProcess(process,out code)&&code!=259)throw new InvalidOperationException("Owned tool exited before registry initialization (0x"+code.ToString("x8")+")");
    System.Threading.Thread.Sleep(50);
   }
   throw new InvalidOperationException("Owned registry initialization receipt is missing after its deadline");
  }
  public void Dispose(){Environment.SetEnvironmentVariable("INSIGHT_PRIVATE_HKCU_HANDLE",null);Environment.SetEnvironmentVariable("INSIGHT_PRIVATE_HKCU_ACK",null);Environment.SetEnvironmentVariable("INSIGHT_PRIVATE_HKCU_NONCE",null);if(user!=IntPtr.Zero){RegCloseKey(user);user=IntPtr.Zero;}if(hive!=IntPtr.Zero){RegCloseKey(hive);hive=IntPtr.Zero;}if(module!=IntPtr.Zero){FreeLibrary(module);module=IntPtr.Zero;}if(held!=null){held.Dispose();held=null;}}
 }
}
