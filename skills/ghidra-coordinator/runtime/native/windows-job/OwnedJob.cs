// MIT; first-party Windows Job Object executor. It never attaches another process to the job.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Threading;
namespace Insight.WindowsJob {
 public sealed class Started { public int LauncherPid; public uint ChildPid; public long ChildBirthTicks; }
 public sealed class Result { public string Kind; public uint ExitCode; public Started Started; }
 [DataContract] public sealed class Specification {
  [DataMember] public int schema;[DataMember] public string nonce,executable,cwd,ownerBirthTicks,observedBirthTicks,nativeMutex;[DataMember] public string[] arguments;[DataMember] public int ownerPid,timeoutMs,observedPid;
 }
 [DataContract] public sealed class Receipt {
  [DataMember] public int schema=1;[DataMember] public string nonce,phase,childBirthTicks;[DataMember] public int launcherPid;[DataMember] public uint childPid,childExitCode;
 }
 public static class OwnedJob {
  static void Save(string path,Receipt value){using(var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.Read)){new DataContractJsonSerializer(typeof(Receipt)).WriteObject(file,value);file.Flush(true);}}
  public static void RunSpecification(string path){
   path=Path.GetFullPath(path);var root=Path.GetDirectoryName(path);Specification spec;
   using(var file=File.OpenRead(path))spec=(Specification)new DataContractJsonSerializer(typeof(Specification)).ReadObject(file);
   long birth;Guid nonce;if(spec.schema!=1||!Guid.TryParse(spec.nonce,out nonce)||!long.TryParse(spec.ownerBirthTicks,out birth)||spec.arguments==null||spec.arguments.Length>256)throw new ArgumentException("Invalid owned job specification");
   Environment.SetEnvironmentVariable("TEMP",root);Environment.SetEnvironmentVariable("TMP",root);
   Process observed=null;Mutex mutex=null;bool held=false;
   try{
    if(spec.observedPid!=0){long expected;if(!long.TryParse(spec.observedBirthTicks,out expected))throw new ArgumentException("Observed process birth identity is missing");observed=Process.GetProcessById(spec.observedPid);var handle=observed.Handle;if(observed.StartTime.ToUniversalTime().Ticks!=expected||WaitForSingleObject(handle,0)!=258)throw new InvalidOperationException("Observed process identity changed or exited");}
    if(spec.nativeMutex!=null){if(spec.nativeMutex!=@"Local\insight-cli-procmon-capture")throw new ArgumentException("Invalid native capture mutex");mutex=new Mutex(false,spec.nativeMutex);try{held=mutex.WaitOne(0);}catch(AbandonedMutexException){held=true;}if(!held)throw new InvalidOperationException("Another owned Process Monitor capture is active");foreach(var name in new[]{"Procmon","Procmon64","Procmon64a"}){var foreign=Process.GetProcessesByName(name);try{if(foreign.Length!=0)throw new InvalidOperationException("An existing Process Monitor instance is not owned by this capture");}finally{foreach(var process in foreign)process.Dispose();}}}
   var result=Run(spec.executable,spec.arguments,spec.cwd,spec.ownerPid,birth,spec.timeoutMs,origin=>Save(Path.Combine(root,"job-started.json"),new Receipt{nonce=spec.nonce,launcherPid=origin.LauncherPid,childPid=origin.ChildPid,childBirthTicks=origin.ChildBirthTicks.ToString(),phase="assigned_suspended"}));
   Save(Path.Combine(root,"job-result.json"),new Receipt{nonce=spec.nonce,launcherPid=Process.GetCurrentProcess().Id,childPid=result.Started.ChildPid,childBirthTicks=result.Started.ChildBirthTicks.ToString(),phase=result.Kind,childExitCode=result.ExitCode});
   }finally{if(held)mutex.ReleaseMutex();if(mutex!=null)mutex.Dispose();if(observed!=null)observed.Dispose();}
  }

  [StructLayout(LayoutKind.Sequential)] struct Limits { public long ProcessTime,JobTime;public uint Flags;public UIntPtr MinWorkingSet,MaxWorkingSet;public uint ActiveProcesses;public UIntPtr Affinity;public uint Priority,Scheduling; }
  [StructLayout(LayoutKind.Sequential)] struct IO { public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes; }
  [StructLayout(LayoutKind.Sequential)] struct Extended { public Limits Basic;public IO Io;public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory; }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup { public uint Size;public string Reserved,Desktop,Title;public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;public ushort Show,ReservedSize;public IntPtr ReservedBytes,Input,Output,Error; }
  [StructLayout(LayoutKind.Sequential)] struct PI { public IntPtr Process,Thread;public uint Pid,Tid; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int type,ref Extended value,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder command,IntPtr processAttributes,IntPtr threadAttributes,bool inherit,uint flags,IntPtr environment,string directory,ref Startup startup,out PI process);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForMultipleObjects(uint count,IntPtr[] handles,bool all,uint timeout);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
  [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int id);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  static void Check(bool ok){if(!ok)throw new Win32Exception(Marshal.GetLastWin32Error());}
  static string Quote(string text){var b=new StringBuilder("\"");int slashes=0;foreach(char c in text){if(c=='\\'){slashes++;continue;}if(c=='\"'){b.Append('\\',slashes*2+1);b.Append(c);}else{b.Append('\\',slashes);b.Append(c);}slashes=0;}b.Append('\\',slashes*2);return b.Append('"').ToString();}
  public static Result Run(string executable,string[] arguments,string directory,int ownerPid,long ownerBirthTicks,int timeoutMs,Action<Started> started){
   if(timeoutMs<1000||timeoutMs>600000||!System.IO.Path.IsPathRooted(executable))throw new ArgumentException("Invalid owned job specification");
   using(var owner=Process.GetProcessById(ownerPid)){
    if(owner.StartTime.ToUniversalTime().Ticks!=ownerBirthTicks)throw new InvalidOperationException("Owner birth identity changed");
    var ownerHandle=owner.Handle;if(WaitForSingleObject(ownerHandle,0)!=258)throw new InvalidOperationException("Owner already exited");
    var job=CreateJobObject(IntPtr.Zero,null);if(job==IntPtr.Zero)throw new Win32Exception(Marshal.GetLastWin32Error());var child=new PI();bool assigned=false;
    try{
     var limits=new Extended();limits.Basic.Flags=0x2000;Check(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(Extended))));
     var startup=new Startup {Size=(uint)Marshal.SizeOf(typeof(Startup)),Flags=0x100,Input=GetStdHandle(-10),Output=GetStdHandle(-11),Error=GetStdHandle(-12)};
     var command=new StringBuilder(Quote(executable));foreach(var argument in arguments)command.Append(' ').Append(Quote(argument));if(command.Length>=32767)throw new ArgumentException("Windows command line exceeds its bound");
     Check(CreateProcess(executable,command,IntPtr.Zero,IntPtr.Zero,true,0x08000004,IntPtr.Zero,directory,ref startup,out child));Check(AssignProcessToJobObject(job,child.Process));assigned=true;
     long childBirth;using(var process=Process.GetProcessById((int)child.Pid))childBirth=process.StartTime.ToUniversalTime().Ticks;
     var origin=new Started {LauncherPid=Process.GetCurrentProcess().Id,ChildPid=child.Pid,ChildBirthTicks=childBirth};started(origin);
     if(WaitForSingleObject(ownerHandle,0)!=258){Check(TerminateJobObject(job,130));return new Result {Kind="owner_lost",ExitCode=130,Started=origin};}
     if(ResumeThread(child.Thread)==0xffffffff)throw new Win32Exception(Marshal.GetLastWin32Error());
     var outcome=WaitForMultipleObjects(2,new[]{child.Process,ownerHandle},false,(uint)timeoutMs);
     if(outcome==0){uint code;Check(GetExitCodeProcess(child.Process,out code));return new Result {Kind="completed",ExitCode=code,Started=origin};}
     if(outcome==1||outcome==258){uint code=outcome==1?130u:124u;Check(TerminateJobObject(job,code));WaitForSingleObject(child.Process,5000);return new Result {Kind=outcome==1?"owner_lost":"timeout",ExitCode=code,Started=origin};}
     throw new Win32Exception(Marshal.GetLastWin32Error());
    }finally{if(child.Process!=IntPtr.Zero&&!assigned)TerminateProcess(child.Process,125);CloseHandle(job);if(child.Thread!=IntPtr.Zero)CloseHandle(child.Thread);if(child.Process!=IntPtr.Zero)CloseHandle(child.Process);}
   }
  }
 }
}
