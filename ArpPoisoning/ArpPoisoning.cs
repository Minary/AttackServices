namespace Minary.AttackService
{
  using MinaryLib.AttackService.Class;
  using MinaryLib.AttackService.Enum;
  using MinaryLib.AttackService.Interface;
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.IO;


  public class ArpPoisoning : IAttackService
  {

    #region MEMBERS
    
    private ServiceStatus serviceStatus;
    private AttackServiceParameters serviceParams;
    private Dictionary<string, SubModule> subModules;
    private Process poisoningEngProc;

    // APE process config
    public static string apeFirewallRules = ".fwrules";
    public static string apeTargetHosts = ".targethosts";
    public static string dnsPoisoningHosts = ".dnshosts";

    public static string attackServicesDir = "attackservices";
    public static string apeServiceDir = Path.Combine(attackServicesDir, "APE");
    public static string apeBinaryPath = Path.Combine(apeServiceDir, "Ape.exe");
    public static string apeProcessName = "Ape";
    private static string apeFwRulesPath = Path.Combine(apeServiceDir, apeFirewallRules);
    private static string apeTargetHostsPath = Path.Combine(apeServiceDir, apeTargetHosts);
    public static string dnsPoisoningHostsPath = Path.Combine(apeServiceDir, dnsPoisoningHosts);

    #endregion


    #region PUBLIC

    public ArpPoisoning(AttackServiceParameters serviceParams, Dictionary<string, SubModule> subModules)
    {
      this.serviceParams = serviceParams;
      this.subModules = subModules;
      this.serviceStatus = ServiceStatus.NotRunning;

      // Register attack service
      this.serviceParams.AttackServiceHost.Register(this);
    }

    #endregion


    #region PRIVATE

    private void OnServiceExited(object sender, System.EventArgs e)
    {
      int exitCode = -99999;

      try
      {
        exitCode = this.poisoningEngProc.ExitCode;
      }
      catch (Exception)
      {
        exitCode = -99999;
      }

      this.poisoningEngProc.EnableRaisingEvents = false;
      this.poisoningEngProc.Exited += null;
      this.serviceParams.AttackServiceHost.OnServiceExited(this.serviceParams.ServiceName, exitCode);
    }

    #endregion


    #region INTERFACE IAttackService implementation

    #region PROPERTIES

    public string ServiceName { get { return this.serviceParams.ServiceName; } set { } }

    public string WorkingDirectory { get { return this.serviceParams.ServiceWorkingDir; } set { } }

    public Dictionary<string, SubModule> SubModules { get { return this.subModules; } set { } }

    public ServiceStatus Status { get { return this.serviceStatus; } set { this.serviceStatus = value; } }

    public IAttackServiceHost AttackServiceHost { get; set; }

    #endregion


    #region PUBLIC

    public ServiceStatus StartService(StartServiceParameters serviceParameters)
    {
      string targetHosts = string.Empty;
      string workingDirectory = Path.Combine(Directory.GetCurrentDirectory(), apeServiceDir);
      string timeStamp = DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss");
      string targetHostsPath = apeTargetHostsPath;
      string processParameters = string.Format("-x {0}", serviceParameters.SelectedIfcId);

      if (string.IsNullOrEmpty(serviceParameters.SelectedIfcId))
      {
        throw new Exception("No interface was declared");
      }

      if (serviceParameters.TargetList.Count <= 0)
      {
        this.serviceStatus = ServiceStatus.NotRunning;
        this.serviceParams.AttackServiceHost.LogMessage("ArpPoisoning.StartService(): No target system selected");
        return ServiceStatus.NotRunning;
      }

      // Write APE targetSystem hosts to list
      foreach (string tmpTargetMac in serviceParameters.TargetList.Keys)
      {
        targetHosts += string.Format("{0},{1}\r\n", serviceParameters.TargetList[tmpTargetMac], tmpTargetMac);
        this.serviceParams.AttackServiceHost.LogMessage("ArpPoisoning.StartService(): Poisoning targetSystem system: {0}/{1}", tmpTargetMac, serviceParameters.TargetList[tmpTargetMac]);
      }

      using (StreamWriter outputFile = new StreamWriter(targetHostsPath))
      {
        targetHosts = targetHosts.Trim();
        outputFile.Write(targetHosts);
      }

      // Start process
      string apeBinaryFullPath = Path.Combine(Directory.GetCurrentDirectory(), apeBinaryPath);

      this.poisoningEngProc = new Process();
      this.poisoningEngProc.StartInfo.WorkingDirectory = workingDirectory;
      this.poisoningEngProc.StartInfo.FileName = apeBinaryFullPath;
      this.poisoningEngProc.StartInfo.Arguments = processParameters;
      this.poisoningEngProc.StartInfo.WindowStyle = this.serviceParams.IsDebuggingOn ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden;
      this.poisoningEngProc.StartInfo.CreateNoWindow = this.serviceParams.IsDebuggingOn ? true : false;
      this.poisoningEngProc.EnableRaisingEvents = true;
      this.poisoningEngProc.Exited += new EventHandler(this.OnServiceExited);
      this.serviceStatus = ServiceStatus.Running;

      this.serviceParams.AttackServiceHost.LogMessage("ArpPoisoning.StartService(): CommandLine:{0} {1}", apeBinaryPath, processParameters);
      this.poisoningEngProc.Start();

      return ServiceStatus.Running;
    }


    public ServiceStatus StopService()
    {
      if (this.poisoningEngProc == null)
      {
        this.serviceParams.AttackServiceHost.LogMessage("ArpPoisoning.StopService(): Can't stop attack service because it never was started");
        this.serviceStatus = ServiceStatus.NotRunning;
        return ServiceStatus.NotRunning;
      }

      this.poisoningEngProc.EnableRaisingEvents = false;
      this.poisoningEngProc.Exited += null;
      this.serviceStatus = ServiceStatus.NotRunning;
      this.serviceParams.AttackServiceHost.LogMessage("ArpPoisoning.StopService(): EnableRaisingEvents:{0}", this.poisoningEngProc.EnableRaisingEvents);

      try
      {
        if (this.poisoningEngProc != null && !this.poisoningEngProc.HasExited)
        {
          this.poisoningEngProc.Kill();
          this.poisoningEngProc = null;
        }
      }
      catch (Exception ex)
      {
        this.serviceParams.AttackServiceHost.LogMessage("ArpPoisoning.StopService(Exception): {0}", ex.Message);
      }

      return ServiceStatus.NotRunning;
    }

    #endregion

    #endregion

  }
}

