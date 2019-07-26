namespace Minary.AttackService.Main
{
  using MinaryLib.AttackService.Class;
  using MinaryLib.AttackService.Enum;
  using MinaryLib.AttackService.Interface;
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.IO;


  public class AS_ArpPoisoning : IAttackService
  {

    #region MEMBERS

    private const string serviceName = "ArpPoisoning";

    private ServiceStatus serviceStatus;
    private AttackServiceParameters serviceParams;
    private Process poisoningEngProc;

    // APE process config
    private static string firewallRulesFile = ".fwrules";
    private static string targetHostsFile = ".targethosts";

    private static string apeProcessName = "Ape";
    private static string apeBinaryPath = Path.Combine(serviceName, "Ape.exe");
    private string workingDirectory;

    #endregion


    #region PUBLIC

    public AS_ArpPoisoning(AttackServiceParameters serviceParams)
    {
      this.serviceParams = serviceParams;
      this.serviceStatus = ServiceStatus.NotRunning;

      // Register attack service
      this.serviceParams.AttackServiceHost.Register(this);

      // Working directory
      this.workingDirectory = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, serviceName);
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
      this.serviceParams.AttackServiceHost.OnServiceExited(serviceName, exitCode);
    }

    #endregion


    #region INTERFACE IAttackService implementation

    #region PROPERTIES

    public string ServiceName { get { return serviceName; } set { } }

    public ServiceStatus Status { get { return this.serviceStatus; } set { this.serviceStatus = value; } }

    public ServiceStartMode StartMode { get { return ServiceStartMode.OnStartSingle; } set { } }

  #endregion


  #region PUBLIC

  public ServiceStatus StartService(StartServiceParameters serviceParameters, Dictionary<string, List<object>> pluginsParameters)
    {
      var timeStamp = DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss");
      var processParameters = $"-x {serviceParameters.SelectedIfcId}";

      if (string.IsNullOrEmpty(serviceParameters.SelectedIfcId))
      {
        throw new Exception("No interface was declared");
      }

      // If no targets were declared write a log message
      // but continue anyway. Target system can also be added at a later moment.
      if (serviceParameters.TargetList.Count <= 0)
      {
        this.serviceStatus = ServiceStatus.NotRunning;
        this.serviceParams.AttackServiceHost.LogMessage("ArpPoisoning.StartService(): No target system selected");
      }

      // Write APE targetSystem hosts to list
      this.WriteTargetSystemsConfigFile(serviceParameters.TargetList);

      // Start process
      string apeBinaryFullPath = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, apeBinaryPath);

      this.poisoningEngProc = new Process();
      this.poisoningEngProc.StartInfo.WorkingDirectory = this.workingDirectory;
      this.poisoningEngProc.StartInfo.FileName = apeBinaryFullPath;
      this.poisoningEngProc.StartInfo.Arguments = processParameters;
      this.poisoningEngProc.StartInfo.WindowStyle = this.serviceParams.AttackServiceHost.IsDebuggingOn ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden;
      this.poisoningEngProc.StartInfo.CreateNoWindow = this.serviceParams.AttackServiceHost.IsDebuggingOn ? true : false;
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
        if (this.poisoningEngProc.HasExited == false)
        {
          this.poisoningEngProc.Kill();
          this.poisoningEngProc = null;
        }
      }
      catch (Exception ex)
      {
        this.serviceParams.AttackServiceHost.LogMessage($"ArpPoisoning.StopService(Exception): {ex.Message}");
      }

      return ServiceStatus.NotRunning;
    }


    public void WriteTargetSystemsConfigFile(Dictionary<string, string> targetList)
    {
      // Fix targetlist if it is corrupt.
      if (targetList == null ||
          targetList.Count < 0)
      {
        targetList = new Dictionary<string, string>();
      }
      
      var targetHostsFullPath = Path.Combine(this.workingDirectory, targetHostsFile);
      var targetHostsRecords = string.Empty;

      // Remove old .targethost file
      if (File.Exists(targetHostsFullPath))
      {
        File.Delete(targetHostsFullPath);
      }

      foreach (var tmpTargetMac in targetList.Keys)
      {
        targetHostsRecords += $"{targetList[tmpTargetMac]},{tmpTargetMac}\r\n";
        this.serviceParams.AttackServiceHost.LogMessage("ArpPoisoning.WriteTargetsToFile(): Poisoning targetSystem system: {0}/{1}", tmpTargetMac, targetList[tmpTargetMac]);
      }

      // Set status "Not running" if no records
      // were put into output data buffer
      if (string.IsNullOrEmpty(targetHostsRecords) ||
          string.IsNullOrWhiteSpace(targetHostsRecords))
      {
        this.serviceParams.AttackServiceHost.LogMessage("The number of \'Target hosts\' for RouterIPv4 is zero/null");
      }

      using (var outputFile = new StreamWriter(targetHostsFullPath))
      {
        targetHostsRecords = targetHostsRecords.Trim();
        outputFile.Write(targetHostsRecords);
      }
    }

    #endregion

    #endregion

  }
}

