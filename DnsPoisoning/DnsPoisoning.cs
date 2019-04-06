namespace Minary.AttackService.Main
{
  using MinaryLib.AttackService.Class;
  using MinaryLib.AttackService.Enum;
  using MinaryLib.AttackService.Interface;
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.IO;
  using System.Linq;


  public class AS_DnsPoisoning : IAttackService
  {

    #region MEMBERS

    private const string serviceName = "DnsPoisoning";

    private ServiceStatus serviceStatus;
    private AttackServiceParameters serviceParams;
    private Process poisoningEngProc;

    // DnsPoisoning process config
    private static string dnsPoisoningHostsFile = ".dnshosts";
    private static string arpPoisoningHostsFile = ".targethosts";

    private static string DnsPoisoningProcessName = "DnsPoisoning";
    private static string DnsPoisoningBinaryPath = Path.Combine(serviceName, "DnsPoisoning.exe");

    #endregion


    #region PUBLIC

    public AS_DnsPoisoning(AttackServiceParameters serviceParams)
    {
      this.serviceParams = serviceParams;
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
      this.serviceParams.AttackServiceHost.OnServiceExited(serviceName, exitCode);
    }

    #endregion


    #region INTERFACE IAttackService implementation

    #region PROPERTIES

    public string ServiceName { get { return serviceName; } set { } }

    public ServiceStatus Status { get { return this.serviceStatus; } set { this.serviceStatus = value; } }

    #endregion


    #region PUBLIC

    public ServiceStatus StartService(StartServiceParameters serviceParameters, Dictionary<string, List<object>> pluginsParameters)
    {
      var workingDirectory = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, serviceName);
      var timeStamp = DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss");
      var processParameters = $"-x {serviceParameters.SelectedIfcId}";

      if (string.IsNullOrEmpty(serviceParameters.SelectedIfcId))
      {
        throw new Exception("No interface was declared");
      }

      try
      {
        // Write DNS Poisoning ip/type/hostname file
        this.WriteDnsPoisoningConfigFile(pluginsParameters);

        // Write Target systems file
        this.WriteTargetSystemsConfigFile(serviceParameters.TargetList);
      }
      catch (Exception e)
      {
        this.serviceStatus = ServiceStatus.NotRunning;
        this.serviceParams.AttackServiceHost.LogMessage($"DnsPoisoning.StartService(EXC): {e.Message}");

        return ServiceStatus.NotRunning;
      }

      // Start process
      string dnsPoisoningBinaryFullPath = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, DnsPoisoningBinaryPath);

      this.poisoningEngProc = new Process();
      this.poisoningEngProc.StartInfo.WorkingDirectory = workingDirectory;
      this.poisoningEngProc.StartInfo.FileName = dnsPoisoningBinaryFullPath;
      this.poisoningEngProc.StartInfo.Arguments = processParameters;
      this.poisoningEngProc.StartInfo.WindowStyle = this.serviceParams.AttackServiceHost.IsDebuggingOn ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden;
      this.poisoningEngProc.StartInfo.CreateNoWindow = this.serviceParams.AttackServiceHost.IsDebuggingOn ? true : false;
      this.poisoningEngProc.EnableRaisingEvents = true;
      this.poisoningEngProc.Exited += new EventHandler(this.OnServiceExited);
      this.serviceStatus = ServiceStatus.Running;

      this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.StartService(): CommandLine:{0} {1}", DnsPoisoningBinaryPath, processParameters);
      this.poisoningEngProc.Start();

      return ServiceStatus.Running;
    }


    public ServiceStatus StopService()
    {
      if (this.poisoningEngProc == null)
      {
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.StopService(): Can't stop attack service because it never was started");
        this.serviceStatus = ServiceStatus.NotRunning;
        return ServiceStatus.NotRunning;
      }

      this.poisoningEngProc.EnableRaisingEvents = false;
      this.poisoningEngProc.Exited += null;
      this.serviceStatus = ServiceStatus.NotRunning;
      this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.StopService(): EnableRaisingEvents:{0}", this.poisoningEngProc.EnableRaisingEvents);

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
        this.serviceParams.AttackServiceHost.LogMessage($"DnsPoisoning.StopService(Exception): {ex.Message}");
      }

      return ServiceStatus.NotRunning;
    }

    #endregion


    #region PRIVATE

    private void WriteDnsPoisoningConfigFile(Dictionary<string, List<object>> pluginsParameters)
    {
      var workingDirectory = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, serviceName);
      var poisoningHostsFullPath = Path.Combine(workingDirectory, dnsPoisoningHostsFile);
      var poisoningHostsRecords = string.Empty;

      if (File.Exists(poisoningHostsFullPath))
      {
        File.Delete(poisoningHostsFullPath);
      }

      // Throw exception if the parameters for the 
      // plugin 'DnsPoisoning' is null/invalid
      if (pluginsParameters == null ||
          pluginsParameters.Count <= 0 ||
          pluginsParameters.ContainsKey("dnspoisoning") == false ||
          pluginsParameters["dnspoisoning"] == null)
      {
//        throw new Exception("The parameters from the plugin 'DnsPoisoning' is null/invalid");
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.WriteDnsPoisoningConfigFile(): The parameters from the plugin 'DnsPoisoning' is null/invalid");
        return;
      }

      // Throw exception if the DnsPoisoning system list
      // is null or invalid (<0)
      List<string> pluginParamsList = pluginsParameters["dnspoisoning"].Cast<string>().ToList();
      if (pluginParamsList == null ||
          pluginParamsList.Count < 0)
      {
        //throw new Exception("Something is wrong with the plugin parameters for DnsPoisoning");
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.WriteDnsPoisoningConfigFile(): Something is wrong with the plugin parameters for DnsPoisoning");
        return;
      }

      poisoningHostsRecords = string.Join("\r\n", pluginParamsList);

      if (string.IsNullOrEmpty(poisoningHostsRecords) ||
          string.IsNullOrWhiteSpace(poisoningHostsRecords))
      {
        this.serviceStatus = ServiceStatus.NotRunning;
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.WriteDnsPoisoningConfigFile(): Could not determine DNS poisoning records");
      }

      using (var outfile = new StreamWriter(poisoningHostsFullPath))
      {
        outfile.Write(poisoningHostsRecords);
      }
    }


    private void WriteTargetSystemsConfigFile(Dictionary<string, string> targetList)
    {
      if (targetList == null ||
          targetList.Count <= 0)
      {
        return;
      }

      var workingDirectory = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, serviceName);
      var arpPoisoningHostsFullPath = Path.Combine(workingDirectory, arpPoisoningHostsFile);
      var arpPoisoningHostsRecords = string.Empty;

      if (File.Exists(arpPoisoningHostsFullPath))
      {
        File.Delete(arpPoisoningHostsFullPath);
      }

      // Keep all IP/MAC combination in output string
      foreach (var tmpTargetMac in targetList.Keys)
      {
        arpPoisoningHostsRecords += $"{targetList[tmpTargetMac]},{tmpTargetMac}\r\n";
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.WriteTargetSystemsConfigFile(): Poisoning targetSystem system: {0}/{1}", tmpTargetMac, targetList[tmpTargetMac]);
      }

      // Set status "Not running" if no records
      // were put into output data buffer
      if (string.IsNullOrEmpty(arpPoisoningHostsRecords) ||
          string.IsNullOrWhiteSpace(arpPoisoningHostsRecords))
      {
        throw new Exception("Something is wrong with the attack parameters \'Target hosts\' for DnsPoisoning");
      }

      // Write
      using (var outfile = new StreamWriter(arpPoisoningHostsFullPath))
      {
        outfile.Write(arpPoisoningHostsRecords);
      }
    }

    #endregion

    #endregion

  }
}
