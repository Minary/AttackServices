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
    private string workingDirectory;

    #endregion


    #region PUBLIC

    public AS_DnsPoisoning(AttackServiceParameters serviceParams)
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

      // Write the .targetsystem  config file
      this.WriteTargetSystemsConfigFile(serviceParameters.TargetList);

      // Write the poisoning records file
      this.WriteDnsPoisoningConfigFile(pluginsParameters);

      // Start process
      string dnsPoisoningBinaryFullPath = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, DnsPoisoningBinaryPath);

      this.poisoningEngProc = new Process();
      this.poisoningEngProc.StartInfo.WorkingDirectory = this.workingDirectory;
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
    

    public void WriteDnsPoisoningConfigFile(Dictionary<string, List<object>> pluginsParameters)
    {
      var poisoningHostsFullPath = Path.Combine(this.workingDirectory, dnsPoisoningHostsFile);
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
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.WriteDnsPoisoningConfigFile(): The parameters of the plugin 'DnsPoisoning' is null/invalid");
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
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.WriteDnsPoisoningConfigFile(): Wrote: {0} target systems to {1}",
                                                        pluginParamsList?.Count ?? 0, poisoningHostsFullPath);
      }
    }


    public void WriteTargetSystemsConfigFile(Dictionary<string, string> targetList)
    {
      // Fix targetlist if it is corrupt.
      if (targetList == null ||
          targetList.Count < 0)
      {
        targetList = new Dictionary<string, string>();
      }
      
      var targetHostsFullPath = Path.Combine(this.workingDirectory, arpPoisoningHostsFile);
      var arpPoisoningHostsRecords = string.Empty;

      // Remove old .targethost file
      if (File.Exists(targetHostsFullPath))
      {
        File.Delete(targetHostsFullPath);
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
        this.serviceParams.AttackServiceHost.LogMessage("The number of \'Target hosts\' for DnsPoisoning is zero/null");
      }

      // Write
      using (var outfile = new StreamWriter(targetHostsFullPath))
      {
        outfile.Write(arpPoisoningHostsRecords);
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.WriteTargetSystemsConfigFile(): Wrote: {0} target systems to {1}",
                                                        targetList.Keys?.Count ?? 0, targetHostsFullPath);

      }
    }

    #endregion

    #endregion

  }
}
