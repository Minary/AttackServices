namespace Minary.AttackService.Main
{
  using MinaryLib.AttackService.Class;
  using MinaryLib.AttackService.Enum;
  using MinaryLib.AttackService.Interface;
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.IO;


  public class AS_DnsPoisoning : IAttackService
  {

    #region MEMBERS

    private const string serviceName = "DnsPoisoning";

    private ServiceStatus serviceStatus;
    private AttackServiceParameters serviceParams;
    private Process poisoningEngProc;

    // DnsPoisoning process config
    private static string dnsPoisoningHostsFile = ".dnshosts";

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

    public ServiceStatus StartService(StartServiceParameters serviceParameters, Dictionary<string, object> pluginsParameters)
    {
      var poisoningHostsRecords = string.Empty;
      var workingDirectory = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, serviceName);
      var poisoningHostsFullPath = Path.Combine(workingDirectory, dnsPoisoningHostsFile);
      var timeStamp = DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss");
      var processParameters = $"-x {serviceParameters.SelectedIfcId}";

      if (File.Exists(poisoningHostsFullPath))
      {
        File.Delete(poisoningHostsFullPath);
      }

      if (string.IsNullOrEmpty(serviceParameters.SelectedIfcId))
      {
        throw new Exception("No interface was declared");
      }

      if (serviceParameters.TargetList.Count <= 0)
      {
        this.serviceStatus = ServiceStatus.NotRunning;
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.StartService(): No target system selected");
      }

      if (pluginsParameters == null ||
          pluginsParameters.Count <= 0 &&
          pluginsParameters.ContainsKey("dnspoisoning") == false)
      {
        this.serviceStatus = ServiceStatus.NotRunning;
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.StartService(): No poisoning parameters were passed");
      }

      List<string> pluginParamsList = pluginsParameters["dnspoisoning"] as List<string>;
      if (pluginParamsList.Count > 0)
      {
        poisoningHostsRecords = string.Join("\r\n", pluginParamsList);
      }

      if (string.IsNullOrEmpty(poisoningHostsRecords) || 
          string.IsNullOrWhiteSpace(poisoningHostsRecords))
      {
        this.serviceStatus = ServiceStatus.NotRunning;
        this.serviceParams.AttackServiceHost.LogMessage("DnsPoisoning.StartService(): Could not determine poisoning records");
      }

      using (var outfile = new StreamWriter(poisoningHostsFullPath))
      {
        outfile.Write(poisoningHostsRecords);
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

    #endregion

  }
}
