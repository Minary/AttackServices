namespace Minary.AttackService.Main
{
  using MinaryLib.AttackService.Class;
  using MinaryLib.AttackService.Enum;
  using MinaryLib.AttackService.Interface;
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.IO;


  public class AS_Sniffer : IAttackService
  {

    #region MEMBERS

    private const string serviceName = "Sniffer";
    private ServiceStatus serviceStatus;
    private AttackServiceParameters serviceParams;
    private Process snifferProc;

    // Sniffer process config
    private static string snifferBinaryPath = Path.Combine(serviceName, "Sniffer.exe");

    #endregion


    #region PUBLIC

    public AS_Sniffer(AttackServiceParameters serviceParams)
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
      var exitCode = -99999;

      try
      {
        exitCode = this.snifferProc.ExitCode;
      }
      catch (Exception)
      {
        exitCode = -99999;
      }

      this.snifferProc.EnableRaisingEvents = false;
      this.snifferProc.Exited += null;
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
      var snifferBinaryFullPath = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, snifferBinaryPath);
      var workingDirectory = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, serviceName);
      var processParameters = $"-x {serviceParameters.SelectedIfcId} -p {this.serviceParams.PipeName}";

      this.snifferProc = new Process();
      this.snifferProc.StartInfo.FileName = snifferBinaryFullPath;
      this.snifferProc.StartInfo.Arguments = processParameters;
      this.snifferProc.StartInfo.WorkingDirectory = workingDirectory;
      this.snifferProc.StartInfo.WindowStyle = this.serviceParams.AttackServiceHost.IsDebuggingOn ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden;
      this.snifferProc.StartInfo.CreateNoWindow = this.serviceParams.AttackServiceHost.IsDebuggingOn ? true : false;
      this.snifferProc.EnableRaisingEvents = true;
      this.snifferProc.Exited += new EventHandler(this.OnServiceExited);

      this.serviceParams.AttackServiceHost.LogMessage("DataSniffer.StartService(): CommandLine:{0} {1}", snifferBinaryPath, processParameters);
      this.serviceStatus = ServiceStatus.Running;
      this.snifferProc.Start();

      return ServiceStatus.Running;
    }


    public ServiceStatus StopService()
    {
      if (this.snifferProc == null)
      {
        this.serviceParams.AttackServiceHost.LogMessage("DataSniffer.StopService(): Can't stop attack service because it never was started");
        this.serviceStatus = ServiceStatus.NotRunning;
        return ServiceStatus.NotRunning;
      }

      this.snifferProc.EnableRaisingEvents = false;
      this.snifferProc.Exited += null;
      this.serviceStatus = ServiceStatus.NotRunning;

      try
      {
        if (this.snifferProc?.HasExited == false)
        {
          this.snifferProc.Kill();
          this.snifferProc = null;
        }
      }
      catch (Exception ex)
      {
        this.serviceParams.AttackServiceHost.LogMessage("DataSniffer.StopService(Exception): {0}", ex.Message);
      }
      finally
      {
        this.snifferProc = null;
      }

      return ServiceStatus.NotRunning;
    }

    
    public void WriteTargetSystemsConfigFile(Dictionary<string, string> targetList)
    {
    }

    #endregion

    #endregion

  }
}
