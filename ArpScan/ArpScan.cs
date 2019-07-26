namespace Minary.AttackService.Main
{
  using MinaryLib.AttackService.Class;
  using MinaryLib.AttackService.Enum;
  using MinaryLib.AttackService.Interface;
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.IO;


  public class AS_ArpScan : IAttackService
  {

    #region MEMBERS

    private const string serviceName = "ArpScan";
    private ServiceStatus serviceStatus;
    private AttackServiceParameters serviceParams;
    private Process arpScanProc;

    // ArpScan process config
    private static string arpScanBinaryPath = Path.Combine(serviceName, "ArpScan.exe");

    #endregion


    #region PUBLIC

    public AS_ArpScan(AttackServiceParameters serviceParams)
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
        exitCode = this.arpScanProc.ExitCode;
      }
      catch (Exception)
      {
        exitCode = -99999;
      }

      this.arpScanProc.EnableRaisingEvents = false;
      this.arpScanProc.Exited += null;
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
      var arpScanBinaryFullPath = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, arpScanBinaryPath);
      var workingDirectory = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, serviceName);
      var processParameters = $"{serviceParameters.SelectedIfcId} {this.serviceParams}";

      this.arpScanProc = new Process();
      this.arpScanProc.StartInfo.FileName = arpScanBinaryFullPath;
      this.arpScanProc.StartInfo.Arguments = processParameters;
      this.arpScanProc.StartInfo.WorkingDirectory = workingDirectory;
      this.arpScanProc.StartInfo.WindowStyle = this.serviceParams.AttackServiceHost.IsDebuggingOn ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden;
      this.arpScanProc.StartInfo.CreateNoWindow = this.serviceParams.AttackServiceHost.IsDebuggingOn ? true : false;
      this.arpScanProc.EnableRaisingEvents = true;
      this.arpScanProc.Exited += new EventHandler(this.OnServiceExited);

      this.serviceParams.AttackServiceHost.LogMessage("ArpScan.StartService(): CommandLine:{0} {1}", arpScanBinaryPath, processParameters);
      this.serviceStatus = ServiceStatus.Running;
      this.arpScanProc.Start();

      return ServiceStatus.Running;
    }


    public ServiceStatus StopService()
    {
      if (this.arpScanProc == null)
      {
        this.serviceParams.AttackServiceHost.LogMessage("ArpScan.StopService(): Can't stop attack service because it never was started");
        this.serviceStatus = ServiceStatus.NotRunning;
        return ServiceStatus.NotRunning;
      }

      this.arpScanProc.EnableRaisingEvents = false;
      this.arpScanProc.Exited += null;
      this.serviceStatus = ServiceStatus.NotRunning;

      try
      {
        if (this.arpScanProc?.HasExited == false)
        {
          this.arpScanProc.Kill();
          this.arpScanProc = null;
        }
      }
      catch (Exception ex)
      {
        this.serviceParams.AttackServiceHost.LogMessage("ArpScan.StopService(Exception): {0}", ex.Message);
      }
      finally
      {
        this.arpScanProc = null;
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
