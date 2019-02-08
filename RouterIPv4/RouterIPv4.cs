namespace Minary.AttackService.Main
{
  using MinaryLib.AttackService.Class;
  using MinaryLib.AttackService.Enum;
  using MinaryLib.AttackService.Interface;
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.IO;


  public class AS_RouterIPv4 : IAttackService
  {

    #region MEMBERS

    private const string serviceName = "RouterIPv4";
    private ServiceStatus serviceStatus;
    private AttackServiceParameters serviceParams;
    private Process routerIPv4Proc;

    // RouterIPv4 process config
    private static string routerIPv4BinaryPath = Path.Combine(serviceName, "RouterIPv4.exe");

    #endregion


    #region PUBLIC

    public AS_RouterIPv4(AttackServiceParameters serviceParams)
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
        exitCode = this.routerIPv4Proc.ExitCode;
      }
      catch (Exception)
      {
        exitCode = -99999;
      }

      this.routerIPv4Proc.EnableRaisingEvents = false;
      this.routerIPv4Proc.Exited += null;
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
      var routerIPv4BinaryFullPath = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, routerIPv4BinaryPath);
      var workingDirectory = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, serviceName);
      var processParameters = $"-s {serviceParameters.SelectedIfcId} -p {this.serviceParams.PipeName}";

      this.routerIPv4Proc = new Process();
      this.routerIPv4Proc.StartInfo.FileName = routerIPv4BinaryFullPath;
      this.routerIPv4Proc.StartInfo.Arguments = processParameters;
      this.routerIPv4Proc.StartInfo.WorkingDirectory = workingDirectory;
      this.routerIPv4Proc.StartInfo.WindowStyle = this.serviceParams.AttackServiceHost.IsDebuggingOn ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden;
      this.routerIPv4Proc.StartInfo.CreateNoWindow = this.serviceParams.AttackServiceHost.IsDebuggingOn ? true : false;
      this.routerIPv4Proc.EnableRaisingEvents = true;
      this.routerIPv4Proc.Exited += new EventHandler(this.OnServiceExited);

      this.serviceParams.AttackServiceHost.LogMessage("RouterIPv4.StartService(): CommandLine:{0} {1}", routerIPv4BinaryPath, processParameters);
      this.serviceStatus = ServiceStatus.Running;
      this.routerIPv4Proc.Start();

      return ServiceStatus.Running;
    }


    public ServiceStatus StopService()
    {
      if (this.routerIPv4Proc == null)
      {
        this.serviceParams.AttackServiceHost.LogMessage("RouterIPv4.StopService(): Can't stop attack service because it never was started");
        this.serviceStatus = ServiceStatus.NotRunning;
        return ServiceStatus.NotRunning;
      }

      this.routerIPv4Proc.EnableRaisingEvents = false;
      this.routerIPv4Proc.Exited += null;
      this.serviceStatus = ServiceStatus.NotRunning;

      try
      {
        if (this.routerIPv4Proc?.HasExited == false)
        {
          this.routerIPv4Proc.Kill();
          this.routerIPv4Proc = null;
        }
      }
      catch (Exception ex)
      {
        this.serviceParams.AttackServiceHost.LogMessage("RouterIPv4.StopService(Exception): {0}", ex.Message);
      }
      finally
      {
        this.routerIPv4Proc = null;
      }

      return ServiceStatus.NotRunning;
    }

    #endregion

    #endregion


  }
}
