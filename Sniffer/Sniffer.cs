namespace Minary.AttackService
{
  using MinaryLib.AttackService.Class;
  using MinaryLib.AttackService.Enum;
  using MinaryLib.AttackService.Interface;
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.IO;


  public class Sniffer : IAttackService
  {

    #region MEMBERS
    
    private ServiceStatus serviceStatus;
    private AttackServiceParameters serviceParams;
    private Process snifferProc;
    private Dictionary<string, SubModule> subModules;

    // Sniffer process config
    public static string attackServicesDir = "attackservices";
    private static string snifferServiceDir = Path.Combine(attackServicesDir, "Sniffer");
    private static string snifferBinaryPath = Path.Combine(snifferServiceDir, "Sniffer.exe");

    #endregion


    #region PUBLIC

    public Sniffer(AttackServiceParameters serviceParams, Dictionary<string, SubModule> subModules)
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
        exitCode = this.snifferProc.ExitCode;
      }
      catch (Exception)
      {
        exitCode = -99999;
      }

      this.snifferProc.EnableRaisingEvents = false;
      this.snifferProc.Exited += null;
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
      string snifferBinaryFullPath = Path.Combine(Directory.GetCurrentDirectory(), snifferBinaryPath);
      string workingDirectory = Path.Combine(Directory.GetCurrentDirectory(), snifferServiceDir);
      string processParameters = string.Format("-s {0} -p {1}", serviceParameters.SelectedIfcId, this.serviceParams.PipeName);

      this.snifferProc = new Process();
      this.snifferProc.StartInfo.FileName = snifferBinaryPath;
      this.snifferProc.StartInfo.Arguments = processParameters;
      this.snifferProc.StartInfo.WorkingDirectory = workingDirectory;
      this.snifferProc.StartInfo.WindowStyle = this.serviceParams.IsDebuggingOn ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden;
      this.snifferProc.StartInfo.CreateNoWindow = this.serviceParams.IsDebuggingOn ? true : false;
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
        if (this.snifferProc != null && !this.snifferProc.HasExited)
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

    #endregion

    #endregion

  }
}
