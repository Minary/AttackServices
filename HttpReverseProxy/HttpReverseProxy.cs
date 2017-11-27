namespace Minary.AttackService
{
  using MinaryLib.AttackService.Class;
  using MinaryLib.AttackService.Enum;
  using MinaryLib.AttackService.Interface;
  using System;
  using System.Collections.Generic;
  using System.Diagnostics;
  using System.IO;
  using System.Net;
  using System.Net.NetworkInformation;


  public class HttpReverseProxy : IAttackService
  {

    #region MEMBERS

    private ServiceStatus serviceStatus;
    private AttackServiceParameters serviceParams;
    private Dictionary<string, SubModule> subModules;
    private Process httpReverseProxyProc;

    // Sniffer process config
    public static string attackServicesDir = "attackservices";
    private static string httpReverseProxyServiceDir = Path.Combine(attackServicesDir, "Sniffer");
    private static string httpReverseProxyBinaryPath = Path.Combine(httpReverseProxyServiceDir, "Sniffer.exe");

    #endregion
    

    #region PUBLIC

    public HttpReverseProxy(AttackServiceParameters serviceParams, Dictionary<string, SubModule> subModules)
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
        exitCode = this.httpReverseProxyProc.ExitCode;
      }
      catch (Exception)
      {
        exitCode = -99999;
      }

      this.httpReverseProxyProc.EnableRaisingEvents = false;
      this.httpReverseProxyProc.Exited += null;
      this.serviceParams.AttackServiceHost.OnServiceExited(this.serviceParams.ServiceName, exitCode);
    }


    private bool IsPortAvailable(int portNo)
    {
      if (portNo <= 0 || portNo > 65535)
      {
        throw new Exception("The port is invalid");
      }

      bool isPortAvailable = true;
      IPGlobalProperties ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
      IPEndPoint[] ipEndPoints = ipGlobalProperties.GetActiveTcpListeners();

      foreach (IPEndPoint endPoint in ipEndPoints)
      {
        if (endPoint.Port == portNo)
        {
          isPortAvailable = false;
          break;
        }
      }

      return isPortAvailable;
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
      string proxyBinaryFullPath = Path.Combine(Directory.GetCurrentDirectory(), httpReverseProxyBinaryPath);
      string workingDirectory = Path.Combine(Directory.GetCurrentDirectory(), attackServicesDir);
      string hostName = "localhost";
      DateTime validityStartDate = DateTime.Now;
      DateTime validityEndDate = validityStartDate.AddYears(10);
      string certificateFileName = "defaultCertificate.pfx";
      string certificateDirectoryName = "Certificates";
      string certificateDirectoryFullPath = Path.Combine(workingDirectory, certificateDirectoryName);
      string certificateFileFullPath = Path.Combine(certificateDirectoryFullPath, certificateFileName);
      string certificateRelativePath = Path.Combine(certificateDirectoryName, certificateFileName);

//      string httpReverseProxyBinaryPath = Path.Combine(Directory.GetCurrentDirectory(), Config.HttpReverseProxyBinaryPath);
      string processParameters = string.Format("/httpport 80 /httpsport 443 /loglevel info /certificate {0}", certificateRelativePath);

      // If certificate directory does not exist create it
      if (!Directory.Exists(certificateDirectoryFullPath))
      {
        Directory.CreateDirectory(certificateDirectoryFullPath);
      }

      // If certificate file does not exist create it.
      if (!File.Exists(certificateFileFullPath))
      {
        NativeWindowsLib.Crypto.Crypto.CreateNewCertificate(certificateFileFullPath, hostName, validityStartDate, validityEndDate);
      }

      // Abort if HTTP port is already in use by another process.
      if (this.IsPortAvailable(80) == false)
      {
        throw new Exception("HTTP port is already in use");
      }

      // Abort if HTTPS port is already in use by another process.
      if (this.IsPortAvailable(443) == false)
      {
        throw new Exception("HTTPS port is already in use");
      }

      // Start process
      this.httpReverseProxyProc = new Process();
      this.httpReverseProxyProc.StartInfo.WorkingDirectory = workingDirectory;
      this.httpReverseProxyProc.StartInfo.FileName = httpReverseProxyBinaryPath;
      this.httpReverseProxyProc.StartInfo.Arguments = processParameters;
      this.httpReverseProxyProc.StartInfo.WindowStyle = this.serviceParams.IsDebuggingOn ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden;
      this.httpReverseProxyProc.StartInfo.CreateNoWindow = this.serviceParams.IsDebuggingOn ? true : false;
      this.httpReverseProxyProc.EnableRaisingEvents = true;
      this.httpReverseProxyProc.Exited += new EventHandler(this.OnServiceExited);

      this.serviceParams.AttackServiceHost.LogMessage("HttpReverseProxy.StartService(): CommandLine:{0} {1}", httpReverseProxyBinaryPath, processParameters);
      this.serviceStatus = ServiceStatus.Running;
      this.httpReverseProxyProc.Start();

      return ServiceStatus.Running;
    }


    public ServiceStatus StopService()
    {
      if (this.httpReverseProxyProc == null)
      {
        this.serviceParams.AttackServiceHost.LogMessage("DataSniffer.StopService(): Can't stop attack service because it never was started");
        this.serviceStatus = ServiceStatus.NotRunning;
        return ServiceStatus.NotRunning;
      }

      this.httpReverseProxyProc.EnableRaisingEvents = false;
      this.httpReverseProxyProc.Exited += null;
      this.serviceStatus = ServiceStatus.NotRunning;

      try
      {
        if (this.httpReverseProxyProc != null && !this.httpReverseProxyProc.HasExited)
        {
          this.httpReverseProxyProc.Kill();
          this.httpReverseProxyProc = null;
        }
      }
      catch (Exception ex)
      {
        this.serviceParams.AttackServiceHost.LogMessage("DataSniffer.StopService(Exception): {0}", ex.Message);
      }
      finally
      {
        this.httpReverseProxyProc = null;
      }

      return ServiceStatus.NotRunning;
    }

    #endregion

    #endregion

  }
}
