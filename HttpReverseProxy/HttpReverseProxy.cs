namespace Minary.AttackService.Main
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


  public class AS_HttpReverseProxy : IAttackService
  {

    #region MEMBERS

    private const string serviceName = "HttpReverseProxy";

    private ServiceStatus serviceStatus;
    private AttackServiceParameters serviceParams;
    private Process httpReverseProxyProc;

    // Sniffer process config
    private static string httpReverseProxyBinaryPath = Path.Combine(serviceName, "HttpReverseProxy.exe");

    #endregion
    

    #region PUBLIC

    public AS_HttpReverseProxy(AttackServiceParameters serviceParams)
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
        exitCode = this.httpReverseProxyProc.ExitCode;
      }
      catch (Exception)
      {
        exitCode = -99999;
      }

      this.httpReverseProxyProc.EnableRaisingEvents = false;
      this.httpReverseProxyProc.Exited += null;
      this.serviceParams.AttackServiceHost.OnServiceExited(serviceName, exitCode);
    }


    private bool IsPortAvailable(int portNo)
    {
      if (portNo <= 0 || portNo > 65535)
      {
        throw new Exception("The port is invalid");
      }

      var isPortAvailable = true;
      var ipGlobalProperties = IPGlobalProperties.GetIPGlobalProperties();
      var ipEndPoints = ipGlobalProperties.GetActiveTcpListeners();

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

    public string ServiceName { get { return serviceName; } set { } }

    public ServiceStatus Status { get { return this.serviceStatus; } set { this.serviceStatus = value; } }

    #endregion


    #region PUBLIC

    public ServiceStatus StartService(StartServiceParameters serviceParameters, Dictionary<string, List<object>> pluginsParameters)
    {
      var proxyBinaryFullPath = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, httpReverseProxyBinaryPath);
      var workingDirectory = Path.Combine(this.serviceParams.AttackServicesWorkingDirFullPath, serviceName);
      var hostName = "localhost";
      var validityStartDate = DateTime.Now;
      var validityEndDate = validityStartDate.AddYears(10);
      var certificateFileName = "defaultCertificate.pfx";
      var certificateDirectoryName = "Certificates";
      var certificateDirectoryFullPath = Path.Combine(workingDirectory, certificateDirectoryName);
      var certificateFileFullPath = Path.Combine(certificateDirectoryFullPath, certificateFileName);
      var certificateRelativePath = Path.Combine(certificateDirectoryName, certificateFileName);

      string processParameters = $"/httpport 80 /httpsport 443 /loglevel info /certificate {certificateRelativePath}";

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
      this.httpReverseProxyProc.StartInfo.FileName = proxyBinaryFullPath;
      this.httpReverseProxyProc.StartInfo.Arguments = processParameters;
      this.httpReverseProxyProc.StartInfo.WindowStyle = this.serviceParams.AttackServiceHost.IsDebuggingOn ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden;
      this.httpReverseProxyProc.StartInfo.CreateNoWindow = this.serviceParams.AttackServiceHost.IsDebuggingOn ? true : false;
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
        if (this.httpReverseProxyProc.HasExited == false)
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
