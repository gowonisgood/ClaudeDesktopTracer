using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.AutomatedAnalysis;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Windows.EventTracing.Processes;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.Permissions;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using static System.Runtime.InteropServices.JavaScript.JSType;


/* config 파일을 파싱하기 위한 class*/
public class McpServer
{
    [JsonPropertyName("mcpServers")]
    public Dictionary<string, commandArgsEnv>? McpServers { get; set; }
}

public class commandArgsEnv
{
    public string? command { get; set; }
    public IList<string>? args { get; set; }
    public Dictionary<string, string>? env { get; set; }
}

class Program
{
    /* parent pid를 구하는 함수, 원래 떠있던 프로세스의 ppid를 얻기 위함 */
    static int? GetPPid(int pid)
    {
        try
        {
            // 1. WMI 쿼리를 사용하여 프로세스의 부모 PID를 가져옴
            using var q = new System.Management.ManagementObjectSearcher(
                $"SELECT ParentProcessId FROM Win32_Process WHERE ProcessId = {pid}");

            // 2. 쿼리 결과에서 ParentProcessId를 추출
            return q.Get().Cast<System.Management.ManagementObject>()
                .Select(mo => (int)(uint)mo["ParentProcessId"]).FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    /* commandline을 구하는 함수 , 원래 떠있던 프로세스의 commandline을 얻기 위함 */
    static string GetCommandLine(int pid)
    {
        try
        {
            using var q = new ManagementObjectSearcher(
                $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");

            foreach (ManagementObject obj in q.Get())
            {
                return obj["CommandLine"]?.ToString() ?? string.Empty;
            }
        }
        catch
        {
            return string.Empty;
        }
        return string.Empty;
    }

    /* 재귀적으로 하위 프로세스 찾는 함수 */
    //#TODO : 성능 최적화 필요
    static void FindAndRegisterSubprocesses(int parentPid, string serverName, ConcurrentDictionary<int, (string serverName, int? ppid, DateTime start)> localSLive)
    {
        foreach (var p in System.Diagnostics.Process.GetProcesses())
        {
            try
            {
                int? ppid = GetPPid(p.Id);
                if (ppid == parentPid && !localSLive.ContainsKey(p.Id))
                {
                    localSLive[p.Id] = (serverName, ppid, DateTime.Now);
                    Console.WriteLine($"[Seed] Subprocess of {serverName}: PID: {p.Id}, PPID: {ppid}");
                    FindAndRegisterSubprocesses(p.Id, serverName, localSLive);
                }
            }
            catch
            {
                Console.WriteLine($"[Error] 접근 실패");
            }
        }
    }

    /* 관리자 권한 체크 함수 */
    static bool IsAdministrator()
    {
        using WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    /* 런타임 실행 경우 : CommandLine에서 Server Name 추출 함수  */
    static string IdentifyServerFromCommandLine(string commandLine, ConcurrentDictionary<string, (string command, List<string> args)> serverDic)
    {
        if (string.IsNullOrEmpty(commandLine)) return "Unknown";

        foreach (var server in serverDic)
        {
            bool allArgsMatch = true;

            foreach (var arg in server.Value.args)
            {
                if (string.IsNullOrEmpty(arg)) continue;

                if (!commandLine.Contains(arg))
                {
                    allArgsMatch = false;
                    break;
                }
            }

            //모든 args가 매칭 되면 해당 서버로 식별
            if (allArgsMatch && server.Value.args.Count > 0)
            {
                return server.Key;
            }
        }
        return "Unknown";
    }


    static void Main(string[] args)
    {
        /* 관리자 권한 체크 */
        if (!IsAdministrator())
        {
            Console.WriteLine("Administrator privileges are required to run this program.");
            return;
        }

        /* claude desktop config 파일 파싱 */
        //TODO: 지금은 하드 코딩이지만 사용자 별로 경로를 자동으로 찾는 기능 구현 필요
        StreamReader sr = new StreamReader("C:\\Users\\gowon\\AppData\\Roaming\\Claude\\claude_desktop_config.json");
        string jsonConfig = sr.ReadToEnd();


#if DEBUG
        Console.WriteLine("[DEBUG] claude desktop json 인자 파싱 결과");
        McpServer? mcpServer = JsonSerializer.Deserialize<McpServer>(jsonConfig); //?의 의미는 null일수도있다
        foreach (var server in mcpServer?.McpServers ?? new Dictionary<string, commandArgsEnv>())
        {
            Console.WriteLine($"Server Name: {server.Key}");
            Console.WriteLine($"Command: {server.Value?.command}");
            foreach (string arg in server.Value?.args ?? Array.Empty<string>()) //??의 의미는 null일경우 오른쪽 사용
            {
                Console.WriteLine($"Arg: {arg}");
            }
            foreach (var envVar in server.Value?.env ?? new Dictionary<string, string>())
            {
                Console.WriteLine($"Env: {envVar.Key} = {envVar.Value}");
            }

        }
#endif
#if RELEASE
        /* Key: 서버 이름, Value: 어떤 걸로 실행 , args */
        ConcurrentDictionary<string, (string command, List<string> args)> exeDic = new();
        ConcurrentDictionary<string, (string command, List<string> args)> runtimeDic = new();

        McpServer? mcpServer = JsonSerializer.Deserialize<McpServer>(jsonConfig);
        foreach (var server in mcpServer?.McpServers ?? new Dictionary<string, commandArgsEnv>())
        {
            var arg = server.Value?.args?.ToList() ?? new List<string>();

            /* .exe로 직접 실행하는 서버 */
            if (server.Value.command.Contains(".exe"))
            {
                exeDic[server.Key] = (server.Value.command, arg);
                continue;
            }
            /* 런타임으로 실행되는 서버 */
            runtimeDic[server.Key] = (server.Value.command + ".exe", arg);
            Console.WriteLine(runtimeDic[server.Key]);

        }
#endif

        /* ETW로 Local MCP Server 이벤트 탐지 */

        // 1. 변수 선언
        const string sessionName = "MCPServerSession";
        const string targetProcName = "claude.exe"; //TODO : 하드코딩 이지만 추후 변경 필요 (입력으로 받는다던지)
        /* MCP client process 추적 dictionary */
        ConcurrentDictionary<int, (int? ppid, DateTime start)> McpClientLive = new();
        ConcurrentDictionary<int, (int? ppid, DateTime start, DateTime stop)> McpClientDead = new();
        /* Local MCP Server process 추적  dictionary */
        ConcurrentDictionary<int, (string serverName,int? ppid, DateTime start)> LocalSLive = new();
        ConcurrentDictionary<int, (string serverName, int? ppid, DateTime start)> LocalSDead = new();
    

        //2. Seed , 현재 떠 있는 대상 프로세스 미리 등록
        //MCP Client 프로세스
        foreach (var p in System.Diagnostics.Process.GetProcessesByName(System.IO.Path.GetFileNameWithoutExtension(targetProcName)))
        {
            McpClientLive[p.Id] = (GetPPid(p.Id), DateTime.Now);
            Console.WriteLine($"[Seed] PID: {p.Id}, PPID: {McpClientLive[p.Id].ppid}");
        }

        //Local MCP Server 프로세스 (runtime)
        foreach (var runtimeServer in runtimeDic)
        {
            var processes = System.Diagnostics.Process.GetProcessesByName(System.IO.Path.GetFileNameWithoutExtension(runtimeServer.Value.command));
            foreach (var p in processes)
            {
                string commandLine = GetCommandLine(p.Id);
                string identifiedServer = IdentifyServerFromCommandLine(commandLine, runtimeDic);
                if (identifiedServer != "Unknown")
                {
                    LocalSLive[p.Id] = (identifiedServer, GetPPid(p.Id), DateTime.Now);
                    Console.WriteLine($"[Seed] Server: {identifiedServer} PID: {p.Id}, PPID: {LocalSLive[p.Id].ppid}");
                }
            }
        }

        //Local MCP Server 프로세스 (exe)
        foreach (var exeServer in exeDic)
        {
            var processName = System.IO.Path.GetFileNameWithoutExtension(exeServer.Value.command);
            var processes = System.Diagnostics.Process.GetProcessesByName(processName);
            foreach (var p in processes)
            {
                string commandLine = GetCommandLine(p.Id);
                if (commandLine.Contains(exeServer.Value.command))
                {
                    LocalSLive[p.Id] = (exeServer.Key, GetPPid(p.Id), DateTime.Now);
                    Console.WriteLine($"[Seed] Server: {exeServer.Key} PID: {p.Id}, PPID: {LocalSLive[p.Id].ppid}");
                }
            }
        }

        foreach(var (pid, serverInfo) in LocalSLive.ToList())
        {
            FindAndRegisterSubprocesses(pid, serverInfo.serverName, LocalSLive);
        }

        //3. ETW 세션 시작 및 이벤트 핸들러 등록
        using var session = new TraceEventSession(sessionName);
        
        //커널 프로세스 이벤트 활성화 (어떤 공급자를 활성화 시킬지 지정)
        session.EnableKernelProvider(KernelTraceEventParser.Keywords.Process);

        //이벤트 소스 얻기 (이벤트 가져와서 파싱)
        var source = session.Source;

        //이벤트 핸들러 등록 (프로세스 시작)
        source.Kernel.ProcessStart += e =>
        {
            var pName = e.ImageFileName ?? string.Empty;
            var pid = e.ProcessID;
            var ppid = e.ParentID == 0 ? (int?)null : e.ParentID;
            if (pName.Equals(targetProcName))
            {
                McpClientLive[pid] = (ppid, e.TimeStamp.ToLocalTime());
                return;
                //Console.WriteLine($"[Start]  pid={pid,-6} ppid={ppid,-6} time={e.TimeStamp:yyyy-MM-dd HH:mm:ss.fff}");
                //Console.WriteLine($"[Start]  pid={pid,-6} ppid={ppid,-6} time={e.TimeStamp:yyyy-MM-dd HH:mm:ss.fff} " +
                //      $"cmd={(e.CommandLine ?? "(no cmd)")}"); //해당 프로세스가 실행되게 된 commandline
            }


            //runtime의 ppid가 cladue의 pid  인경우

            foreach (var McpClient in McpClientLive)
            {
                if (e.ParentID == McpClient.Key)
                {
                    foreach (var runtimeServer in runtimeDic)
                    {
                        if (pName.Equals(runtimeServer.Value.command))
                        {
                            string commandLine = e.CommandLine ?? "(no cmd)";


                            // commandLine 에서 서버 식별
                            string identifiedServer = IdentifyServerFromCommandLine(commandLine, runtimeDic);

                            Console.WriteLine($"[Start] Server: {identifiedServer}  pid={pid,-6} ppid={ppid,-6} time={e.TimeStamp:yyyy-MM-dd HH:mm:ss.fff} " +
                  $"cmd={commandLine}");
                            LocalSLive[pid] = (identifiedServer, ppid, e.TimeStamp.ToLocalTime());
                            continue; //TODO: 여기 return 인가?
                        }
                    }

                    foreach (var exeServer in exeDic)
                    {
                        if (exeServer.Value.command.Contains(pName))
                        {
                            string commandLine = e.CommandLine ?? "(no cmd)";

                            // commandLine 에서 서버 식별
                            string identifiedServer = "Unknown";
                            if (commandLine.Equals(exeServer.Value.command)) identifiedServer = exeServer.Key;
                            

                            Console.WriteLine($"[Start] Server: {identifiedServer}  pid={pid,-6} ppid={ppid,-6} time={e.TimeStamp:yyyy-MM-dd HH:mm:ss.fff} " +
                  $"cmd={commandLine}");
                            LocalSLive[pid] = (identifiedServer, ppid, e.TimeStamp.ToLocalTime());

                            continue; //TODO: 여기 return 인가?
                        }
                    }

                }
            }

            //Local MCP Server의 하위 프로세스 재귀적으로 탐지
            if(ppid.HasValue && LocalSLive.ContainsKey(ppid.Value))
            {
              var parentServerInfo = LocalSLive[ppid.Value];
                Console.WriteLine($"[Subprocess] Parent Server: {parentServerInfo.serverName}  pid={pid,-6} ppid={ppid,-6} time={e.TimeStamp:yyyy-MM-dd HH:mm:ss.fff} " +
                  $"cmd={(e.CommandLine ?? "(no cmd)")}");

                LocalSLive[pid] = (parentServerInfo.serverName, ppid, e.TimeStamp.ToLocalTime());
            }
        };

        //이벤트 핸들러 등록 (프로세스 종료)
        source.Kernel.ProcessStop += e =>
        {
            var pid = e.ProcessID;
            if (McpClientLive.TryRemove(pid, out var McpClientInfo))
            {
                McpClientDead[pid] = (McpClientInfo.ppid, McpClientInfo.start, e.TimeStamp.ToLocalTime());
                //Console.WriteLine($"[Stop ]  pid={pid,-6} lived={(e.TimeStamp - dpid.start).TotalSeconds,6:F1}s");
            }
            else if (LocalSLive.TryRemove(pid, out var serverInfo))
            {
                LocalSDead[pid] = (serverInfo.serverName, serverInfo.ppid, serverInfo.start);
                Console.WriteLine($"[Stop ] Server: {serverInfo.serverName}  pid={pid,-6} ppid={serverInfo.ppid,-6} " +
                    $"lived={(e.TimeStamp - serverInfo.start).TotalSeconds,6:F1}s");
            }
        };


        source.Process();
    }
}