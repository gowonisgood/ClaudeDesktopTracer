using System;
using System.Diagnostics;
using System.IO;

using System.Text.Json;
using System.Text.Json.Serialization;

using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

using System.Management;


using System.Collections.Concurrent;
using System.Linq;

using static System.Runtime.InteropServices.JavaScript.JSType;

using System.Security.Permissions;
using System.Security.Principal;


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

    /* 관리자 권한 체크 함수 */
    static bool IsAdministrator()
    {
        using WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
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
        ConcurrentDictionary<string, string> exeDic = new();
        ConcurrentDictionary<string, string> runtimeDic = new();

        McpServer? mcpServer = JsonSerializer.Deserialize<McpServer>(jsonConfig);
        foreach (var server in mcpServer?.McpServers ?? new Dictionary<string, commandArgsEnv>())
        {

            if (server.Value.command.Contains(".exe"))
            {
                exeDic[server.Key] = server.Value.command;
                continue;
            }
            runtimeDic[server.Key] = server.Value.command + ".exe";
            Console.WriteLine(runtimeDic[server.Key]);

        }
#endif

        /* ETW로 Local MCP Server 이벤트 탐지 */

        // 1. 변수 선언
        const string sessionName = "MCPServerSession";
        const string targetProcName = "claude.exe"; //TODO : 하드코딩 이지만 추후 변경 필요
        ConcurrentDictionary<int, (int? ppid, DateTime start)> Live = new();
        ConcurrentDictionary<int, (int? ppid, DateTime start, DateTime stop)> Dead = new();

        //2. Seed , 현재 떠 있는 대상 프로세스 미리 등록
        //TODO : 현재 떠 있는 Local MCP Server도 등록 해야함, 지금은 claude.exe 떠있는 것만 등록 됨
        foreach (var p in Process.GetProcessesByName(System.IO.Path.GetFileNameWithoutExtension(targetProcName)))
        {
            Live[p.Id] = (GetPPid(p.Id), DateTime.Now);
            Console.WriteLine($"[Seed] PID: {p.Id}, PPID: {Live[p.Id].ppid}");
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
            if (pName.Equals(targetProcName))
            {

                var pid = e.ProcessID;
                var ppid = e.ParentID == 0 ? (int?)null : e.ParentID;

                Live[pid] = (ppid, e.TimeStamp.ToLocalTime());

                //Console.WriteLine($"[Start]  pid={pid,-6} ppid={ppid,-6} time={e.TimeStamp:yyyy-MM-dd HH:mm:ss.fff}");
                //Console.WriteLine($"[Start]  pid={pid,-6} ppid={ppid,-6} time={e.TimeStamp:yyyy-MM-dd HH:mm:ss.fff} " +
                //      $"cmd={(e.CommandLine ?? "(no cmd)")}"); //해당 프로세스가 실행되게 된 commandline
            }


            //runtime의 ppid가 cladue의 pid  인경우

            foreach (var li in Live)
            {
                if (e.ParentID == li.Key)
                {
                    foreach (string runtime in runtimeDic.Values)
                    {
                        //TODO : 어떤 서버 실행 하는지도 구별 기능 필요. 지금은 그냥 claude의 자식인 uv.exe면 무조건 프로세스 출력하게 해둠. (uv.exe로 실행하는게 하나가 아닐 수도 있음)
                        if (pName.Equals(runtime))
                        {
                            var pid = e.ProcessID;
                            var ppid = e.ParentID == 0 ? (int?)null : e.ParentID;
                            Console.WriteLine($"[Start]  pid={pid,-6} ppid={ppid,-6} time={e.TimeStamp:yyyy-MM-dd HH:mm:ss.fff} " +
                  $"cmd={(e.CommandLine ?? "(no cmd)")}");
                            continue;
                        }
                    }
                    foreach (string exe in exeDic.Values)
                    {
                        if (exe.Contains(pName))
                        {
                            var pid = e.ProcessID;
                            var ppid = e.ParentID == 0 ? (int?)null : e.ParentID;
                            Console.WriteLine($"[Start]  pid={pid,-6} ppid={ppid,-6} time={e.TimeStamp:yyyy-MM-dd HH:mm:ss.fff} " +
                                $"cmd={(e.CommandLine ?? "(no cmd)")}");
                            continue;
                        }
                    }

                }
            }
        };

        //이벤트 핸들러 등록 (프로세스 종료)
        source.Kernel.ProcessStop += e =>
        {
            var pid = e.ProcessID;
            if (Live.TryRemove(pid, out var dpid))
            {
                Dead[pid] = (dpid.ppid, dpid.start, e.TimeStamp.ToLocalTime());
                //Console.WriteLine($"[Stop ]  pid={pid,-6} lived={(e.TimeStamp - dpid.start).TotalSeconds,6:F1}s");
            }
        };




        source.Process();
    }
}