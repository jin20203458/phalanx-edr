using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using Phalanx.Shared.Protos;
using ActionType = Phalanx.Shared.Protos.MitigationCommand.Types.ActionType;

namespace Phalanx.Cockpit.Services;

/// <summary>
/// C++ 네이티브 커널 센서(Phalanx.Sensor.exe)의 UAC 관리자 권한 기동 및
/// 세션 로컬 Win32 명명 이벤트 / gRPC 기반 Graceful Shutdown을 관장하는 제어 서비스.
/// </summary>
public class SensorProcessController
{
    public static SensorProcessController Instance { get; } = new();

    private Process? _sensorProcess;
    private readonly CockpitUiBridge _uiBridge;

    public bool IsSensorRunning { get; private set; }
    public event Action<bool>? SensorStateChanged;

    /// <summary>
    /// C++ 센서가 연결할 Cockpit gRPC 수신 엔드포인트 (기본: 127.0.0.1:50051)
    /// </summary>
    public string Endpoint { get; set; } = "127.0.0.1:50051";

    /// <summary>
    /// C++ 센서 기본 워치독 제한시간(초) (기본: 10초)
    /// </summary>
    public int WatchdogTimeoutSec { get; set; } = 10;

    /// <summary>
    /// C++ 센서 AI 수사 1회성 연장 제한시간(초) (기본: 50초)
    /// </summary>
    public int ExtendTimeoutSec { get; set; } = 50;

    public SensorProcessController(CockpitUiBridge? uiBridge = null)
    {
        _uiBridge = uiBridge ?? CockpitUiBridge.Instance;
        _uiBridge.SensorConnectionChanged += OnSensorConnectionChanged;
        LoadSettingsFromAppSettings();
    }

    private void LoadSettingsFromAppSettings()
    {
        try
        {
            string[] candidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "AppSettings.json"),
                Path.Combine(Directory.GetCurrentDirectory(), "AppSettings.json"),
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, @"..\..\..\..\src\Phalanx.Cockpit\AppSettings.json"))
            };

            foreach (var path in candidates)
            {
                if (File.Exists(path))
                {
                    var json = File.ReadAllText(path);
                    using var doc = System.Text.Json.JsonDocument.Parse(json);
                    var root = doc.RootElement;
                    if (root.TryGetProperty("Sensor", out var s))
                    {
                        string host = s.TryGetProperty("Host", out var h) && !string.IsNullOrWhiteSpace(h.GetString()) ? h.GetString()! : "127.0.0.1";
                        int port = s.TryGetProperty("Port", out var p) && p.TryGetInt32(out var pVal) ? pVal : 50051;
                        Endpoint = $"{host}:{port}";
                    }
                    if (root.TryGetProperty("Gemini", out var g))
                    {
                        if (g.TryGetProperty("WatchdogTimeoutSec", out var wt) && wt.TryGetInt32(out var wtVal))
                            WatchdogTimeoutSec = Math.Clamp(wtVal, 1, 60);
                        if (g.TryGetProperty("CtsTimeoutSec", out var ct) && ct.TryGetInt32(out var ctVal))
                            ExtendTimeoutSec = Math.Clamp(ctVal, 5, 300);
                    }
                    break;
                }
            }
        }
        catch { }
    }

    private void OnSensorConnectionChanged(bool isConnected)
    {
        if (isConnected && !IsSensorRunning)
        {
            IsSensorRunning = true;
            SensorStateChanged?.Invoke(true);
        }
        else if (!isConnected && IsSensorRunning && (_sensorProcess == null || _sensorProcess.HasExited))
        {
            IsSensorRunning = false;
            SensorStateChanged?.Invoke(false);
        }
    }

    /// <summary>
    /// C++ 센서 실행 파일(Phalanx.Sensor.exe) 위치를 동적으로 탐색합니다.
    /// </summary>
    public string? ResolveSensorBinaryPath()
    {
        string baseDir = AppContext.BaseDirectory;

        // 1. AppContext 기준 상대 경로 (bin/Debug/net9.0-windows -> out/build/windows-default/...)
        string candidate1 = Path.GetFullPath(Path.Combine(baseDir, @"..\..\..\..\out\build\windows-default\src\Phalanx.Sensor\Phalanx.Sensor.exe"));
        if (File.Exists(candidate1)) return candidate1;

        // 2. 현재 작업 디렉터리 기준
        string candidate2 = Path.GetFullPath(Path.Combine(Directory.GetCurrentDirectory(), @"out\build\windows-default\src\Phalanx.Sensor\Phalanx.Sensor.exe"));
        if (File.Exists(candidate2)) return candidate2;

        // 3. 상위 디렉터리 순회 탐색 (Phalanx.sln이 있는 루트 디렉터리 기반)
        var dir = new DirectoryInfo(baseDir);
        while (dir != null && dir.Exists)
        {
            string slnCheck = Path.Combine(dir.FullName, "Phalanx.sln");
            string slnxCheck = Path.Combine(dir.FullName, "Phalanx.slnx");
            if (File.Exists(slnCheck) || File.Exists(slnxCheck))
            {
                string candidate3 = Path.Combine(dir.FullName, @"out\build\windows-default\src\Phalanx.Sensor\Phalanx.Sensor.exe");
                if (File.Exists(candidate3)) return candidate3;
            }
            dir = dir.Parent;
        }

        return null;
    }

    /// <summary>
    /// UAC 승격(runas)을 통해 C++ 센서를 관리자 권한으로 기동합니다.
    /// </summary>
    public async Task<bool> StartSensorAsync()
    {
        _sensorProcess?.Dispose();
        _sensorProcess = null;

        // 1. 이미 외부 또는 백그라운드에서 센서가 돌고 있는지 확인
        var existing = Process.GetProcessesByName("Phalanx.Sensor");
        if (existing.Length > 0)
        {
            for (int i = 1; i < existing.Length; i++)
            {
                try { existing[i].Dispose(); } catch { }
            }

            Console.WriteLine($"[SensorController] 이미 실행 중인 Phalanx.Sensor 프로세스 감지 (PID: {existing[0].Id})");
            _sensorProcess = existing[0];
            try
            {
                _sensorProcess.EnableRaisingEvents = true;
                _sensorProcess.Exited += (s, e) =>
                {
                    Console.WriteLine("[SensorController] C++ 커널 센서 프로세스 종료 감지.");
                    IsSensorRunning = false;
                    SensorStateChanged?.Invoke(false);
                };
            }
            catch { }

            IsSensorRunning = true;
            SensorStateChanged?.Invoke(true);
            return true;
        }

        string? exePath = ResolveSensorBinaryPath();
        if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
        {
            Console.WriteLine("[SensorController] Phalanx.Sensor.exe 바이너리를 찾을 수 없습니다. 빌드 상태를 확인하십시오.");
            return false;
        }

        string workingDir = Path.GetDirectoryName(exePath)!;

        var psi = new ProcessStartInfo
        {
            FileName = exePath,
            Arguments = $"--endpoint {Endpoint} --watchdog-timeout {WatchdogTimeoutSec} --extend-timeout {ExtendTimeoutSec}",
            WorkingDirectory = workingDir, // Gate 1 필수 지침: 7개 종속 DLL 로더 실패(0xC0000135) 방지
            UseShellExecute = true,
            Verb = "runas" // UAC 팝업 요청
        };

        try
        {
            Console.WriteLine($"[SensorController] C++ 커널 센서 UAC 승격 기동 시도: {exePath}");
            _sensorProcess = Process.Start(psi);

            if (_sensorProcess != null)
            {
                _sensorProcess.EnableRaisingEvents = true;
                _sensorProcess.Exited += (s, e) =>
                {
                    Console.WriteLine("[SensorController] C++ 커널 센서 프로세스 종료 감지.");
                    IsSensorRunning = false;
                    SensorStateChanged?.Invoke(false);
                };

                IsSensorRunning = true;
                SensorStateChanged?.Invoke(true);
                return true;
            }
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // 사용자가 UAC 권한 승인을 '아니오'로 취소한 경우 (ERROR_CANCELLED)
            Console.WriteLine("[SensorController] 사용자가 UAC 관리자 권한 승인을 취소했습니다.");
            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SensorController] 센서 프로세스 기동 예외: {ex.Message}");
            return false;
        }

        return false;
    }

    /// <summary>
    /// gRPC 역전송 및 세션 로컬 Win32 이벤트를 통해 C++ 센서를 안전하게 종료(Graceful Shutdown)합니다.
    /// </summary>
    public async Task StopSensorAsync()
    {
        Console.WriteLine("[SensorController] C++ 커널 센서 종료 절차 개시...");

        // 1단계: gRPC 완화 명령 스트림을 통한 제어 종료 신호 전송
        try
        {
            await _uiBridge.SendManualCommandAsync(new MitigationCommand
            {
                Action = ActionType.ActionKill,
                TargetPid = 0,
                Reason = "PHALANX_SENSOR_SHUTDOWN"
            });
            Console.WriteLine("[SensorController] gRPC PHALANX_SENSOR_SHUTDOWN 명령 전송 완료.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SensorController] gRPC 종료 명령 전송 실패 (바이패스): {ex.Message}");
        }

        // 2단계: 세션 로컬 Win32 명명 이벤트 시그널링 (gRPC 단절 시에도 안전 종료 보장)
        try
        {
            using var shutdownEvent = EventWaitHandle.OpenExisting(@"Local\PhalanxSensorShutdownEvent");
            shutdownEvent.Set();
            Console.WriteLine(@"[SensorController] Win32 Local\PhalanxSensorShutdownEvent 시그널 전송 완료.");
        }
        catch (WaitHandleCannotBeOpenedException)
        {
            // 이벤트가 아직 생성되지 않았거나 이미 종료된 경우 무시
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SensorController] Win32 이벤트 시그널 실패: {ex.Message}");
        }

        // 3단계: 센서 프로세스 정상 종료 대기 (최대 3초)
        if (_sensorProcess != null)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await _sensorProcess.WaitForExitAsync(cts.Token);
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("[SensorController] 센서 정상 종료 대기 시간 초과(3초). 강제 프로세스 종료를 시도합니다.");
                try
                {
                    if (!_sensorProcess.HasExited)
                    {
                        _sensorProcess.Kill(entireProcessTree: true);
                    }
                }
                catch (Exception killEx)
                {
                    Console.WriteLine($"[SensorController] 센서 강제 종료 실패: {killEx.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[SensorController] 센서 종료 대기 중 예외: {ex.Message}");
            }
            finally
            {
                try
                {
                    _sensorProcess.Dispose();
                }
                catch { }
                _sensorProcess = null;
            }
        }

        IsSensorRunning = false;
        SensorStateChanged?.Invoke(false);
        Console.WriteLine("[SensorController] C++ 커널 센서 안전 정리 완료.");
    }
}
