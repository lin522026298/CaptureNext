// Windows-only thin shell: no archive logic and no second task queue.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace CaptureNext {
    static class ShellRuntimeDirectory {
        [StructLayout(LayoutKind.Sequential)] struct HandleInfo {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
        static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle file,out HandleInfo information);

        static List<SafeFileHandle> Prepare(string workspace,string runtime) {
            string root=Path.GetFullPath(workspace), target=Path.GetFullPath(runtime).TrimEnd('\\');
            if(root.Length>3) root=root.TrimEnd('\\');
            if(root.StartsWith(@"\\",StringComparison.Ordinal) || root.Length<3 || root[1]!=':' || root[2]!='\\' ||
                (!target.Equals(Path.Combine(root,"archives","wechat-next","product"),StringComparison.OrdinalIgnoreCase) &&
                 !target.Equals(Path.Combine(root,"archives","wechat-next","product-recovery"),StringComparison.OrdinalIgnoreCase)))
                throw new IOException("Runtime directory outside fixed local scope.");
            var paths=new List<string>();
            for(string path=target;path!=null;path=Path.GetDirectoryName(path)) paths.Add(path);
            paths.Reverse();
            var guards=new List<SafeFileHandle>();
            try {
                foreach(string path in paths) {
                    FileAttributes attributes;
                    try { attributes=File.GetAttributes(path); }
                    catch(FileNotFoundException) { attributes=0; }
                    catch(DirectoryNotFoundException) { attributes=0; }
                    if(attributes==0) {
                        // Never create the workspace or an absent ancestor.
                        if(!path.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.OrdinalIgnoreCase))
                            throw new IOException("Runtime workspace must already exist.");
                        Directory.CreateDirectory(path); attributes=File.GetAttributes(path);
                    }
                    if((attributes&FileAttributes.ReparsePoint)!=0 || (attributes&FileAttributes.Directory)==0)
                        throw new IOException("Runtime path must contain only ordinary directories.");
                    // READ_ATTRIBUTES, SHARE_READ, OPEN_EXISTING, and
                    // OPEN_REPARSE_POINT|BACKUP_SEMANTICS. Hold every ancestor
                    // until the marker write ends; never request delete access.
                    var guard=CreateFile(path,0x80,1,IntPtr.Zero,3,0x00200000|0x02000000,IntPtr.Zero);
                    guards.Add(guard); HandleInfo info;
                    if(guard.IsInvalid || !GetFileInformationByHandle(guard,out info) ||
                        (info.Attributes&0x400)!=0 || (info.Attributes&0x10)==0)
                        throw new IOException("Runtime directory guard unavailable.");
                }
                return guards;
            } catch { foreach(var guard in guards) guard.Dispose(); throw; }
        }

        public static void Write(string workspace,string runtime,string contents) {
            var guards=Prepare(workspace,runtime);
            try {
                if(contents==null) return; // Window preflight: no marker rewrite.
                string path=Path.Combine(runtime,"shell.private.json");
                // OPEN_ALWAYS, not CREATE_ALWAYS: inspect the SAME no-follow
                // handle before truncation so a link/file conflict is harmless.
                using(var file=CreateFile(path,0x40000000|0x80,1,IntPtr.Zero,4,0x00200000,IntPtr.Zero)) {
                    HandleInfo info;
                    if(file.IsInvalid || !GetFileInformationByHandle(file,out info) ||
                        (info.Attributes&(0x400|0x10))!=0 || info.Links!=1)
                        throw new IOException("Runtime marker must be an ordinary single-link file.");
                    using(var stream=new FileStream(file,FileAccess.Write)) {
                        byte[] bytes=new UTF8Encoding(false).GetBytes(contents);
                        stream.SetLength(0); stream.Write(bytes,0,bytes.Length); stream.Flush(true);
                    }
                }
            } finally { foreach(var guard in guards) guard.Dispose(); }
        }
    }

    // Pure status projection: never display backend payloads, paths or user data.
    // Stable issue keys deliberately exclude timestamps and last_success.
    class TrayStatus {
        public readonly List<string> Items = new List<string>();
        public readonly List<string> Issues = new List<string>();
        readonly StringBuilder key = new StringBuilder();
        public string FaultKey { get { return key.ToString(); } }
        public string Text(string ordinary) {
            string value=Issues.Count==0?ordinary:"本地聊天档案 · "+String.Join("；",Issues.ToArray());
            return value.Length<=63?value:value.Substring(0,60)+"…";
        }
        static Dictionary<string,object> Map(Dictionary<string,object> parent,string name) {
            object value; return parent.TryGetValue(name,out value)?value as Dictionary<string,object>:null;
        }
        static string Value(Dictionary<string,object> parent,string name) {
            object value; return parent!=null && parent.TryGetValue(name,out value) && value!=null?Convert.ToString(value):"";
        }
        static bool Flag(Dictionary<string,object> parent,string name) { return Value(parent,name)=="True"; }
        void Add(string name,string text,bool attention,string signature) {
            Items.Add(name+"："+text);
            if(!attention) return;
            Issues.Add(name+text);
            key.Append(name.Length).Append(':').Append(name).Append(signature.Length).Append(':').Append(signature);
        }
        void Pipeline(Dictionary<string,object> pipelines,string stage,string label) {
            var value=Map(pipelines,stage);
            string outcome=Value(value,"outcome");
            bool failed=outcome=="failed";
            bool pending=outcome=="warning" || outcome=="pending" || outcome=="partial" ||
                outcome=="interrupted" || outcome=="interrupted_unconfirmed" ||
                (Flag(value,"pending") && outcome!="running" && outcome!="queued");
            string text=failed?"失败":pending?"待处理":outcome=="running"?"执行中":outcome=="queued"?"排队中":outcome=="completed"?"已完成":"尚无结果";
            if(stage=="backup_cleanup" && (failed || pending)) text="待完成";
            // Internal signatures support state-change deduplication only. The
            // values below never enter menus, notifications or persisted files.
            Add(label,text,failed || pending,outcome+"\n"+Value(value,"reason")+"\n"+Value(value,"error_type")+"\n"+Value(value,"next_step"));
        }
        public static TrayStatus From(Dictionary<string,object> state) {
            var status=new TrayStatus();
            var product=Map(state,"product") ?? new Dictionary<string,object>();
            var pipelines=Map(product,"pipelines") ?? new Dictionary<string,object>();
            bool recovery=Value(product,"mode")=="recovery";
            string watch=Value(state,"watch_error");
            status.Add("自动归档",Flag(state,"closing")?"已停止":watch!=""?"失败":recovery?"只读恢复模式":Flag(state,"watching")?"运行中":"已暂停",
                Flag(state,"closing") || watch!="",Flag(state,"closing")?"closing":watch);
            var union=Map(product,"union");
            bool unionPending=Value(union,"status")=="pending";
            status.Add("联合同步",unionPending?"待完成":Value(union,"status")=="caught_up"?"已追平":recovery?"不适用":"尚未追平",
                unionPending,Value(union,"reason"));
            string schedule=Value(product,"schedule_error");
            status.Add("计划账本",schedule!=""?"失败":recovery?"不适用":"正常",schedule!="",schedule);
            PipelineKnown(status,pipelines,"backup","备份");
            PipelineKnown(status,pipelines,"deep_verify","深度校验");
            PipelineKnown(status,pipelines,"restore","恢复");
            PipelineKnown(status,pipelines,"backup_cleanup","备份整理");
            // A committed backup and pending GC are separate outcomes, even on
            // older receipts that expose governance only inside backup details.
            var backup=Map(pipelines,"backup");
            var details=backup==null?null:Map(backup,"details");
            var governance=details==null?null:Map(details,"governance");
            if(!pipelines.ContainsKey("backup_cleanup") && Flag(governance,"cleanup_pending"))
                status.Add("备份整理","待完成",true,"cleanup_pending");
            string[] stages={"capture","union","identities","media_voice","media","media_cache"};
            string[] labels={"采集记录","联合整理","联系人索引","语音索引","媒体索引","媒体缓存整理"};
            for(int i=0;i<stages.Length;i++) if(pipelines.ContainsKey(stages[i])) status.Pipeline(pipelines,stages[i],labels[i]);
            return status;
        }
        static void PipelineKnown(TrayStatus status,Dictionary<string,object> pipelines,string stage,string label) {
            // Omit an absent cleanup result; it is not evidence of pending GC.
            if(stage!="backup_cleanup" || pipelines.ContainsKey(stage)) status.Pipeline(pipelines,stage,label);
        }
    }
    class TrayNotice {
        string previous="";
        public bool Changed(string fault,bool enabled) {
            bool notify=enabled && fault!="" && fault!=previous;
            previous=fault; return notify;
        }
    }
    class Shell : ApplicationContext {
        [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr handle,int command);
        readonly JavaScriptSerializer json = new JavaScriptSerializer();
        readonly NotifyIcon tray;
        readonly ToolStripMenuItem healthMenu;
        readonly TrayNotice notices = new TrayNotice();
        readonly HttpClient http;
        readonly Process backend;
        readonly string workspace, runtime, endpoint, token;
        readonly EventWaitHandle openEvent, exitEvent;
        readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        Form window;
        WebView2 view;
        bool quitting, polling, notifications;
        bool? lastStartup;
        string phase = "tray", pollError = "", healthText = "";
        int ticks, heartbeatTicks;
        bool exerciseReady;
        readonly bool exercise;

        static string Quote(string value) { return "\"" + value.Replace("\"", "\\\"") + "\""; }
        public Shell(string root, EventWaitHandle signal, EventWaitHandle exitSignal, bool hidden, bool test, string offline, bool recovery) {
            workspace = root; openEvent = signal; exitEvent=exitSignal; exercise = test;
            if(test) phase="startup-recovery";
            runtime = Path.Combine(root,"archives","wechat-next","product");
            var portable = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"backend-dist","CaptureNextCore","CaptureNextCore.exe");
            ProcessStartInfo start;
            if (File.Exists(portable)) {
                start = new ProcessStartInfo(portable,"--root " + Quote(root));
            } else {
                start = new ProcessStartInfo(Path.Combine(root,".venv","Scripts","python.exe"),
                    "-m wechat_capture_next.product_host --root " + Quote(root));
            }
            if(offline!=null) start.Arguments+=" --offline "+Quote(offline);
            if(recovery) start.Arguments+=" --recovery";
            start.WorkingDirectory = root;
            start.UseShellExecute = false; start.CreateNoWindow = true;
            start.RedirectStandardInput = true; start.RedirectStandardOutput = true; start.RedirectStandardError = true;
            backend = Process.Start(start);
            bool initialized=false;
            try {
            // The redirected bootstrap never enters command lines, files or URLs.
            var handshake = backend.StandardOutput.ReadLineAsync();
            if (!handshake.Wait(TimeSpan.FromSeconds(90)) || handshake.Result == null)
                throw new InvalidOperationException("后台启动未完成；请检查是否已有采集器占用状态。不会启动第二个采集器。");
            var boot = json.Deserialize<Dictionary<string,object>>(handshake.Result);
            endpoint = (string)boot["url"]; token = (string)boot["token"];
            bool recoveryMode=boot.ContainsKey("mode") && (string)boot["mode"]=="recovery";
            if(recoveryMode) runtime=Path.Combine(root,"archives","wechat-next","product-recovery");
            backend.BeginErrorReadLine(); // Drain diagnostics; never persist chat/token output.
            var handler = new HttpClientHandler { UseProxy = false };
            http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
            http.DefaultRequestHeaders.Add("X-Capture-Token", token);
            http.DefaultRequestHeaders.Add("Origin",endpoint);
            var menu = new ContextMenuStrip();
            menu.Items.Add("打开档案窗口",null,async (s,e)=>await OpenWindow("overview"));
            menu.Items.Add("开始自动归档",null,async (s,e)=>await Submit("start_watch")).Enabled=!recoveryMode;
            menu.Items.Add("停止自动归档",null,async (s,e)=>await Submit("stop_watch")).Enabled=!recoveryMode;
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("开启 WebUI 并打开浏览器",null,async (s,e)=>await Browser(true));
            menu.Items.Add("关闭 WebUI",null,async (s,e)=>await Browser(false));
            menu.Items.Add("设置",null,async (s,e)=>await OpenWindow("settings"));
            healthMenu=new ToolStripMenuItem("后台分项状态");
            healthMenu.DropDownItems.Add("正在读取状态").Enabled=false;
            menu.Items.Add(healthMenu);
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("退出（安全收尾）",null,async (s,e)=>await Quit());
            tray = new NotifyIcon { Icon = SystemIcons.Application, Text = "本地聊天档案 · 后台准备中", ContextMenuStrip = menu, Visible = true };
            tray.DoubleClick += async (s,e)=>await OpenWindow("overview");
            timer.Interval = 1000;
            timer.Tick += async (s,e)=> {
                heartbeatTicks++;
                if(exitEvent.WaitOne(0)) { await Quit(); return; }
                if(!exercise || exerciseReady) ticks++;
                if(openEvent.WaitOne(0)) await OpenWindow("overview");
                if(exercise && ticks==30) await OpenWindow("overview");
                if(exercise && ticks==75 && window!=null) window.Close();
                if(exercise && ticks==110) await OpenWindow("settings");
                if(exercise && ticks==135 && window!=null) window.Close();
                if(exercise && ticks==160) await Quit();
                if(heartbeatTicks%5==0) await Poll();
            };
            timer.Start();
            WriteState();
            CleanBrowserMetrics();
            if (!hidden) { var ignored = OpenWindow("overview"); }
            initialized=true;
            } finally {
                if(!initialized) {
                    // No Kill: EOF lets an already-starting core close at its
                    // transaction boundary even if bootstrap times out/fails.
                    try { backend.StandardInput.Close(); } catch { }
                    try { backend.StandardOutput.Close(); } catch { }
                    try { backend.StandardError.Close(); } catch { }
                    backend.Dispose();
                }
            }
        }

        void WriteState() {
            try {
                ShellRuntimeDirectory.Write(workspace,runtime,json.Serialize(new {
                    pid=Process.GetCurrentProcess().Id, backend_pid=backend.Id, phase=phase,
                    window_open=window!=null, poll_error=pollError, at=DateTime.UtcNow.ToString("o") }));
            } catch { /* Runtime evidence failure must not stop acquisition. */ }
        }
        void CleanBrowserMetrics() {
            // Only disposable metrics in THIS product's generated WebView
            // profile. Never traverse a reparse point or any archive/source.
            string directory=Path.Combine(runtime,"webview-cache","EBWebView","BrowserMetrics");
            try {
                string current=directory;
                while(current!=null) {
                    if(Directory.Exists(current) && (File.GetAttributes(current)&FileAttributes.ReparsePoint)!=0) return;
                    current=Path.GetDirectoryName(current);
                }
                if(!Directory.Exists(directory)) return;
                foreach(string file in Directory.GetFiles(directory,"BrowserMetrics-*.pma",SearchOption.TopDirectoryOnly)) {
                    string name=Path.GetFileName(file);
                    if(!name.StartsWith("BrowserMetrics-",StringComparison.Ordinal) ||
                        !name.EndsWith(".pma",StringComparison.Ordinal)) continue;
                    if((File.GetAttributes(file)&FileAttributes.ReparsePoint)==0) {
                        try { File.Delete(file); } catch(IOException) { /* Active runtime: retry after exit. */ }
                    }
                }
            } catch { /* Cache housekeeping must never stop archival. */ }
        }
        async Task<Dictionary<string,object>> Get(string path) {
            var response = await http.GetAsync(endpoint+path);
            response.EnsureSuccessStatusCode();
            return json.Deserialize<Dictionary<string,object>>(await response.Content.ReadAsStringAsync());
        }
        async Task<Dictionary<string,object>> Submit(string action, Dictionary<string,object> extra=null) {
            try {
                var body = extra ?? new Dictionary<string,object>();
                body["action"] = action;
                body["request_id"] = Guid.NewGuid().ToString("N");
                var response = await http.PostAsync(endpoint+"/api/jobs",new StringContent(json.Serialize(body),Encoding.UTF8,"application/json"));
                response.EnsureSuccessStatusCode();
                return json.Deserialize<Dictionary<string,object>>(await response.Content.ReadAsStringAsync());
            } catch { Alert("请求结果未确认，请查看任务记录后再重试。",true); return null; }
        }
        async Task Browser(bool enabled) {
            try {
            var job = await Submit("webui",new Dictionary<string,object>{{"enabled",enabled}});
            if(job==null || !enabled) return;
            string id=(string)job["id"];
            for(int i=0;i<30;i++) {
                await Task.Delay(200);
                var jobs=await Get("/api/jobs");
                foreach(var item in (object[])jobs["jobs"]) {
                    var j=(Dictionary<string,object>)item;
                    if((string)j["id"]==id && (string)j["status"]=="completed") {
                        var result=(Dictionary<string,object>)j["result"];
                        Process.Start(new ProcessStartInfo((string)result["url"]) { UseShellExecute=true });
                        return;
                    }
                }
            }
            Alert("WebUI 开启请求仍在排队，完成后可再次使用该菜单打开。",false);
            } catch { if(!quitting) Alert("WebUI 状态连接未确认，请稍后从任务记录查看。",true); }
        }
        void Alert(string text,bool error) {
            if(!notifications) return;
            tray.ShowBalloonTip(5000,"本地聊天档案",text,error?ToolTipIcon.Warning:ToolTipIcon.Info);
        }
        void UpdateHealth(TrayStatus status,string ordinary) {
            tray.Text=status.Text(ordinary);
            string current=String.Join("\n",status.Items.ToArray());
            if(current!=healthText) {
                // Do not rebuild unchanged menus every heartbeat, or retain
                // removed ToolStripItems for the lifetime of the tray process.
                while(healthMenu.DropDownItems.Count>0) {
                    var item=healthMenu.DropDownItems[0];
                    healthMenu.DropDownItems.RemoveAt(0); item.Dispose();
                }
                foreach(string item in status.Items) healthMenu.DropDownItems.Add(item).Enabled=false;
                healthText=current;
            }
            if(notices.Changed(status.FaultKey,notifications)) Alert("后台有分项需要处理，请从托盘的后台分项状态或窗口查看。",true);
        }
        async Task Poll() {
            if(polling || quitting) return;
            polling=true;
            try {
                // Keep the shared timer dispatching --quit / activation even
                // after the backend dies; only skip its HTTP status query.
                if(backend.HasExited) { tray.Text="本地聊天档案 · 后台已退出"; if(notices.Changed("backend_exited",notifications)) Alert("后台已退出，未继续采集。请安全退出后重新打开。",true); return; }
                var state=await Get("/api/product");
                var product=(Dictionary<string,object>)state["product"];
                var settings=(Dictionary<string,object>)product["settings"];
                notifications=(bool)settings["notifications"];
                bool startup=(bool)settings["launch_at_login"];
                bool recoveryMode=product.ContainsKey("mode") && (string)product["mode"]=="recovery";
                if(!recoveryMode && startup!=lastStartup) { ApplyStartup(startup); lastStartup=startup; }
                if(pollError!="") { pollError=""; WriteState(); }
                var union=(Dictionary<string,object>)product["union"];
                if(exercise && !exerciseReady && (bool)product["message_recovery_completed"] &&
                    (bool)state["watching"] && (string)union["status"]=="caught_up") {
                    exerciseReady=true; ticks=0; phase="tray"; WriteState();
                }
                string ordinary=recoveryMode?"本地聊天档案 · 只读恢复模式":(bool)state["closing"]?"本地聊天档案 · 后台已停止":(bool)state["busy"]?"本地聊天档案 · 任务执行中":(bool)state["watching"]?"本地聊天档案 · 自动归档中":"本地聊天档案 · 已暂停";
                UpdateHealth(TrayStatus.From(state),ordinary);
            } catch(Exception error) { tray.Text="本地聊天档案 · 状态连接未确认"; if(notices.Changed("poll:"+error.GetType().Name,notifications)) Alert("后台状态连接未确认，请稍后查看。",true); if(pollError!=error.GetType().Name) { pollError=error.GetType().Name; WriteState(); } }
            finally { polling=false; }
        }
        void ApplyStartup(bool enabled) {
            const string name="CaptureNextLocalArchive";
            const string registryPath=@"Software\Microsoft\Windows\CurrentVersion\Run";
            using(var key=Registry.CurrentUser.OpenSubKey(registryPath,true) ?? (enabled?Registry.CurrentUser.CreateSubKey(registryPath):null)) {
                if(key==null) return;
                string command=Quote(Application.ExecutablePath)+" --root "+Quote(workspace)+" --tray";
                string old=key.GetValue(name) as string;
                if(enabled) {
                    if(old!=null && old!=command) throw new InvalidOperationException("启动项已被其他安装占用。");
                    key.SetValue(name,command);
                } else if(old==command) key.DeleteValue(name,false);
            }
        }
        async Task OpenWindow(string page) {
            if(quitting) return;
            if(window!=null) { RevealWindow(window); if(view!=null && view.CoreWebView2!=null) view.CoreWebView2.Navigate(endpoint+"/#"+page); return; }
            var form=new Form { Text="本地聊天档案 · Capture Next", Width=1260, Height=860,
                MinimumSize=new Size(640,480), StartPosition=FormStartPosition.CenterScreen, AutoScaleMode=AutoScaleMode.Dpi };
            window=form;
            var browser=new WebView2 { Dock=DockStyle.Fill };
            view=browser;
            form.Controls.Add(browser);
            form.FormClosed += (s,e)=> { browser.Dispose(); if(window==form) { window=null; view=null; phase="tray-after-window"; WriteState(); } };
            RevealWindow(form); phase="window"; WriteState();
            try {
                ShellRuntimeDirectory.Write(workspace,runtime,null);
                var options=new CoreWebView2EnvironmentOptions("--disk-cache-size=1048576 --media-cache-size=1048576");
                // Own crash handling, no automatic crash upload to Microsoft.
                options.IsCustomCrashReportingEnabled=true;
                var env=await CoreWebView2Environment.CreateAsync(null,Path.Combine(runtime,"webview-cache"),options);
                env.BrowserProcessExited += (s,e)=> { if(window==null) CleanBrowserMetrics(); };
                if(form.IsDisposed) return;
                await browser.EnsureCoreWebView2Async(env);
                if(form.IsDisposed) return;
                browser.CoreWebView2.Settings.AreDevToolsEnabled=false;
                browser.CoreWebView2.Settings.AreDefaultContextMenusEnabled=false;
                browser.CoreWebView2.Settings.IsStatusBarEnabled=false;
                browser.CoreWebView2.Settings.IsPasswordAutosaveEnabled=false;
                browser.CoreWebView2.Settings.IsGeneralAutofillEnabled=false;
                browser.CoreWebView2.NavigationStarting += (s,e)=> { Uri uri; if(!Uri.TryCreate(e.Uri,UriKind.Absolute,out uri) || uri.GetLeftPart(UriPartial.Authority)!=endpoint) e.Cancel=true; };
                browser.CoreWebView2.NewWindowRequested += (s,e)=> { e.Handled=true; };
                browser.CoreWebView2.PermissionRequested += (s,e)=> { e.State=CoreWebView2PermissionState.Deny; };
                browser.CoreWebView2.DownloadStarting += (s,e)=> { e.Cancel=true; };
                browser.Source=new Uri(endpoint+"/#"+page);
            } catch { if(!form.IsDisposed) { browser.Dispose(); form.Controls.Add(new Label { Text="独立窗口初始化失败。请确认 WebView2 Runtime 已安装；后台仍可运行，托盘可开启 WebUI。",Dock=DockStyle.Fill,Padding=new Padding(25) }); } }
        }
        void RevealWindow(Form form) {
            form.Show();
            // A background launcher may pass STARTF_USESHOWWINDOW/SW_HIDE.
            // Its first ShowWindow is overridden by Windows; this explicit
            // second call must reveal the GUI requested from the tray/event.
            ShowWindow(form.Handle,9); // SW_RESTORE, also displays hidden forms.
            form.Activate();
        }
        async Task Quit() {
            if(quitting) return;
            quitting=true; timer.Stop(); tray.Text="本地聊天档案 · 正在安全收尾";
            if(window!=null) window.Close();
            try { if(!backend.HasExited) { backend.StandardInput.WriteLine("quit"); backend.StandardInput.Flush(); await Task.Run(()=>backend.WaitForExit()); } }
            finally { phase="stopped"; WriteState(); tray.Visible=false; tray.Dispose(); http.Dispose(); ExitThread(); }
        }
    }

    static class Program {
        [STAThread] static int Main(string[] args) {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            string root=Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"..","..",".."));
            bool hidden=false,test=false,quit=false;
            string offline=null;bool recovery=false;
            for(int i=0;i<args.Length;i++) { if(args[i]=="--root" && i+1<args.Length) root=Path.GetFullPath(args[++i]); else if(args[i]=="--tray") hidden=true; else if(args[i]=="--offline" && i+1<args.Length) offline=Path.GetFullPath(args[++i]); else if(args[i]=="--recovery") recovery=true; else if(args[i]=="--quit") quit=true; else if(args[i]=="--exercise") { hidden=true; test=true; } }
            string identity;
            using(var sha=SHA256.Create()) identity=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(root.ToUpperInvariant()))).Replace("-","").Substring(0,24);
            bool created;
            using(var mutex=new Mutex(true,@"Local\CaptureNext."+identity,out created))
            using(var signal=new EventWaitHandle(false,EventResetMode.AutoReset,@"Local\CaptureNext.Open."+identity))
            using(var exitSignal=new EventWaitHandle(false,EventResetMode.AutoReset,@"Local\CaptureNext.Exit."+identity)) {
                if(!created) { if(quit) exitSignal.Set(); else signal.Set(); return 0; }
                if(quit) { mutex.ReleaseMutex(); return 0; }
                try { Application.Run(new Shell(root,signal,exitSignal,hidden,test,offline,recovery)); return 0; }
                catch { MessageBox.Show("应用未能启动。可能已有采集器占用状态，或运行环境不可用。未启动重复采集。","本地聊天档案",MessageBoxButtons.OK,MessageBoxIcon.Warning); return 1; }
                finally { mutex.ReleaseMutex(); }
            }
        }
    }
}
