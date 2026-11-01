/* Archive content is always text, never HTML. One backend owns every job. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id),
    boot = window.__BOOTSTRAP__ || {};
  const names = {
    watch: "自动接续检查与采集",
    start_watch: "开始自动归档",
    stop_watch: "暂停自动归档",
    capture: "断线补采",
    sync_union: "联合增量同步",
    deep_verify: "完整深核验",
    backup_pair: "成对备份",
    restore_pair: "独立恢复验证",
    settings: "保存设置",
    import_source: "来源导入归并",
    export_union: "导出完整观察",
    compare: "独立来源比对",
    validate: "完整当前核验",
    refresh_status: "核实状态",
    webui: "WebUI 开关",
    index_media:"更新附件关联",
    prepare_media:"准备语音播放",
    prepare_image:"准备图片查看",
    load_image_keys:"临时加载媒体解码参数",
    verify_attachment:"核实文件／视频候选",
    export_attachment:"导出文件／视频原字节",
    prepare_attachment:"准备文件／视频预览",
    backup_cleanup:"备份空间整理",
    snapshot_pin:"更新恢复点固定状态",
    export_raw_asset:"导出已保存原件",
    open_restored:"只读打开恢复副本",close_restored:"关闭恢复副本",promote_restore:"验证恢复接管材料",
  };
  const labels = {
    overview: "自动归档",
    messages: "联合消息",
    assets: "原始附件",
    backups: "备份与恢复",
    manual: "手动工具",
    settings: "设置与计划",
    jobs: "任务记录",
  };
  const states = {
    queued: "排队中",
    running: "执行中",
    completed: "已完成",
    failed: "失败",
    warning: "需留意",
    interrupted: "已中断",
    interrupted_unconfirmed: "上次完成情况未确认",
  };
  const healthReasons = {
    backup_cleanup_complete:"备份空间整理已完成",
    backup_cleanup_pending:"恢复点已保留，仍有空间待整理",
    authenticated_noop_cleanup_deferred:"档案未变；剩余空间由独立整理任务处理",
    backup_cleanup_error:"空间整理未完成，请检查错误和可用空间",
    backup_cleanup_reclaim_stalled:"空闲页回收未继续推进，请检查后再整理",
    backup_cleanup_requested:"正在认证恢复点并整理空间",
    accepted_backup_collection_started:"新恢复点已提交，正在认证并回收旧空间",
    backup_cleanup_unconfirmed:"本次空间整理未确认完成",
    piggyback_cleanup_completion_unconfirmed:"新恢复点已提交，附带空间整理未确认完成",
    backup_or_cleanup_completion_unconfirmed:"上次备份或空间整理完成情况未确认",
    scheduled_cleanup_submission_unconfirmed:"本周期自动整理未确认入队",
    configured_local_asset_tree_only:"已完成已配置的本机附件来源，不代表全部媒体已关联",
    asset_source_errors:"附件来源处理有错误，已归档文件仍保留",
    asset_source_not_configured:"未配置原始附件来源",
    asset_import_pending:"附件内容仍在归档中",
    asset_scan_pending:"附件扫描尚未完成",
    asset_completion_unconfirmed:"附件处理完成情况未确认",
    native_voice_only_other_media_pending:"原生语音索引已完成；其他媒体仍须按各消息的关联证据判断",
    native_import_retry_required:"原生媒体索引未完成，可重新执行关联更新；原件仍保留",
    accepted_contact_database_absent:"尚未采集到可用的联系人数据库，暂保留原始身份标识",
    contact_index_retry_required:"可读名称索引未完成，可重试联合整理；消息与历史仍保留",
    capture_retained_sync_retry_required:"已采集内容保留，联合归并待重试",
    preview_only_originals_preserved:"仅处理可重建预览缓存，归档原件保留",
    source_errors:"部分来源读取有错误，请检查来源状态后重试补采",
  };
  const phases={sync_captured_versions:"同步已采集版本",pair_preflight:"检查成对来源与路径",exact_cut_probe:"识别是否有变化",
    state_deep_verification:"完整核验采集状态",union_deep_verification:"完整核验联合档案",
    union_attachment_verification:"核验附件闭包",repository_tree_publish:"增量写入备份块",
    before_verify:"回读备份块",before_commit:"提交可用恢复点",after_commit:"恢复点已提交",
    before_gc_commit:"回收过期无引用块",after_gc_commit:"整理备份空间",backup_collection:"认证并整理备份空间",
    before_retention:"认证保留点引用",before_retention_commit:"提交保留集合",after_retention_commit:"保留集合已提交",
    after_batch_edges:"回收无引用边",after_edge_commit:"引用批次已提交",after_batch_delete:"回收无引用块",
    before_batch_commit:"提交空间回收批次",after_batch_commit:"回收批次已提交",finished:"完成",failed:"失败"};
  phases.backup_collection_auth="认证保留点与引用";phases.backup_collection_blocks="分批回收无引用内容与空闲页";
  phases.offline_authentication="完整认证离线副本原始文件";
  let current = null,
    offset = 0,
    next = null,
    assetOffset = 0,
    assetNext = null,
    assetGeneration = 0,
    query = "",
    loadedSettings = false,
    loading = false,
    page = "overview",
    messageGeneration = 0,
    conversationGeneration = 0,
    detailGeneration = 0,
    jobsSignature = "",
    backupSignature = "",
    settingsJob = null;
  let conversationOffset=0,conversationNext=null,conversationQuery="",conversation=null,
    archiveView="current",senderFilter="",typeFilter="",dateFilter="",restoreRepository="rolling",anchorId=null;
  let recoverySeen=false,recoveryNavigationPending=false,userNavigated=!!location.hash,recoveryAutoHash=null;
  let uiInitialized=false;
  let restoredIdentity="";
  const mediaUrls=new Set();
  const clearMedia=()=>{for(const url of mediaUrls)URL.revokeObjectURL(url);mediaUrls.clear();};
  const viewQuery=()=>`view=${encodeURIComponent(archiveView)}`;
  const fmt = (n) => (typeof n === "number" ? n.toLocaleString("zh-CN") : "—");
  function bodyLabel(m){
    let type;try{type=Number(BigInt(String(m.message_type))&4294967295n);}catch{return m.body_text||"[正文未知]";}
    return ({3:"[图片] · 在详情中查看",34:"[语音] · 在详情中播放",43:"[视频] · 原字段和附件状态见详情",47:"[表情] · 在详情中查看",49:"[文件／分享] · 原字段见详情"})[type]||m.body_text||"[无文本正文]";
  }
  function dateLabel(value){const d=new Date(value);return value&&Number.isFinite(d.getTime())?d.toLocaleString("zh-CN"):value||"时间未知";}
  function element(tag, cls, text) {
    const el = document.createElement(tag);
    el.className = cls || "";
    if (text !== undefined) el.textContent = String(text);
    return el;
  }
  function text(id, value) {
    $(id).textContent = value ?? "—";
  }
  function notify(message) {
    text("toast", message);
    $("toast").hidden = false;
    setTimeout(() => ($("toast").hidden = true), 6000);
  }
  function offlineReadState(s=current){
    if(s?.product.mode!=="recovery"||s.product.offline_view)return null;
    if(s.product.offline_loading)return "正在完整认证离线副本原始文件；大副本可能较慢。认证成功前不读取消息，可在任务记录查看进度。";
    if(["failed","interrupted_unconfirmed","interrupted"].includes(s.product.offline_open_job?.status))return "离线副本认证尚未完成；请在任务记录检查失败原因后重试。正式状态未被覆盖，不表示原件永久缺失。";
    return "尚未打开已验证离线副本。请到备份与恢复页选择副本；不会连接微信或覆盖正式状态。";
  }
  async function api(path, body) {
    // Old immutable copies may not contain newer viewer access indexes. A
    // slow first read is not evidence of maintenance or a failed archive.
    const archiveRead=!body&&/^\/api\/(conversations|union-messages|message-context|message-detail|image-candidates|attachment-candidates|assets)(\?|$)/.test(path);
    const c = new AbortController(),
      t = setTimeout(() => c.abort(), archiveRead?120000:25000);
    try {
      const r = await fetch(path, {
        method: body ? "POST" : "GET",
        headers: {
          "X-Capture-Token": boot.token,
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
        cache: "no-store",
        signal: c.signal,
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
      return data;
    } finally {
      clearTimeout(t);
    }
  }
  async function submit(action, params = {}) {
    try {
      const job = await api("/api/jobs", {
        action,
        ...params,
        request_id: crypto.randomUUID().replaceAll("-", ""),
      });
      notify(`${names[action] || action}已进入唯一后台队列。`);
      await refresh();
      return job;
    } catch {
      notify("请求结果未确认，请先检查任务记录，不要重复提交。");
      return null;
    }
  }
  function buttonBusy(busy) {
    document
      .querySelectorAll("[data-action],#backup-now,#close-restored,#settings-form button,#restore button,#open-restored button,#promote-restored button,#import button,#export button,#compare button,#image-keys button")
      .forEach((b) => (b.disabled = !current || busy));
    // Reading a WAL snapshot is independent of ordinary capture. Only true
    // maintenance/teardown blocks reader forms, not every brief polling job.
    document.querySelectorAll("#search button,#conversation-search button,#message-filters button")
      .forEach(b=>b.disabled=!current||!!current.product?.maintenance||!!current.closing);
    $("watch").disabled = !current || !!current.closing;
  }
  async function refresh() {
    if (loading) return;
    loading = true;
    try {
      const [s, j] = await Promise.all([api("/api/product"), api("/api/jobs")]);
      current = s;
      $("error").hidden = true;
      text(
        "connection",
        s.product.maintenance ? "维护中 · 采集稍后接续" : "● 已连接同一后台",
      );
      text(
        "capture-state",
        s.closing
          ? "正在安全退出"
          : s.watching
            ? "自动归档已开启"
            : "自动归档已暂停",
      );
      text("watch", s.watching ? "暂停自动归档" : "启动自动归档");
      const u = s.product.union;
      const recovery=s.product.mode==="recovery";
      const previousAssetView=archiveView,previousRestoredIdentity=restoredIdentity;
      const nextRestoredIdentity=JSON.stringify([s.product.offline_view?.receipt_root,s.product.offline_view?.snapshot_id]);
      if(nextRestoredIdentity!==restoredIdentity){
        const changed=restoredIdentity!=="";restoredIdentity=nextRestoredIdentity;
        if(changed&&archiveView==="restored"){
          messageGeneration++;conversationGeneration++;detailGeneration++;$("message-detail").close();
          $("message-list").replaceChildren();$("conversation-list").replaceChildren();conversation=null;offset=conversationOffset=0;anchorId=null;
          text("conversation-title","全部会话");if(uiInitialized&&page==="messages"&&s.product.offline_view)conversations().then(messages);
        }
      }
      $("recovery-takeover").hidden=!recovery;
      if(recovery&&s.product.takeover?.next_step)text("takeover-materials",s.product.takeover.next_step);
      $("archive-view").options[0].disabled=recovery;
      $("archive-view").options[1].disabled=!s.product.offline_view;
      text("offline-state",s.product.offline_view ? `已只读打开：${s.product.offline_view.receipt_root}。与正式采集分离，不会重连微信。` : offlineReadState(s)||"尚未打开离线副本。离线查阅不加载微信密钥、不覆盖正式状态。");
      if(archiveView==="restored"&&!s.product.offline_view){archiveView="current";messageGeneration++;detailGeneration++;$("message-detail").close();$("archive-view").value="current";conversation=null;if(uiInitialized&&page==="messages")conversations().then(messages);}
      if(recovery&&s.product.offline_view&&archiveView!=="restored"){
        archiveView="restored";messageGeneration++;detailGeneration++;$("message-detail").close();$("archive-view").value="restored";conversation=null;offset=conversationOffset=0;
        if(uiInitialized&&page==="messages")conversations().then(messages);
      }
      $("asset-view").options[0].disabled=recovery;$("asset-view").options[1].disabled=!s.product.offline_view;$("asset-view").value=archiveView;
      if(uiInitialized&&page==="assets"&&(previousAssetView!==archiveView||(archiveView==="restored"&&previousRestoredIdentity!==restoredIdentity))){assetOffset=0;assets();}
      if(recovery){
        text("connection",s.product.offline_loading?"只读恢复模式 · 离线副本认证中":"只读恢复模式 · 本后台未启动采集");text("capture-state","正式采集核心未连接");
        if(!recoverySeen){recoverySeen=true;recoveryNavigationPending=!userNavigated;}
        if(recoveryNavigationPending&&!s.product.offline_loading){
          recoveryNavigationPending=false;
          if(!userNavigated){recoveryAutoHash=s.product.offline_view?"#messages":"#backups";location.hash=recoveryAutoHash;}
        }
      }
      text(
        "pipeline-state",
        recovery ? offlineReadState(s)||"可查阅已验证恢复副本。原状态未覆盖；本恢复后台不启动采集。" : u.status === "caught_up"
          ? `消息联合同步已完成 · ${u.as_of ? new Date(u.as_of).toLocaleString("zh-CN") : ""}`
          : "采集已落盘的记录仍保留；联合同步正在补偿或待重试。",
      );
      text(
        "busy",
        s.current_job
          ? names[s.current_job.action] || s.current_job.action
          : "空闲",
      );
      text("logical", fmt(u.stats?.logical_messages));
      text("observations", fmt(u.stats?.observations));
      text("versions", fmt(s.summary?.versions));
      text("assets-count", fmt(s.summary?.assets));
      if (s.watch_error) {
        $("error").hidden = false;
        text(
          "error",
          "后台流程尚未确认完成：" +
            s.watch_error +
            "。已落盘记录保留，后台后续重试。",
        );
      }
      if (s.product.schedule_error || s.closing) {
        $("error").hidden = false;
        text("error", s.closing ? "后台任务线程已停止，请安全退出后重新打开。" : "计划账本暂未保存，后台将重试：" + s.product.schedule_error);
      }
      buttonBusy(s.busy || j.queued > 0 || s.closing);
      if(recovery){
        $("watch").disabled=true;$("backup-now").disabled=true;
        document.querySelectorAll("[data-action]").forEach(b=>b.disabled=true);
        for(const id of ["settings-form","import","export","compare"])$(id).querySelectorAll("input,button,select").forEach(el=>el.disabled=true);
      }
      renderJobs(j.jobs);
      renderHealth(s);
      const offlineWaiting=offlineReadState(s);
      if(offlineWaiting){
        if(page==="messages"){text("message-list",offlineWaiting);text("conversation-list",offlineWaiting);}
        if(page==="assets")text("asset-list",offlineWaiting);
      }
      const backupKey = j.jobs.filter(job => ["backup_pair","snapshot_pin","backup_cleanup"].includes(job.action)).map(job => job.id + job.status).join(",");
      if (page === "backups" && !s.busy && backupKey !== backupSignature) {
        backupSignature = backupKey;
        backups();
      }
      const saved = j.jobs.find(job => job.id === settingsJob);
      if (saved?.status === "completed") {
        text("settings-result", "设置已保存。自动采集与 WebUI 启动选项在下次启动生效；登录启动由桌面壳登记。");
        settingsJob = null;
      }
      if (!loadedSettings) {
        for (const [k, v] of Object.entries(s.product.settings)) {
          const el = $("settings-form").elements.namedItem(k);
          if (el) {
            if (el.type === "checkbox") el.checked = v;
            else el.value = v;
          }
        }
        loadedSettings = true;
      }
      if(!uiInitialized){uiInitialized=true;route();}
    } catch {
      $("error").hidden = false;
      text(
        "error",
        "后台连接尚未确认。页面不会启动第二个采集器；请从托盘查看状态。",
      );
      text("connection", "连接未确认");
      current = null;
      buttonBusy(true);
    } finally {
      loading = false;
    }
  }
  function renderJobs(jobs) {
    const signature = JSON.stringify(jobs);
    if (signature === jobsSignature) return;
    jobsSignature = signature;
    const box = $("job-list");
    box.replaceChildren();
    if (!jobs.length)
      box.append(element("p", "hint", "本次运行暂无手动任务。"));
    for (const job of jobs) {
      const row = element("div", "job");
      row.append(
        element("b", "", names[job.action] || job.action),
        element("span", "tag", " " + (states[job.status] || job.status)),
      );
      row.append(
        element("small", "", new Date(job.created).toLocaleString("zh-CN")),
      );
      if (job.error) row.append(element("p", "", job.error));
      if (job.result?.next_step) row.append(element("p","hint",job.result.next_step));
      const active=["queued","running"].includes(job.status);
      row.append(element("p","hint",`阶段：${phases[job.phase]||names[job.phase]||job.phase||states[job.status]||job.status} · ${active?(job.status==="queued"?"尚在唯一队列排队，未开始执行":job.blocks_capture?"执行期间占用唯一队列，采集随后补偿":"离线恢复模式，不运行采集"):"本任务已结束，不再阻塞采集"}`));
      if(job.retry){const retry=element("button","secondary","检查结果后重试");retry.type="button";
        retry.addEventListener("click",()=>{
          if(!window.confirm("请先检查是否已有完整结果。确认后将创建一项新任务，不会重放旧请求。继续吗？"))return;
          const params={...job.retry},action=params.action;delete params.action;
          if(["restore_pair","export_union","compare","export_asset","export_raw_asset","export_attachment","validate"].includes(action)){
            const name=window.prompt("请输入新的输出名称（不会覆盖原结果）",(params.name||"retry")+"-"+Date.now().toString(36));
            if(!name)return;params.name=name;
          }
          submit(action,params);
        });row.append(retry);}
      if (job.result) {
        const d = element("details"),
          summary = element("summary", "", "查看结果与范围");
        d.append(
          summary,
          element("pre", "", JSON.stringify(job.result, null, 2)),
        );
        row.append(d);
      }
      box.append(row);
    }
  }
  function renderHealth(s){
    const box=$("pipeline-health");box.replaceChildren();
    const stages={capture:"采集",union:"联合归并",identities:"名称与身份索引",assets:"原始附件",media_voice:"原生语音索引",media:"全部媒体覆盖",media_cache:"可重建预览缓存",backup:"独立备份",backup_cleanup:"备份空间整理",deep_verify:"完整深核验",restore:"恢复验证"};
    for(const [key,title] of Object.entries(stages)){
      const value=s.product.pipelines?.[key],row=element("div","pipeline-result");
      let outcome=value?(states[value.outcome]||value.outcome):"本账本暂无成功记录";
      if(key==="capture"&&s.watch_error)outcome="最近采集记录保留；本轮流程未确认";
      if(s.product.mode==="recovery"&&["capture","union","assets","media"].includes(key))outcome="离线恢复模式未运行此环节";
      row.append(element("b","",title+"："+outcome),element("small","hint",`最近成功：${value?.last_success?new Date(value.last_success).toLocaleString("zh-CN"):"尚未确认"}`));
      if(value?.reason)row.append(element("small","hint","未完成原因 / 范围："+(healthReasons[value.reason]||value.reason)));
      if(value?.error_type)row.append(element("small","hint","错误类型："+value.error_type));
      if(value?.next_step)row.append(element("small","hint","后续处理："+value.next_step));box.append(row);
    }
  }
  async function messages() {
    const seq = ++messageGeneration,view=archiveView;
    const waiting=offlineReadState();if(waiting){text("message-list",waiting);return;}
    text("message-list", "加载联合消息…首次读取旧恢复副本可能较慢，后台状态仍可查阅。");
    try {
      const data = await api(
        `/api/union-messages?limit=50&offset=${offset}&q=${encodeURIComponent(query)}&${viewQuery()}`+
        (conversation ? (conversation.account_alias===null?"&null_account=1":`&account_alias=${encodeURIComponent(conversation.account_alias)}`)+
          (conversation.conversation_id===null?"&null_conversation=1":`&conversation_id=${encodeURIComponent(conversation.conversation_id)}`) : "")+
        (senderFilter ? `&sender_id=${encodeURIComponent(senderFilter)}` : "")+(typeFilter ? `&message_type=${encodeURIComponent(typeFilter)}` : "")+
        (dateFilter ? `&since=${encodeURIComponent(new Date(dateFilter+"T00:00:00").toISOString())}` : ""),
      );
      if (seq !== messageGeneration||view!==archiveView) return;
      renderMessages(data);
    } catch {
      if(seq!==messageGeneration||view!==archiveView)return;
      text("message-list","读取尚未确认。旧恢复副本首次读取可能较慢；请检查后台或维护状态后重试，未据此判定消息缺失。");
    }
  }
  function renderMessages(data) {
      next = data.next_offset;
      const box = $("message-list");
      box.replaceChildren();
      for (const m of data.rows) {
        const row = element("div", "message");
        row.id="message-"+m.logical_id;
        if(m.logical_id===anchorId)row.classList.add("anchor");
        row.append(
          element(
            "div",
            "meta",
            `${dateLabel(m.event_time)} · ${m.conversation_name || m.conversation_id || "会话未知"} · ${m.sender_name || m.sender_id || "发送者未知"} · 类型 ${m.message_type || "未知"}`,
          ),
          element("div", "body", bodyLabel(m)),
          element(
            "small",
            "hint",
            `${m.observation_count} 个观察 · ${m.source_count} 个来源 · ${m.conflict_count} 个冲突`,
          ),
        );
        const actions=element("div","actions"),details=element("button","secondary","来源、版本与冲突"),context=element("button","secondary","前后文");
        details.type=context.type="button";
        details.addEventListener("click",()=>messageDetail(m.logical_id));
        context.addEventListener("click",()=>messageContext(m.logical_id));
        actions.append(details,context);
        if(m.sender_id){const sender=element("button","secondary","只看此发送者");sender.type="button";
          sender.title=m.sender_name||m.sender_id;
          sender.addEventListener("click",()=>{senderFilter=m.sender_id;$("sender-filter").value=senderFilter;offset=0;anchorId=null;messages();});actions.append(sender);}
        row.append(actions);
        box.append(row);
      }
      if (!data.rows.length)
        box.append(element("p", "hint", "没有符合条件的消息。"));
      text("page-number", `从第 ${offset+1} 条开始`);
      $("previous").disabled = offset === 0;
      $("next").disabled = next === null;
      if(anchorId)$("message-"+anchorId)?.scrollIntoView({block:"center"});
  }
  async function conversations(){
    const seq=++conversationGeneration,view=archiveView;
    const waiting=offlineReadState();if(waiting){text("conversation-list",waiting);return;}
    text("conversation-list","正在读取会话…旧副本首次查询可能较慢，请稍候；查询未完成不代表没有记录。");
    try{
      const d=await api(`/api/conversations?limit=30&offset=${conversationOffset}&q=${encodeURIComponent(conversationQuery)}&${viewQuery()}`);
      if(seq!==conversationGeneration||view!==archiveView)return;
      conversationNext=d.next_offset;const box=$("conversation-list");box.replaceChildren();
      for(const c of d.rows){const b=element("button","secondary conversation-choice",c.conversation_name||c.conversation_id||"未知会话");b.type="button";
        b.append(element("small","",`${fmt(c.message_count)} 条 · ${c.last_time||"时间未知"}`));
        b.title=`账号：${c.account_alias}\n稳定会话标识：${c.conversation_id}`;
        b.addEventListener("click",()=>{conversation=c;offset=0;anchorId=null;text("conversation-title",c.conversation_name||c.conversation_id);messages();});box.append(b);}
      if(!d.rows.length)box.append(element("p","hint","没有匹配的会话。名称未解析时仍可按稳定标识查找。"));
      $("conversation-prev").disabled=conversationOffset===0;$("conversation-next").disabled=conversationNext===null;
    }catch{if(seq===conversationGeneration&&view===archiveView)text("conversation-list","会话读取尚未确认。旧副本首次读取可能较慢；请检查后台状态后重试。");}
  }
  async function messageContext(id){
    const seq=++messageGeneration,view=archiveView;
    try{const d=await api(`/api/message-context?id=${encodeURIComponent(id)}&${viewQuery()}`);
      if(seq!==messageGeneration||view!==archiveView)return;
      conversation={account_alias:d.account_alias,conversation_id:d.conversation_id};offset=d.offset;anchorId=id;query=senderFilter=typeFilter=dateFilter="";
      for(const input of ["query","sender-filter","type-filter","date-filter"])$(input).value="";
      text("conversation-title",d.rows[0]?.conversation_name||d.conversation_id);renderMessages(d);
    }catch{if(seq===messageGeneration&&view===archiveView)notify("前后文未读取成功，请稍后重试。");}
  }
  function jsonDetail(title,value){const d=element("details"),s=element("summary","",title);d.append(s);let ready=false;
    d.addEventListener("toggle",()=>{if(d.open&&!ready){d.append(element("pre","",JSON.stringify(value,null,2)));ready=true;}});return d;}
  async function messageDetail(id){
    const seq=++detailGeneration,view=archiveView;
    const box=$("detail-content");box.replaceChildren(element("p","hint","读取来源和版本…"));$("message-detail").showModal();
    try{const d=await api(`/api/message-detail?id=${encodeURIComponent(id)}&${viewQuery()}`);if(seq!==detailGeneration||view!==archiveView)return;box.replaceChildren();
      box.append(element("p","hint","代表观察按确定性规则选取，不表示最新版本。候选关系尚未确认为重复。显示名称是辅助库观察值，不代表发送当时名称。"),
        element("p","body",bodyLabel(d.message)),jsonDetail("名称来源与历史",d.identities),jsonDetail("冲突字段与全部值",d.conflicts));
      const pictures=element("section","media-panel");pictures.append(element("h3","","图片与表情"));box.append(pictures);
      renderImageCandidates(pictures,d.images,id,seq,view);
      const files=element("section","media-panel");files.append(element("h3","","文件与视频"));box.append(files);
      renderAttachmentCandidates(files,d.attachments,id,seq,view);
      for(const o of d.observations){const row=element("section","observation");
        row.append(element("b","",`${o.source_id} · ${o.snapshot_id}`),element("p","body",bodyLabel(o)),jsonDetail("该观察的完整原始正文",o.body_text),
          jsonDetail("与代表观察的字段差异",o.differences_from_representative),jsonDetail("原始字段、类型、定位及归并依据",o));box.append(row);}
      const media=element("section","media-panel");media.append(element("h3","","消息附件"));
      media.append(element("p","hint","当前已接入原生语音证据；图片、视频和文件的关联仍可能未知。原字节保存不代表已关联或可解码。"));
      if(!d.media?.rows?.length)media.append(element("p","hint","关联未知：未找到可确认的原生语音记录；不表示原文件永久缺失。"));
      for(const item of d.media?.rows||[]){const part=element("div","observation");
        part.append(element("b","",item.status==="linked"?"已关联语音 · 原字节已保存，按需解码":"候选关联 · 尚未确认，不自动播放"),jsonDetail("附件原生来源与判定依据",item));
        if(item.status==="linked"){const play=element("button","secondary","准备并播放语音");play.type="button";
          play.addEventListener("click",()=>playVoice(play,part,id,item,seq,view));part.append(play);}
        media.append(part);
      }box.append(media);
      box.append(jsonDetail("不确定候选（不是已确认重复）",d.candidates));
      if(d.candidate_next_offset!==null){const more=element("button","secondary","读取更多候选");let n=d.candidate_next_offset;
        more.addEventListener("click",async()=>{try{more.disabled=true;const x=await api(`/api/message-detail?id=${encodeURIComponent(id)}&offset=${n}&${viewQuery()}`);if(seq!==detailGeneration||view!==archiveView)return;more.before(jsonDetail("更多不确定候选",x.candidates));n=x.candidate_next_offset;more.disabled=n===null;}catch{if(seq===detailGeneration&&view===archiveView){more.disabled=false;notify("候选未读取成功。");}}});box.append(more);}
    }catch{if(seq===detailGeneration&&view===archiveView)box.replaceChildren(element("p","hint","详情暂不可用，未将未读取的内容标为无冲突。"));}
  }
  function renderImageCandidates(box,data,id,seq,view){
    if(!data)return;
    if(!data.rows.length){box.append(element("p","hint","尚无可确认的图片候选。文件也可能以其他名称保存；不能据此断言原文件缺失。"));return;}
    box.append(element("p","hint","候选依据是消息原字段中的显式内容校验值或原生文件标识，不是时间相近。文件标识不是内容 MD5；解码后的内容校验另行显示，不会据此合并消息。"));
    for(const item of data.rows){const row=element("div","observation");
      row.append(element("p","hint",`${fmt(item.bytes)} B · ${item.evidence[0]?.example_path||item.file_sha}`),jsonDetail("候选来源与判定范围",item));
      for(const md5 of item.md5s?.length?item.md5s:[null]){const open=element("button","secondary",md5?"验证并查看图片":"查看原生标识候选（内容关联未确认）");open.type="button";
        open.addEventListener("click",()=>viewImage(open,row,id,item.file_sha,md5,seq,view));row.append(open);}
      box.append(row);
    }
    if(data.next_after){const more=element("button","secondary","更多图片候选");more.type="button";
      more.addEventListener("click",async()=>{try{more.disabled=true;const next=await api(`/api/image-candidates?id=${encodeURIComponent(id)}&after=${data.next_after}&${viewQuery()}`);if(seq!==detailGeneration||view!==archiveView)return;more.remove();renderImageCandidates(box,next,id,seq,view);}catch{more.disabled=false;notify("候选暂未读取成功。");}});box.append(more);}
  }
  async function viewImage(button,box,id,sha,md5,seq,view){
    button.disabled=true;button.textContent="图片处理中…";
    let accepted=false;
    try{
      const job=await submit("prepare_image",{logical_id:id,sha,expected_md5:md5,view});
      if(!job)throw new Error("unconfirmed");accepted=true;let finished=null;
      for(let i=0;i<95;i++){
        if(seq!==detailGeneration||view!==archiveView)return;
        const jobs=await api("/api/jobs"),row=jobs.jobs.find(r=>r.id===job.id);
        if(row&&!["queued","running"].includes(row.status)){finished=row;break;}
        await new Promise(resolve=>setTimeout(resolve,1000));
      }
      if(!finished){button.textContent="后台任务尚未确认，请查看任务记录";return;}
      if(finished.result?.status==="saved_unsupported"){
        button.textContent="原文件已保存，当前无法解码";
        box.append(element("p","hint","可能需要额外媒体解码参数，或格式／大小超出当前查看支持；原始字节未删除。可在高级工具临时加载已有参数后重新打开详情。"));return;
      }
      if(finished.status!=="completed"||!finished.result?.artifact_id)throw new Error("decode failed");
      const response=await fetch(`/api/image?id=${encodeURIComponent(finished.result.artifact_id)}`,{headers:{"X-Capture-Token":boot.token},cache:"no-store"});
      if(!response.ok||!(response.headers.get("content-type")||"").startsWith("image/"))throw new Error("image unavailable");
      const blob=await response.blob();if(seq!==detailGeneration||view!==archiveView)return;
      const url=URL.createObjectURL(blob);mediaUrls.add(url);const picture=element("img","media-image");picture.src=url;picture.alt="归档候选图片";
      const matches=finished.result.content_checksum_matches;
      box.append(element("p",matches===false?"error":"hint",matches===true?
        "图片内容校验一致；物理文件来源仍未确认。":matches===false?"该候选的内容校验不一致，未将它关联到消息。":"原字节已完整核实；消息没有可用内容校验值，仍只是原生文件标识候选，未确认关联。"),picture);
      button.textContent="已准备图片";
    }catch{if(seq===detailGeneration&&view===archiveView){button.textContent=accepted?"查看任务记录后重试":"请求未确认，请查看任务记录";notify("当前原件或图片处理未核实，请查看任务记录；不会据此断言原文件永久缺失。");}}
  }
  function renderAttachmentCandidates(box,data,id,seq,view){
    if(!data?.hints?.length&&!data?.native_filename_hints?.length){box.append(element("p","hint","此消息未解析出受支持的文件／视频证据。原始字段仍可在观察详情查阅。"));return;}
    box.append(element("p","hint","名称／路径或原生文件标识只用于候选，原生标识不是内容 MD5；需完整校验才确认内容相等，不等于物理来源确证。原字节导出不会自动执行文件；受支持的小型视频或 UTF-8 文本可在此预览，其他原件仍可导出。"),jsonDetail("消息原字段中的附件线索",{content_claims:data.hints,native_filename_hints:data.native_filename_hints||[]}));
    if(!data.rows.length)box.append(element("p","hint","未找到匹配的已保存候选，关联未知；不能据此证明原文件永久缺失。"));
    for(const item of data.rows){const row=element("div","observation");row.append(element("p","hint",`${fmt(item.bytes)} B · ${item.evidence[0]?.relative_path||item.file_sha}`),jsonDetail("候选来源与依据（有界示例，原记录保留）",item));
    for(const [action,label] of [["prepare_attachment","预览文本／播放视频"],["verify_attachment","核实原字节与关联"],["export_attachment","导出原文件…"]]){const button=element("button","secondary",label);button.type="button";
        button.addEventListener("click",()=>attachmentAction(button,row,action,id,item.file_sha,seq,view));row.append(button);}box.append(row);}
    if(data.next_after){const more=element("button","secondary","更多文件／视频候选");more.type="button";
      more.addEventListener("click",async()=>{try{more.disabled=true;const next=await api(`/api/attachment-candidates?id=${encodeURIComponent(id)}&after=${data.next_after}&${viewQuery()}`);if(seq!==detailGeneration||view!==archiveView)return;more.remove();renderAttachmentCandidates(box,next,id,seq,view);}catch{more.disabled=false;notify("候选读取未完成，请重试。");}});box.append(more);}
  }
  async function attachmentAction(button,box,action,id,sha,seq,view){
    const params={logical_id:id,sha,view};
    if(action==="export_attachment"){
      const name=prompt("输入新的导出文件名（可带扩展名）。保存到本程序任务输出目录；不会自动打开或执行。","attachment-"+crypto.randomUUID().slice(0,12)+".bin");
      if(!name)return;params.name=name;
    }
    button.disabled=true;
    try{const job=await submit(action,params);if(!job)throw new Error("unconfirmed");
      button.textContent="已排队，可在任务记录追踪";
      for(let i=0;i<600;i++){
        if(seq!==detailGeneration||view!==archiveView)return;
        const jobs=await api("/api/jobs"),row=jobs.jobs.find(r=>r.id===job.id);
        if(row&&!["queued","running"].includes(row.status)){
          if(row.status!=="completed"&&row.status!=="warning")throw new Error("task incomplete");
          box.append(element("p","hint",row.result?.content_checksum_matches?"完整原字节校验通过，内容与消息显式校验值一致；物理来源仍未确认。":row.result?.status==="file_missing"?"所选原文件不在绑定内容库中，需检查来源或恢复材料。":"原字节检查完成，但仍是未确认候选；没有把它自动关联或合并消息。"),jsonDetail("核实／预览／导出结果与保存路径",row.result));
          if(action==="prepare_attachment"){
            if(row.result?.artifact_id){
              const response=await fetch(`/api/attachment-preview?id=${encodeURIComponent(row.result.artifact_id)}`,{headers:{"X-Capture-Token":boot.token},cache:"no-store"});
              if(!response.ok)throw new Error("preview unavailable");
              const mime=(response.headers.get("content-type")||"").split(";")[0];
              if(mime==="text/plain"){
                const content=await response.text();if(seq!==detailGeneration||view!==archiveView)return;
                box.append(element("pre","file-text-preview",content));
              }else if(["video/mp4","video/webm","video/ogg"].includes(mime)){
                const blob=await response.blob();if(seq!==detailGeneration||view!==archiveView)return;
                const url=URL.createObjectURL(blob);mediaUrls.add(url);const video=element("video","media-video");video.controls=true;video.preload="metadata";video.src=url;
                video.addEventListener("error",()=>{box.append(element("p","hint","此视频容器已保存，但当前浏览器／系统不支持其编码；请导出原字节使用合适的播放器。"));},{once:true});box.append(video);
              }else throw new Error("unsupported preview MIME");
            }else box.append(element("p","hint","原文件保留；当前预览不支持此格式、编码或大小，可导出原字节。"));
          }
          if(row.result?.destination)box.append(element("p","body","保存位置："+row.result.destination));
          button.textContent="处理完成";return;
        }
        await new Promise(resolve=>setTimeout(resolve,1000));
      }
      button.textContent="任务仍在后台，请看任务记录";
    }catch{button.textContent="未确认完成，请查看任务记录";notify("未完成核实／导出。原始归档保留，可从任务记录重试。");}
  }
  async function playVoice(button,part,id,item,seq,view){
    button.disabled=true;button.textContent="语音处理中…";
    try{
      const job=await submit("prepare_media",{logical_id:id,snapshot_id:item.snapshot_id,locator:item.locator,view});
      if(!job)throw new Error("unconfirmed");let completed=null;
      for(let i=0;i<95;i++){
        if(seq!==detailGeneration||view!==archiveView)return;
        const jobs=await api("/api/jobs"),row=jobs.jobs.find(r=>r.id===job.id);
        if(row&&!["queued","running"].includes(row.status)){if(row.status!=="completed"||!row.result?.artifact_id)throw new Error("decode unavailable");completed=row;break;}
        await new Promise(resolve=>setTimeout(resolve,1000));
      }
      if(!completed)throw new Error("not confirmed");
      const response=await fetch(`/api/media?id=${encodeURIComponent(completed.result.artifact_id)}`,{headers:{"X-Capture-Token":boot.token},cache:"no-store"});
      if(!response.ok||!(response.headers.get("content-type")||"").startsWith("audio/wav"))throw new Error("unavailable");
      const blob=await response.blob();if(seq!==detailGeneration||view!==archiveView)return;
      const url=URL.createObjectURL(blob);mediaUrls.add(url);const audio=element("audio");audio.controls=true;audio.preload="metadata";audio.src=url;part.append(audio);
      button.textContent="已准备，可播放";audio.play().catch(()=>{});
    }catch{if(seq===detailGeneration&&view===archiveView){button.disabled=false;button.textContent="重试准备语音";part.append(element("p","hint","当前原件完整性、解码或缓存维护尚未确认，请查看任务记录。已有派生物不会被当作原件完整证明。"));}}
  }
  async function assets() {
    const view=archiveView,seq=++assetGeneration;
    const waiting=offlineReadState();if(waiting){text("asset-list",waiting);return;}
    text("asset-list", "加载原始附件…");
    try {
      const data = await api(`/api/assets?limit=50&offset=${assetOffset}&${viewQuery()}`);
      if(view!==archiveView||seq!==assetGeneration)return;
      assetNext = data.next_offset;
      const box = $("asset-list");
      box.replaceChildren();
      for (const f of data.rows) {
        const row = element("div", "message");
        row.append(
          element("b", "", f.relative_path),
          element("small", "hint", `${fmt(f.bytes)} B · ${f.file_sha}`),
        );
        if(f.evidence)row.append(jsonDetail("原件来源与保留路径（不代表消息关联）",f.evidence));
        row.append(element("p",f.status==="file_missing"?"error":"hint",f.status==="file_missing"?"当前绑定内容库缺少该原件；不代表其他来源永久缺失。":"这里只列出保留元数据，导出时才完整核实原字节；消息关联尚未确认。"));
        if(f.evidence_count>(f.evidence?.length||0)){
          const more=element("button","secondary",`读取全部来源（${fmt(f.evidence_count)} 条，分批展示）`);let evidenceOffset=0;more.type="button";
          more.addEventListener("click",async()=>{try{
            more.disabled=true;const evidence=await api(`/api/assets?id=${encodeURIComponent(f.evidence_query_id||f.file_sha)}&limit=50&offset=${evidenceOffset}&view=${encodeURIComponent(view)}`);
            if(seq!==assetGeneration||view!==archiveView)return;
            more.before(jsonDetail(`来源记录 · 从第 ${evidenceOffset+1} 条开始`,evidence.rows));evidenceOffset=evidence.next_offset;
            if(evidenceOffset===null)more.remove();else more.disabled=false;
          }catch{if(seq===assetGeneration&&view===archiveView){more.disabled=false;notify("来源记录尚未读取完成，请重试。");}}});row.append(more);
        }
        const b = element("button", "secondary", "导出原始文件");
        b.type = "button";
        b.addEventListener("click",()=>exportRawAsset(b,row,f,view,seq));
        row.append(b);
        box.append(row);
      }
      if (!data.rows.length)
        box.append(element("p", "hint", "本来源尚无已发布附件。"));
      $("asset-prev").disabled = assetOffset === 0;
      $("asset-next").disabled = assetNext === null;
    } catch {
      if(seq===assetGeneration&&view===archiveView)text("asset-list", "当前阅读来源的附件尚未读取成功；请检查所选恢复副本及后台状态后重试，不代表原件不存在。");
    }
  }
  async function exportRawAsset(button,box,file,view,seq){
    button.disabled=true;button.textContent="等待原件导出…";let accepted=false;
    try{
      const extension=/\.([a-zA-Z0-9]{1,10})$/.exec(file.relative_path||"");
      const name="asset-"+crypto.randomUUID().slice(0,12)+(extension?"."+extension[1]:".bin");
      const job=await submit("export_raw_asset",{sha:file.file_sha,name,view});
      if(!job)throw new Error("submission unconfirmed");accepted=true;
      for(let i=0;i<95;i++){
        if(seq!==assetGeneration||view!==archiveView)return;
        const jobs=await api("/api/jobs"),current=jobs.jobs.find(row=>row.id===job.id);
        if(seq!==assetGeneration||view!==archiveView)return;
        if(current&&!["queued","running"].includes(current.status)){
          if(current.status!=="completed"||!current.result?.export_readback_verified||!current.result?.destination)throw new Error("export unconfirmed");
          button.textContent="原件已导出并核实";
          box.append(element("p","hint","已保存到以下本地路径（未自动打开或执行）："),element("p","body",current.result.destination));
          return;
        }
        await new Promise(resolve=>setTimeout(resolve,1000));
      }
      button.textContent="任务仍在后台，请查看任务记录";
    }catch{if(seq===assetGeneration&&view===archiveView){button.disabled=true;button.textContent=accepted?"请先检查任务记录再重试":"提交结果未确认，请先检查任务记录";notify("导出尚未确认完成；不会把提交受理当成已保存。请检查任务记录及已有输出，确认未执行后再重新打开原件页提交。");}}
  }
  async function backups() {
    text("backup-list", "加载已发布清单…");
    try {
      const d = await api("/api/union-backups");
      const box = $("backup-list");
      box.replaceChildren();
      if(current?.product.mode==="recovery")box.append(element("p","hint","只读恢复模式不会更改仓库的固定状态或自动回收旧点；可选择恢复点进行独立恢复。"));
      for(const [repository,status] of Object.entries(d.repositories||{})){
        if(status.status==="unavailable")box.append(element("p","error",`${repository==="rolling"?"滚动":"旧版保留"}仓库暂不可读（${status.error_type||"未确认"}）。另一健康仓库的恢复点仍列在下方。${status.next_step||"请保留故障仓库并检查。"}`));
      }
      for (const b of d.snapshots) {
        const row = element("div", "message");
        row.append(
          element("small", "hint", `${b.created} · ${b.repository==="legacy"?"旧版保留仓库（不自动回收）":b.pinned?"手动固定":"最近成功恢复点"}`),
          element("div", "", b.snapshot_id),
        );
        row.append(element("p","hint",b.includes_secrets===true
          ? "清单含数据库密钥材料（敏感）；接管仍须完整恢复及当前来源认证。"
          : b.includes_secrets===false
            ? "清单不含数据库密钥；仅凭此点不能按当前流程接续采集。"
            : "数据库密钥材料未确认；旧格式还需配对状态仓库及恢复核验。"));
        if(b.provenance_included===true)row.append(element("p","hint","清单包含历史来源材料；列表不等于本次内容深核验。"));
        const choose = element("button", "secondary", "选择用于独立恢复");
        choose.type = "button";
        choose.addEventListener("click", () => {
          $("restore-id").value = b.snapshot_id;
          restoreRepository=b.repository;$("restore-repository").value=b.repository;
          $("restore-name").focus();
        });
        row.append(choose);
        if(b.repository==="rolling"&&current?.product.mode!=="recovery"){const pin=element("button","secondary",b.pinned?"取消固定":"固定此恢复点");pin.type="button";pin.addEventListener("click",async()=>{
          pin.disabled=true;const accepted=await submit("snapshot_pin",{snapshot_id:b.snapshot_id,enabled:!b.pinned});
          if(!accepted)pin.disabled=false;else refresh();
        });row.append(pin);}
        box.append(row);
      }
      if (!d.snapshots.length)
        box.append(element("p", "hint", Object.values(d.repositories||{}).some(v=>v.status==="unavailable")?"当前未列出可用恢复点；存在未能读取的仓库，不代表其中没有备份。":"尚无已发布联合快照。"));
    } catch {
      text("backup-list", "备份清单暂时不可用；不表示现有备份不存在。");
    }
  }
  function route() {
    const requested = location.hash.slice(1) || "overview";
    page = Object.hasOwn(labels, requested) ? requested : "overview";
    for (const key of Object.keys(labels)) $(key).hidden = key !== page;
    document.querySelectorAll("nav a").forEach((a) => {
      const active = a.hash === "#" + page;
      a.classList.toggle("active", active);
      if (active) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    });
    text("page-title", labels[page]);
    if (current&&uiInitialized) {
      if (page === "messages") {conversations().then(messages);}
      if (page === "assets") assets();
      if (page === "backups") backups();
    }
  }
  $("watch").addEventListener("click", () =>
    submit(current?.watching ? "stop_watch" : "start_watch"),
  );
  document
    .querySelectorAll("[data-action]")
    .forEach((b) =>
      b.addEventListener("click", () => submit(b.dataset.action)),
    );
  $("backup-now").addEventListener("click", () =>
    submit("backup_pair", { include_secrets: $("include-secrets").checked }),
  );
  $("search").addEventListener("submit", (e) => {
    e.preventDefault();
    query = $("query").value;
    offset = 0;
    messages();
  });
  $("previous").addEventListener("click", () => {
    offset = Math.max(0, offset - 50);
    messages();
  });
  $("next").addEventListener("click", () => {
    if (next !== null) {
      offset = next;
      messages();
    }
  });
  $("asset-prev").addEventListener("click", () => {
    assetOffset = Math.max(0, assetOffset - 50);
    assets();
  });
  $("asset-next").addEventListener("click", () => {
    if (assetNext !== null) {
      assetOffset = assetNext;
      assets();
    }
  });
  $("restore").addEventListener("submit", (e) => {
    e.preventDefault();
    submit("restore_pair", {
      snapshot_id: $("restore-id").value.trim(),
      name: $("restore-name").value.trim(),
      repository:$("restore-repository").value,
    });
  });
  $("conversation-search").addEventListener("submit",e=>{e.preventDefault();conversationQuery=$("conversation-query").value;conversationOffset=0;conversations();});
  $("conversation-prev").addEventListener("click",()=>{conversationOffset=Math.max(0,conversationOffset-30);conversations();});
  $("conversation-next").addEventListener("click",()=>{if(conversationNext!==null){conversationOffset=conversationNext;conversations();}});
  $("all-conversations").addEventListener("click",()=>{conversation=null;offset=0;anchorId=null;text("conversation-title","全部会话");messages();});
  $("message-filters").addEventListener("submit",e=>{e.preventDefault();senderFilter=$("sender-filter").value.trim();typeFilter=$("type-filter").value.trim();dateFilter=$("date-filter").value;offset=0;anchorId=null;messages();});
  $("clear-filters").addEventListener("click",()=>{senderFilter=typeFilter=dateFilter="";for(const i of ["sender-filter","type-filter","date-filter"])$(i).value="";offset=0;messages();});
  function selectView(value){archiveView=value;$("archive-view").value=value;$("asset-view").value=value;messageGeneration++;conversationGeneration++;detailGeneration++;assetGeneration++;$("message-detail").close();conversation=null;offset=conversationOffset=assetOffset=0;anchorId=null;text("conversation-title","全部会话");if(page==="assets")assets();else conversations().then(messages);}
  $("archive-view").addEventListener("change",()=>selectView($("archive-view").value));
  $("asset-view").addEventListener("change",()=>selectView($("asset-view").value));
  $("message-detail").addEventListener("close",()=>{detailGeneration++;$("detail-content").querySelectorAll("audio,video").forEach(a=>{a.pause();a.removeAttribute("src");a.load();});clearMedia();});
  $("detail-close").addEventListener("click",()=>$("message-detail").close());
  $("open-restored").addEventListener("submit",e=>{e.preventDefault();submit("open_restored",{path:$("restored-path").value.trim()});});
  $("close-restored").addEventListener("click",()=>submit("close_restored"));
  $("promote-restored").addEventListener("submit",e=>{e.preventDefault();if($("promote-confirm").checked)submit("promote_restore",{path:$("promote-path").value.trim(),confirm:"USE_VERIFIED_COPY"});});
  $("import").addEventListener("submit", (e) => {
    e.preventDefault();
    submit("import_source", {
      path: $("import-path").value.trim(),
      origin: $("import-origin").value.trim(),
    });
  });
  $("export").addEventListener("submit", (e) => {
    e.preventDefault();
    submit("export_union", { name: $("export-name").value.trim() });
  });
  $("compare").addEventListener("submit", (e) => {
    e.preventDefault();
    submit("compare", {
      reference: $("compare-path").value.trim(),
      name: $("compare-name").value.trim(),
    });
  });
  $("settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const value = {};
    for (const el of e.target.elements) {
      if (el.name)
        value[el.name] = el.type === "checkbox" ? el.checked : Number(el.value);
    }
    const job = await submit("settings", { value });
    if (job) {
      settingsJob = job.id;
      text(
        "settings-result",
        "设置已排队；请在任务记录确认“已完成”。启动项由运行中的桌面壳应用，启动选项在下次启动生效。",
      );
    }
  });
  $("image-keys").addEventListener("submit",e=>{e.preventDefault();submit("load_image_keys",{path:$("image-key-path").value.trim()});});
  document.querySelectorAll("nav a").forEach(a=>a.addEventListener("click",()=>{userNavigated=true;}));
  window.addEventListener("hashchange",()=>{if(location.hash!==recoveryAutoHash)userNavigated=true;recoveryAutoHash=null;route();});
  route();
  refresh();
  setInterval(refresh, 3000);
})();
