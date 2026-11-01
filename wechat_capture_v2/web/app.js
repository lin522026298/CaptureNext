"use strict";
const $ = (id) => document.getElementById(id);
const titles = {
  overview: "总览",
  capture: "采集与补采",
  backup: "备份与恢复",
  verify: "比对与导出",
  jobs: "任务记录",
  about: "来源与边界",
};
const labels = {
  reconcile: "完整补采",
  backup: "创建备份",
  restore: "恢复到独立目录",
  compare: "同源逐字段比对",
  verify: "对象完整性校验",
  jsonl: "完整原始导出",
  wua: "去重归档导出",
  extract_assets: "提取附件",
  verify_assets: "附件读回校验",
};
const statuses = {
  queued: "排队中",
  running: "执行中",
  completed: "已完成",
  failed: "未完成",
  interrupted: "已中断",
  cancelled: "已取消",
};
const errors = {
  external_writer_busy: "外部采集器正在使用数据。请先让它正常结束，再启动。",
  watch_exited: "采集器异常退出，请检查本地日志后重试。",
  writer_busy: "其他进程占用写锁，请稍后重新创建任务。",
  insufficient_free_space: "可用磁盘空间不足，请释放空间后重新创建任务。",
  task_failed_check_private_log: "执行未通过，请查看该任务目录的本地私有日志。",
  console_restarted: "控制台曾退出，此任务未被认定成功。",
  console_stopped: "控制台已结束。",
  task_failed: "任务执行失败，请检查本地日志。",
};
const descriptions = {
  reconcile:
    "重新读取全部本机数据库并核对所有记录，不设条数或历史时间限制。大库可能耗时较久。",
  backup:
    "创建独立完整状态备份。即使不包含解密密钥，备份仍包含聊天明文和个人信息，请妥善保管。",
  restore:
    "先验证所选备份，再恢复到全新状态目录并逐对象读回。不会修改微信目录，不会自动切换当前数据源。",
  compare: "对同一份冻结输入，与旧解包链路逐字段核对；可能持续数分钟。",
  verify: "流式解压、核对全部已发布对象及账本引用。大归档需要较长时间。",
  jsonl: "导出所有原始版本、精确字段和解释历史。文件包含敏感聊天明文。",
  wua: "生成新的 WUA 去重归档。约 32 万条记录曾需约 5 GB 内存和数分钟。不会删除原始观察或修改旧归档。",
  extract_assets:
    "将所有已归档附件还原到新目录。可能需要较大额外空间，不会移动原文件。",
  verify_assets:
    "与当前最后成功观察到的附件清单逐路径、长度、SHA-256 核对所选提取结果；当前清单若已有更新，可能报告差异。",
};
let token = null,
  state = null,
  inFlight = false,
  online = false,
  lastSettingsTouched = false,
  pending = null,
  toastTimer = null,
  jobsSignature = "";
let lastSuccess = 0,
  submitting = false,
  shuttingDown = false,
  shutdownDisconnected = false;
const fetch = async (...args) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await window.fetch(args[0], {
      ...args[1],
      signal: controller.signal,
    });
    const body = await response.arrayBuffer();
    return new Response(body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } finally {
    clearTimeout(timer);
  }
};
function text(id, value) {
  $(id).textContent = value;
}
function count(v) {
  return typeof v === "number" ? v.toLocaleString("zh-CN") : "—";
}
function size(v) {
  if (typeof v !== "number") return "—";
  for (const [n, d] of [
    ["GiB", 1024 ** 3],
    ["MiB", 1024 ** 2],
    ["KiB", 1024],
  ])
    if (v >= d) return `${(v / d).toFixed(1)} ${n}`;
  return `${v} B`;
}
function date(v, short = false) {
  if (!v) return "—";
  return new Date(v).toLocaleString(
    "zh-CN",
    short
      ? { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }
      : {
          month: "2-digit",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        },
  );
}
function toast(message) {
  text("toast", message);
  $("toast").hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($("toast").hidden = true), 6500);
}
function route() {
  const name = location.hash.slice(1);
  const view = titles[name] ? name : "overview";
  document
    .querySelectorAll("[data-page]")
    .forEach((p) => (p.hidden = p.dataset.page !== view));
  document.querySelectorAll("[data-view]").forEach((a) => {
    a.classList.toggle("active", a.dataset.view === view);
    if (a.dataset.view === view) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  text("crumb", titles[view]);
  document.title = `${titles[view]} · 留存`;
}
async function api(path, body) {
  const headers = { "X-Capture-Token": token };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
  });
  if (response.status === 403) {
    token = null;
    throw new Error("连接凭据已更新，正在重新连接；请稍后重试。");
  }
  if (!response.ok) {
    let message = "操作未被接受，请稍后重试。";
    try {
      const data = await response.json();
      message = data.detail || message;
    } catch {}
    throw new Error(message);
  }
  return response.json();
}
function element(tag, className, value) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (value !== undefined) e.textContent = value;
  return e;
}
function resultLine(result) {
  if (!result) return "";
  const parts = [];
  const words = {
    rows: "原始版本",
    observations: "观察记录",
    logical_messages: "去重逻辑记录",
    expected_message_rows: "预期记录",
    matched_message_rows: "匹配记录",
    files_verified: "已核验文件",
    files_restored: "已还原文件",
    verified_bytes: "核验字节",
    files: "文件",
    active_observations: "当前原始观察记录",
  };
  for (const [k, label] of Object.entries(words))
    if (typeof result[k] === "number")
      parts.push(
        `${label} ${k.endsWith("bytes") ? size(result[k]) : count(result[k])}`,
      );
  if (result.pass === true) parts.push("校验通过");
  if (result.contains_plaintext_keys === true) parts.push("包含敏感密钥");
  return parts.join(" · ") || "任务已完成，详细证据保留在独立输出中。";
}
function renderJobs(container, jobs) {
  const target = $(container);
  const signature = JSON.stringify(jobs);
  if (target.dataset.signature === signature) return;
  target.dataset.signature = signature;
  const focused = target.contains(document.activeElement)
    ? {
        job: document.activeElement.closest("[data-job]")?.dataset.job,
        action: document.activeElement.dataset.jobAction,
      }
    : null;
  target.replaceChildren();
  if (!jobs.length) {
    const empty = element("div", "empty");
    empty.append(
      element("strong", "", "还没有后台任务"),
      element(
        "p",
        "",
        "从完整补采、创建备份或同源比对开始，结果会保留在这里。",
      ),
    );
    target.append(empty);
    return;
  }
  for (const j of jobs) {
    const row = element("article", "job");
    row.dataset.job = j.id;
    const info = element("div");
    info.append(
      element("h3", "", labels[j.kind] || "归档任务"),
      element("div", "job-meta", `${date(j.created)} · ${j.id.slice(0, 8)}`),
      element("div", "job-phase", errors[j.error_code] || j.phase),
    );
    row.append(
      info,
      element("span", `job-status ${j.status}`, statuses[j.status] || j.status),
    );
    if (j.result)
      row.append(element("div", "job-result", resultLine(j.result)));
    if (j.diagnostic_directory) {
      const diagnosis = element("div", "job-output");
      diagnosis.append(
        element("span", "", "本地诊断目录："),
        element("code", "", j.diagnostic_directory),
      );
      const copy = element("button", "", "复制诊断目录");
      copy.type = "button";
      copy.dataset.jobAction = "diagnosis";
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(j.diagnostic_directory);
          toast("已复制诊断目录。私有日志不通过网页传输。");
        } catch {
          toast("请选中诊断路径手动复制。");
        }
      });
      diagnosis.append(document.createElement("br"), copy);
      row.append(diagnosis);
    }
    if (j.status === "completed" && j.output) {
      const output = element("div", "job-output");
      output.append(
        element("span", "", "独立输出："),
        element("code", "", j.output),
      );
      const copy = element("button", "", "复制路径");
      copy.type = "button";
      copy.dataset.jobAction = "copy";
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(j.output);
          toast("已复制新结果路径。");
        } catch {
          toast("浏览器未允许复制，请选中路径手动复制。");
        }
      });
      output.append(document.createElement("br"), copy);
      row.append(output);
    }
    if (j.status === "queued") {
      const cancel = element("button", "job-cancel", "取消排队");
      cancel.type = "button";
      cancel.dataset.jobAction = "cancel";
      cancel.addEventListener("click", async () => {
        try {
          await api(`/api/jobs/${j.id}/cancel`, {});
          await refresh();
        } catch (e) {
          toast(e.message);
        }
      });
      row.append(cancel);
    }
    target.append(row);
  }
  if (focused?.job && focused.action) {
    const found = target.querySelector(
      `[data-job="${focused.job}"] [data-job-action="${focused.action}"]`,
    );
    if (found) found.focus({ preventScroll: true });
    else $("main").focus({ preventScroll: true });
  }
}
function updateSelect(id, jobs, kind, emptyLabel) {
  const select = $(id);
  const chosen = select.value;
  const filtered = jobs.filter(
    (j) => j.kind === kind && j.status === "completed",
  );
  const sig = filtered.map((j) => j.id).join(",");
  if (select.dataset.signature === sig) return;
  select.dataset.signature = sig;
  select.replaceChildren();
  select.append(
    new Option(filtered.length ? "请选择已完成结果" : emptyLabel, ""),
  );
  for (const j of filtered)
    select.append(
      new Option(
        `${date(j.finished)} · ${j.id.slice(0, 8)}${j.include_secrets ? " · 含密钥" : ""}`,
        j.id,
      ),
    );
  if (filtered.some((j) => j.id === chosen)) select.value = chosen;
}
function render() {
  if (!state) return;
  const c = state.catalog,
    w = state.watch;
  const busy = w.running || w.desired;
  const stopping = w.stopping;
  const label = stopping
    ? "安全停止中"
    : w.running
      ? "采集运行中"
      : w.desired
        ? "等待后台任务"
        : "待启动";
  text("watch-pill", label);
  text("capture-state", label);
  text(
    "watch-title",
    stopping
      ? "正在收好，当前这一轮。"
      : w.running
        ? "本机变化，持续观察。"
        : w.desired
          ? "任务结束后，继续采集。"
          : "准备好，持续留存。",
  );
  text(
    "watch-description",
    w.error_code
      ? errors[w.error_code] || "采集遇到问题，请检查本地日志。"
      : w.running
        ? "持续核对已落盘内容；回填的旧序号也会重新扫描。"
        : "启动后自动扫描本机新增内容，重新运行时先核对离线期间的数据。",
  );
  document.querySelectorAll("[data-watch]").forEach((b) => {
    b.textContent = busy ? "安全停止采集" : "开始实时采集 ↗";
    b.disabled = !online || stopping;
  });
  if (!lastSettingsTouched) $("watch-assets").checked = w.assets;
  const last = c.last_cycle;
  const latest = w.latest;
  // A metadata-only idle poll is not evidence that a previous gap closed.
  const partial =
    (last && last.errors > 0) ||
    (w.running && latest && latest.error_count > 0);
  const success =
    Boolean(c.last_successful_reconciliation) &&
    !["interrupted", "running"].includes(last?.status);
  text("database-icon", partial ? "!" : success ? "✓" : "·");
  text(
    "database-coverage",
    !c.available
      ? "暂时无法读取状态"
      : partial
        ? "存在未关闭缺口，需要重试"
        : !success
          ? last?.status === "interrupted"
            ? "上轮已中断，需要重新核对"
            : "尚未完成本机内容核对"
          : `${count(c.database_paths)} 个本机数据库路径 · 以成功观察为准`,
  );
  const a = c.last_asset_scan || latest?.assets;
  text(
    "asset-coverage",
    a?.enabled === false
      ? "附件采集未配置或未启用"
      : a?.errors > 0
        ? "附件存在未关闭缺口，等待后续成功扫描"
        : a?.complete === false
          ? "正在分时扫描，附件尚未齐备"
          : a?.complete === true
            ? "本轮遍历完成，未代表全部媒体关联"
            : `${count(c.asset_paths)} 个已观察路径 · 当前是否齐备未验证`,
  );
  text("metric-active", count(c.active_observations));
  text("metric-versions", count(c.raw_versions));
  text("metric-assets", count(c.asset_paths));
  text("metric-reconcile", date(c.last_successful_reconciliation, true));
  text("metric-db", `${count(c.database_paths)} 个本机数据库路径`);
  text("last-observation", date(w.updated));
  text(
    "last-result",
    latest
      ? latest.error_count
        ? `本轮存在 ${latest.error_count} 项缺口`
        : latest.status === "idle"
          ? "未见文件变化；等待周期内容复核"
          : latest.status === "local_complete_assets_pending"
            ? "数据库完成，附件仍待采集"
            : "本轮本机核对完成"
      : "未开始本次观察",
  );
  text(
    "last-duration",
    latest ? `${latest.elapsed_seconds.toFixed(3)} 秒` : "—",
  );
  text("resource-memory", size(state.resources.private_bytes));
  text("resource-free", size(state.resources.free_bytes));
  text("resource-state", size(c.state_database_bytes));
  text(
    "queue-count",
    count(
      state.jobs.filter((j) => ["queued", "running"].includes(j.status)).length,
    ),
  );
  renderJobs("recent-jobs", state.jobs.slice(0, 3));
  renderJobs("all-jobs", state.jobs);
  updateSelect(
    "restore-input",
    state.inputs || state.jobs,
    "backup",
    "暂无可恢复的成功备份",
  );
  updateSelect(
    "assets-input",
    state.inputs || state.jobs,
    "extract_assets",
    "暂无已完成的提取",
  );
  $("restore-button").disabled = !$("restore-input").value || !online;
  $("assets-verify-button").disabled = !$("assets-input").value || !online;
  text("updated", `状态读取 ${date(c.checked_at)}`);
  text(
    "clock",
    new Date().toLocaleDateString("zh-CN", {
      month: "long",
      day: "numeric",
      weekday: "short",
    }),
  );
  document.querySelectorAll("[data-action]").forEach((b) => {
    if (!["restore", "verify_assets"].includes(b.dataset.action))
      b.disabled = !online;
  });
  $("shutdown-console").disabled = !online;
}
async function refresh() {
  if (inFlight || shutdownDisconnected) return;
  inFlight = true;
  try {
    if (!token) {
      const r = await fetch("/api/session", {
        headers: { "X-Capture-Bootstrap": "1" },
        credentials: "same-origin",
        cache: "no-store",
      });
      if (!r.ok) throw new Error("session unavailable");
      token = (await r.json()).token;
    }
    state = await api("/api/status");
    lastSuccess = Date.now();
    shuttingDown = shuttingDown || state.closing;
    online = !shuttingDown;
    text("connection", shuttingDown ? "正在安全退出" : "控制台连接正常");
    $("connection").className = shuttingDown
      ? "connection"
      : "connection online";
    $("connection-alert").hidden = !shuttingDown;
    if (shuttingDown)
      text(
        "connection-alert",
        "正在安全退出：等待当前任务或采集边界完成，不再接受新操作。",
      );
    render();
  } catch {
    online = false;
    if (shuttingDown) shutdownDisconnected = true;
    text("connection", shuttingDown ? "退出连接已关闭" : "连接中断");
    $("connection").className = "connection offline";
    $("connection-alert").hidden = false;
    if (shuttingDown)
      text(
        "connection-alert",
        "安全退出请求已受理，控制台连接已关闭。若要重新打开，请运行新控制台启动器。",
      );
    document
      .querySelectorAll("[data-action],[data-watch],#shutdown-console")
      .forEach((b) => (b.disabled = true));
  } finally {
    inFlight = false;
  }
}
function confirmTask(kind) {
  if (!online || submitting) {
    toast("尚未连接或前次请求未返回，请稍后重试。");
    return;
  }
  pending = { kind, acknowledge: true, request_id: crypto.randomUUID() };
  text("confirm-submit", "确认并加入队列");
  text(
    "confirm-notice",
    "实时采集会先安全暂停，任务结束后按原设置恢复。输出始终使用新目录。",
  );
  if (kind === "backup") pending.include_secrets = $("include-secrets").checked;
  if (kind === "restore") pending.input_job = $("restore-input").value;
  if (kind === "verify_assets") pending.input_job = $("assets-input").value;
  text("confirm-title", labels[kind]);
  text(
    "confirm-description",
    descriptions[kind] +
      (pending.include_secrets
        ? "\n本次已选择包含明文解密密钥，请仅保存在自己控制的本机。"
        : ""),
  );
  $("confirm-assets-row").hidden = kind !== "reconcile";
  $("confirm-assets").checked = false;
  $("confirm-dialog").returnValue = "";
  $("confirm-dialog").showModal();
}
document
  .querySelectorAll("[data-action]")
  .forEach((b) =>
    b.addEventListener("click", () => confirmTask(b.dataset.action)),
  );
$("confirm-dialog").addEventListener("cancel", () => {
  pending = null;
  $("confirm-dialog").returnValue = "";
});
$("confirm-dialog").addEventListener("close", async () => {
  if ($("confirm-dialog").returnValue !== "confirm" || !pending || submitting) {
    pending = null;
    return;
  }
  const task = pending;
  pending = null;
  submitting = true;
  if (task.kind === "reconcile") task.assets = $("confirm-assets").checked;
  try {
    if (task.kind === "shutdown") {
      await api("/api/shutdown", { acknowledge: true });
      shuttingDown = true;
      online = false;
      document
        .querySelectorAll("[data-action],[data-watch],#shutdown-console")
        .forEach((b) => (b.disabled = true));
      toast("已请求安全退出，正在等待当前后台任务结束。");
      return;
    }
    await api("/api/jobs", task);
    toast("已加入后台队列。刷新或关闭页面不会中断任务。");
    location.hash = "jobs";
    await refresh();
  } catch (e) {
    toast(e.message + " 请求结果不明时，请先查看任务记录，避免重复创建。");
  } finally {
    submitting = false;
  }
});
document.querySelectorAll("[data-watch]").forEach((b) =>
  b.addEventListener("click", async () => {
    if (!state) return;
    const enabled = !(state.watch.running || state.watch.desired);
    try {
      await api("/api/watch", { enabled, assets: $("watch-assets").checked });
      lastSettingsTouched = false;
      toast(
        enabled
          ? "已请求开始采集，启动时会先核对本机全部内容。"
          : "已请求安全停止，将等待当前采集边界。",
      );
      await refresh();
    } catch (e) {
      toast(e.message);
    }
  }),
);
$("watch-assets").addEventListener("change", () => {
  lastSettingsTouched = true;
  if (state?.watch.running) toast("此设置将在下次启动采集时生效。");
});
$("restore-input").addEventListener(
  "change",
  () => ($("restore-button").disabled = !$("restore-input").value || !online),
);
$("assets-input").addEventListener(
  "change",
  () =>
    ($("assets-verify-button").disabled = !$("assets-input").value || !online),
);
document.querySelector(".skip").addEventListener("click", (e) => {
  e.preventDefault();
  $("main").focus();
});
$("shutdown-console").addEventListener("click", () => {
  if (!online || submitting) return;
  pending = { kind: "shutdown" };
  text("confirm-submit", "确认安全退出");
  text(
    "confirm-notice",
    "退出后不会自动恢复采集。已完成结果和所有原始数据继续保留。",
  );
  text("confirm-title", "安全退出本控制台");
  text(
    "confirm-description",
    "停止继续接收新任务，等待当前采集或作业安全结束，然后退出后台。尚未开始的排队任务将记为中断。不会修改微信或旧工具。",
  );
  $("confirm-assets-row").hidden = true;
  $("confirm-dialog").returnValue = "";
  $("confirm-dialog").showModal();
});
document.querySelectorAll("[data-view]").forEach((a) => {
  a.title = titles[a.dataset.view];
  a.setAttribute("aria-label", titles[a.dataset.view]);
});
window.addEventListener("hashchange", route);
window.addEventListener("online", refresh);
route();
refresh();
setInterval(refresh, 3000);
setInterval(() => {
  if (online && Date.now() - lastSuccess > 12000) {
    online = false;
    text("connection", "状态已过期");
    $("connection").className = "connection offline";
    $("connection-alert").hidden = false;
    document
      .querySelectorAll("[data-action],[data-watch],#shutdown-console")
      .forEach((b) => (b.disabled = true));
  }
}, 1000);
