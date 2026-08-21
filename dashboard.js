/* ==========================================
   REAL-TIME MALWARE DETECTION DASHBOARD v2
   Uses Flask backend data only. No demo rows.
========================================== */

const API = "http://127.0.0.1:5000";

const loggedIn = localStorage.getItem("loggedIn");
const storedUser = JSON.parse(localStorage.getItem("user") || "null");
if (loggedIn !== "true" || !storedUser) {
    window.location.href = "login.html";
}

const username = document.getElementById("username");
if (username) username.textContent = storedUser?.fullname || "Administrator";

function escapeHtml(value){
    return String(value ?? "").replace(/[&<>\"']/g, c => ({
        "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;", "'":"&#39;"
    }[c]));
}

function updateClock(){
    const el = document.getElementById("clock");
    if (el) el.textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock,1000);
updateClock();

function animateCounter(el,target){
    if(!el) return;
    const old = Number(el.dataset.value || 0);
    const start = performance.now();
    const duration = 350;
    function step(now){
        const p = Math.min((now-start)/duration,1);
        el.textContent = Math.round(old+(target-old)*p).toLocaleString();
        if(p<1) requestAnimationFrame(step);
    }
    el.dataset.value = target;
    requestAnimationFrame(step);
}

function statusClass(status){
    const s=String(status||"Safe").toLowerCase();
    if(s.includes("malware")||s.includes("malicious")) return "danger-text";
    if(s.includes("suspicious")||s.includes("warning")||s.includes("medium")) return "warning-text";
    return "safe";
}

function formatTime(value){
    if(!value) return "—";
    const d=new Date(value);
    return Number.isNaN(d.getTime()) ? String(value) : d.toLocaleTimeString();
}

function setThreatLevel(level){
    const el=document.getElementById("threatLevel");
    if(!el) return;
    const v=String(level||"LOW RISK").toUpperCase();
    el.textContent=v;
    el.className="level "+(v.includes("HIGH")?"high":v.includes("MEDIUM")?"medium":"low");
}

function updateChart(chart){
    const safe=Number(chart?.safe||0), warning=Number(chart?.warning||0), malware=Number(chart?.malware||0);
    const max=Math.max(safe,warning,malware,1);
    const update=(barId,countId,value)=>{
        const bar=document.getElementById(barId), count=document.getElementById(countId);
        if(bar) bar.style.width=((value/max)*100)+"%";
        if(count) count.textContent=value.toLocaleString();
    };
    update("safeBar","safeChartCount",safe);
    update("warningBar","warningChartCount",warning);
    update("malwareBar","malwareChartCount",malware);
}

function renderActivity(rows){
    const body=document.getElementById("activityBody");
    if(!body) return;
    body.innerHTML="";
    if(!rows || !rows.length){
        body.innerHTML='<tr><td colspan="3">No real activity recorded yet.</td></tr>';
        return;
    }
    rows.slice(0,8).forEach(item=>{
        const tr=document.createElement("tr");
        tr.innerHTML=`<td>${escapeHtml(item.file||item.filename||"Unknown")}</td>
        <td><span class="${statusClass(item.status)}">${escapeHtml(item.status||"Safe")}</span></td>
        <td>${escapeHtml(formatTime(item.time||item.event_time))}</td>`;
        body.appendChild(tr);
    });
}

async function loadDashboard(){
    const notification=document.getElementById("notificationText");
    try{
        const response=await fetch(`${API}/dashboard/stats?_=${Date.now()}`,{cache:"no-store"});
        const data=await response.json();
        if(!response.ok || !data.success) throw new Error(data.message||`HTTP ${response.status}`);
        const s=data.stats||{};

        animateCounter(document.getElementById("totalFiles"),Number(s.total_files||0));
        animateCounter(document.getElementById("safeFiles"),Number(s.safe_files||0));
        animateCounter(document.getElementById("malwareDetected"),Number(s.malware_detected||0));
        animateCounter(document.getElementById("threatAlerts"),Number(s.threat_alerts||0));
        setThreatLevel(s.threat_level);
        updateChart(s.chart);
        renderActivity(s.recent_activity||[]);

        if(notification){
            const monitor=s.live_monitoring
                ? `Live monitoring is ACTIVE: ${s.monitor_folder||"selected folder"}.`
                : "Live monitoring is currently stopped. Start it from File Activity to see real-time events here.";
            notification.textContent=(s.notification||"No security notification.")+" "+monitor;
        }

        const bar=document.getElementById("protectionBar");
        if(bar){
            const total=Math.max(Number(s.total_files||0),1);
            const alerts=Number(s.threat_alerts||0);
            const protection=Math.round(Math.max(0,Math.min(100,100-(alerts/total*100))));
            bar.style.width=protection+"%";
        }
    }catch(err){
        console.error("Dashboard backend error:",err);
        if(notification) notification.textContent="Cannot load live security data. Make sure Flask is running at http://127.0.0.1:5000.";
    }
}

loadDashboard();
setInterval(loadDashboard,2000);

const logoutBtn=document.getElementById("logoutBtn");
if(logoutBtn){
    logoutBtn.addEventListener("click",()=>{
        localStorage.removeItem("loggedIn");
        localStorage.removeItem("user");
        localStorage.removeItem("currentUser");
        window.location.href="login.html";
    });
}


// ==========================================
// LOCAL MONITORING AGENT DOWNLOAD
// ==========================================
const downloadAgentBtn = document.getElementById("downloadAgentBtn");
const agentStatus = document.getElementById("agentStatus");

async function downloadMonitoringAgent(){
    if(!storedUser?.email){
        alert("Please log in again before downloading the monitoring agent.");
        return;
    }
    try{
        if(downloadAgentBtn) downloadAgentBtn.disabled=true;
        if(agentStatus) agentStatus.textContent="Pairing this PC with your account...";
        const pair=await fetch(`${API}/api/agent/pair`,{
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body:JSON.stringify({email:storedUser.email,device_name:navigator.platform || "Windows-PC"})
        });
        const pairData=await pair.json();
        if(!pair.ok || !pairData.success) throw new Error(pairData.message||"Unable to pair device.");
        const response=await fetch(`${API}/agent/download?token=${encodeURIComponent(pairData.token)}`);
        if(!response.ok) throw new Error("Unable to download the monitoring agent.");
        const blob=await response.blob();
        const url=URL.createObjectURL(blob);
        const a=document.createElement("a");
        a.href=url;
        a.download="DAVE-Monitor-Agent.zip";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        if(agentStatus) agentStatus.textContent="Agent paired. Extract and run the downloaded agent on this PC.";
    }catch(err){
        console.error(err);
        if(agentStatus) agentStatus.textContent="Agent download failed.";
        alert(err.message);
    }finally{
        if(downloadAgentBtn) downloadAgentBtn.disabled=false;
    }
}
if(downloadAgentBtn) downloadAgentBtn.addEventListener("click",downloadMonitoringAgent);

async function updateAgentStatus(){
    const statusEl=document.getElementById("agentStatus");
    if(!statusEl || !storedUser?.email) return;
    try{
        const r=await fetch(`${API}/api/agent/status?email=${encodeURIComponent(storedUser.email)}&_=${Date.now()}`,{cache:"no-store"});
        const d=await r.json();
        if(!r.ok || !d.success) return;
        if(d.connected && d.device){
            statusEl.textContent=`Agent connected: ${d.device.device_name || "Windows-PC"} • Events received: ${Number(d.device.event_count||0)}`;
        }else{
            statusEl.textContent="Agent not connected. Download and run the monitoring agent.";
        }
    }catch(e){
        statusEl.textContent="Agent status unavailable.";
    }
}
updateAgentStatus();
setInterval(updateAgentStatus,3000);
