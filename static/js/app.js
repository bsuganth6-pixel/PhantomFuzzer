const PF = {
  esc(s) { if(s==null) return ""; return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); },

  async postJSON(url, body) {
    const r = await fetch(url, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body||{}) });
    return r.json();
  },
  setLoading(loader, btn, on) { if(loader) loader.classList.toggle("active", on); if(btn) btn.disabled = on; },

  toast(msg, type="info", ms=4000) {
    const c = document.getElementById("toast-container"); if(!c) return;
    const el = document.createElement("div"); el.className = `toast ${type}`;
    const icon = type==="success"?"circle-check":type==="error"?"circle-exclamation":"circle-info";
    el.innerHTML = `<i class="fa-solid fa-${icon}"></i><span>${this.esc(msg)}</span>`;
    c.appendChild(el);
    setTimeout(()=>{ el.style.animation="toastOut 0.2s ease forwards"; setTimeout(()=>el.remove(),200); }, ms);
  },

  confIcon(conf) {
    return {high:"triangle-exclamation", medium:"circle-exclamation", low:"circle-info"}[conf] || "circle-info";
  },

  finding(f) {
    return `
      <div class="finding conf-${f.confidence}">
        <div class="finding-icon"><i class="fa-solid fa-${this.confIcon(f.confidence)}"></i></div>
        <div class="finding-body">
          <strong>${this.esc(f.type.replace(/_/g,' '))}<span class="conf-badge ${f.confidence}">${f.confidence} confidence</span></strong>
          <span>${this.esc(f.evidence)}</span>
          <div class="finding-payload">${this.esc(f.payload)}</div>
        </div>
      </div>`;
  },
};
