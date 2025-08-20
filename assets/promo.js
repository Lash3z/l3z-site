<script>
// /assets/promo.js
(function () {
  function qs(id){ return document.getElementById(id); }
  function show(el, msg, isOk=true){
    if(!el) return;
    el.textContent = msg;
    el.style.color = isOk ? "#12d48a" : "#ff7a8a";
    el.style.opacity = "1";
    setTimeout(()=>{ el.style.opacity="0.9"; }, 0);
  }

  // ---- ADMIN: Create Promo Code ----
  async function handleCreate(e){
    e?.preventDefault?.();
    const code   = qs("promo_code_input")?.value?.trim();
    const lbx    = Number(qs("promo_lbx_input")?.value);
    const hours  = Number(qs("promo_hours_input")?.value || 48);
    const out    = qs("promo_admin_status");

    if(!code || !Number.isFinite(lbx) || lbx <= 0){
      return show(out, "Enter code + positive LBX.", false);
    }
    try{
      const r = await api.post("/api/code/create", { code, lbx, expiresHours: hours });
      if(r?.ok){
        const eta = new Date(r.expiresAt);
        show(out, `Created ${r.code} (+${r.lbx} LBX), expires ${eta.toLocaleString()}.`);
      }else{
        show(out, r?.error || "Failed creating code.", false);
      }
    }catch(err){
      show(out, err.message || "Network error.", false);
    }
  }

  // ---- USER: Redeem Promo Code ----
  async function handleRedeem(e){
    e?.preventDefault?.();
    const code = qs("claim_code_input")?.value?.trim();
    const out  = qs("claim_status");
    const hdr  = document.querySelector("[data-lbx-header]"); // optional: your header balance element

    if(!code) return show(out, "Enter a code.", false);
    try{
      const r = await api.post("/api/code/redeem", { code });
      if(r?.ok){
        show(out, `Success! New balance: ${r.lbx} LBX.`);
        if(hdr) hdr.textContent = r.lbx; // live-update the header LBX if present
      }else{
        const msg = ({
          missing_code: "No code entered.",
          invalid_code: "Invalid code.",
          code_expired: "That code has expired.",
          already_redeemed: "You already redeemed this one.",
        })[r?.error] || r?.error || "Redeem failed.";
        show(out, msg, false);
      }
    }catch(err){
      show(out, err.message || "Network error.", false);
    }
  }

  // Public initializers so you can call on specific pages
  window.Promo = {
    initAdmin: function(){
      const btn = qs("promo_create_btn");
      if(btn) btn.addEventListener("click", handleCreate);
    },
    initClaim: function(){
      const btn = qs("claim_btn");
      if(btn) btn.addEventListener("click", handleRedeem);
    }
  };
})();
</script>
