<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>LASH3Z — Home</title>
  <link rel="icon" type="image/png" href="/assets/L3Z_logoMain.png">

  <style>
    :root{
      --cyan:#00ffff; --ink:#eaf7ff; --glass:rgba(0,0,0,.85); --panel:#0f1416;
      --line:rgba(0,255,255,.18); --shadow:0 8px 24px rgba(0,0,0,.35);
      --sidew:260px; --toph:72px; --gold:#ffb42d; --dark:#0b1113;
      --icon-size: 46px; --icon-gap: 16px; --icon-radius: 10px; --icon-hover-scale: 1.10;
    }
    *{box-sizing:border-box}
    html,body{
      margin:0;height:100%;
      font-family:'Segoe UI',system-ui,Arial,sans-serif;
      background:url("/assets/BG_page.png") no-repeat center/cover fixed;
      color:var(--ink);
    }

    /* ===== Top bar & layout ===== */
    .topbar{ position:fixed; top:0; left:0; right:0; height:var(--toph);
      display:flex; align-items:center; justify-content:center; background:var(--glass);
      box-shadow:0 0 12px var(--cyan); z-index:1000; padding:0 12px; gap:26px; }
    .top-inner{position:relative; display:flex; align-items:center; width:100%; max-width:1400px; gap:16px}
    .menu-btn{display:none; border:1px solid var(--line); background:#061214; color:var(--ink); padding:8px 10px; border-radius:10px; cursor:pointer}
    .username-display{color:var(--cyan); font-weight:700; white-space:nowrap}
    .icon-bar{display:flex; align-items:center; gap:var(--icon-gap)}
    .icon-link{width:var(--icon-size); height:var(--icon-size); display:block}
    .icon-img{width:100%; height:100%; display:block; object-fit:contain; border-radius:var(--icon-radius); transition:transform .15s}
    .icon-img:hover{transform:scale(var(--icon-hover-scale))}
    .icon-bar.right{ margin-left:auto; }
    .ub-badge{
      display:inline-flex; align-items:center; gap:6px;
      padding:6px 10px; border-radius:999px; font-weight:800;
      background:#2a2310; color:#ffe39a; border:1px solid #8c6926;
      margin-right:10px;
    }
    .admin-pill{
      display:none; align-items:center; gap:8px; padding:8px 12px; border-radius:999px;
      background:linear-gradient(180deg,#072125,#04161a); border:1px solid var(--line); color:#bff;
      font-weight:900; text-decoration:none; box-shadow:0 0 16px rgba(0,255,255,.15);
    }
    .admin-pill:hover{ filter:brightness(1.1); }
    .admin-pill span{ font-weight:900; letter-spacing:.3px; }

    .sidebar{ position:fixed; top:var(--toph); left:0; bottom:0; width:var(--sidew);
      background:var(--glass); box-shadow:0 0 16px var(--cyan); overflow:auto; padding:12px; z-index:900; }
    .main{ margin-left:var(--sidew); padding:calc(var(--toph) + 16px) 20px 24px; min-height:100vh; }
    .sidebar h3{color:var(--cyan); margin:10px 0 6px; font-size:14px; letter-spacing:.3px}
    .navlink{ display:flex; align-items:center; gap:10px; width:100%; text-decoration:none; color:#fff;
      background:#111; border:1px solid #1b1b1b; padding:10px 10px; border-radius:8px; margin-bottom:8px;
      transition:background .15s, color .15s, transform .05s; }
    .navlink:hover{background:var(--cyan); color:#001113}
    .navlink:active{transform:translateY(1px)}
    .navlink img{width:20px; height:20px; object-fit:contain}

    /* ===== Banner slider ===== */
    .banner{text-align:center}
    .slider{ position:relative; max-width:100%; margin:0 auto;
      border-radius:12px; box-shadow:var(--shadow); overflow:hidden; border:1px solid var(--line);
      background:rgba(0,0,0,.5); }
    .slider .slide{ display:none; }
    .slider .slide.active{ display:block; }
    .slider img{ width:100%; height:auto; display:block; }
    .slide-nav{ position:absolute; top:50%; transform:translateY(-50%); background:rgba(0,0,0,.45); color:#fff; border:1px solid var(--line);
      width:42px; height:42px; border-radius:50%; cursor:pointer; z-index:2; display:grid; place-items:center; font-size:20px; }
    .slide-nav:hover{ background:rgba(0,0,0,.65); }
    .slide-nav.prev{ left:10px; } .slide-nav.next{ right:10px; }
    .dots{ position:absolute; left:0; right:0; bottom:10px; display:flex; gap:8px; justify-content:center; z-index:2; }
    .dot{ width:28px; height:6px; border-radius:999px; background:rgba(255,255,255,.35); border:1px solid rgba(255,255,255,.15); cursor:pointer; }
    .dot.active{ background:#bfff00; }

    /* ===== Jackpot widget ===== */
    .jackpot-wrap{ max-width:1000px; margin:22px auto 8px; padding:0 8px; }
    .jackpot{ position:relative; background:linear-gradient(180deg,#0e1519,#0a0f12);
      border:1px solid var(--line); border-radius:18px;
      box-shadow:0 0 22px rgba(0,255,255,.2), inset 0 0 0 1px rgba(255,255,255,.03);
      padding:18px 14px 22px; overflow:hidden; }
    .jp-header{ display:flex; justify-content:space-between; align-items:center; margin-bottom:12px; gap:12px; flex-wrap:wrap; }
    .jp-title{ font-weight:900; letter-spacing:1.2px; color:var(--gold); text-shadow:0 0 18px rgba(255,180,45,.35); font-size:22px; }
    .jp-ctl{display:flex; gap:12px; align-items:center; flex-wrap:wrap}
    .jp-reset{border:none; background:#132026; color:#cfe; border:1px solid var(--line); padding:6px 10px; border-radius:10px; cursor:pointer}
    .jp-reset:hover{background:#173038}
    .reels{ display:flex; justify-content:center; gap:10px; margin:8px auto 0; padding:10px 8px 0; }
    .reel{ width:110px; height:120px; border-radius:12px;
      background:radial-gradient(ellipse at 50% 0%, rgba(0,255,255,.10), rgba(0,0,0,.1) 60%), #0a1316;
      border:1px solid rgba(0,255,255,.14);
      box-shadow:inset 0 30px 30px rgba(0,0,0,.35), 0 8px 16px rgba(0,0,0,.35);
      display:flex; align-items:center; justify-content:center; overflow:hidden; position:relative; }
    .reel.small{ width:80px; } .reel.symbol{ width:90px; }
    .digit{ font-weight:900; font-variant-numeric:tabular-nums; font-size:56px; letter-spacing:1px;
      text-shadow:0 0 16px rgba(0,255,255,.25); }
    .sep{ display:flex; align-items:center; justify-content:center; width:28px; font-size:44px; opacity:.85 }
    .cap{ text-align:center; margin-top:10px; font-size:12px; color:#cfe; opacity:.85 }

    /* ===== Tiles ===== */
    .tiles{ display:flex; flex-wrap:wrap; justify-content:center; gap:16px; margin-top:24px; }
    .tile{ width:170px; height:170px; display:flex; flex-direction:column; align-items:center; justify-content:center;
      text-decoration:none; color:#fff; background:rgba(0,0,0,.80);
      border-radius:18px; box-shadow:0 0 16px var(--cyan); transition:transform .2s; }
    .tile:hover{transform:scale(1.04)}
    .tile img{width:64px; height:64px; margin-bottom:8px; object-fit:contain}
    .tile span{font-size:15px; text-align:center}
  </style>

  <script>
    // DEV shim for localhost only
    (function(){
      if ('serviceWorker' in navigator && (location.hostname === 'localhost' || location.hostname === '127.0.0.1')) {
        navigator.serviceWorker.register('/api-shim.sw.js', { scope: '/' }).catch(()=>{});
      }
    })();

    /* ===== Unified viewer + balance helper (prevents races) ===== */
    (function(){
      const sget=(k,d=null)=>{ try{ const v=localStorage.getItem(k); return v?JSON.parse(v):d; }catch(_){ return d; } };
      const pickName=()=>{
        const qp=new URLSearchParams(location.search).get('viewer'); if(qp) return qp.trim().toUpperCase();
        const sess=sget('l3z:session'); if(sess?.user) return String(sess.user).toUpperCase();
        const prof=sget('l3z:user'); if(prof?.username) return String(prof.username).toUpperCase();
        const lg=localStorage.getItem('user:username'); if(lg) return String(lg).toUpperCase();
        const last=sget('lash3z_last_user'); if(last) return String(last).toUpperCase();
        return 'PLAYER';
      };

      let _memo=null;
      async function fetchBalance(name){
        // 1) viewer/me
        try{
          const r=await fetch('/api/viewer/me',{credentials:'include',cache:'no-store'});
          if(r.ok){ const j=await r.json();
            const u=(j?.username||name||'PLAYER').toUpperCase();
            if (j?.wallet && typeof j.wallet.balance==='number') return {username:u, balance: j.wallet.balance};
            name=u; // continue with possibly corrected username
          }
        }catch(_){}
        // 2) wallet/balance
        try{
          const r=await fetch('/api/wallet/balance',{credentials:'include',cache:'no-store'});
          if(r.ok){ const j=await r.json(); if(typeof j.balance==='number') return {username:name, balance:j.balance}; }
        }catch(_){}
        // 3) wallet/me
        try{
          const r=await fetch('/api/wallet/me?viewer='+encodeURIComponent(name),{credentials:'include',cache:'no-store'});
          if(r.ok){ const j=await r.json(); if(j?.wallet && typeof j.wallet.balance==='number') return {username:name, balance:j.wallet.balance}; }
        }catch(_){}
        // 4) local
        const w = sget('lbx:wallet:'+name) || { balance:0 };
        return {username:name, balance:Number(w.balance)||0};
      }

      // Expose one promise so all callers share it and we avoid “last write wins”.
      window.l3zGetViewer = async function(){
        if(_memo) return _memo;
        const name = pickName();
        _memo = fetchBalance(name).then(x=>({ username:(x.username||name).toUpperCase(), balance:Math.max(0, Math.floor(Number(x.balance)||0)) }));
        return _memo;
      };
    })();
  </script>
</head>
<body>

<!-- ====== TOP BAR ====== -->
<div class="topbar">
  <div class="top-inner">
    <button id="menuBtn" class="menu-btn">☰ Menu</button>
    <div class="username-display" id="usernameDisplay">Welcome, PLAYER</div>

    <div class="icon-bar right" id="socialBar">
      <span class="ub-badge">LBX <b id="ubBal">0</b></span>
      <!-- Admin button (hidden until verified) -->
      <a id="adminPill" class="admin-pill" href="/pages/dashboard/admin/Admin_Dashboard.html" title="Administration">
        <img src="/assets/L3Z_logoMain.png" alt="Admin" style="width:18px;height:18px;opacity:.9"/>
        <span>Administration</span>
      </a>
      <!-- socials will be injected -->
    </div>
  </div>
</div>

<!-- ====== SIDEBAR (no admin section here) ====== -->
<div id="sidebar" class="sidebar">
  <h3>Dashboard</h3>
  <a class="navlink" href="/index.html"><img src="/assets/overview_icon.png" alt="Home">Home Page</a>

  <h3>Account</h3>
  <a class="navlink" href="/pages/dashboard/home/signup.html"><img src="/assets/signup.png" alt="Sign Up">Sign Up</a>
  <a class="navlink" href="/pages/dashboard/home/login.html"><img src="/assets/login.png" alt="Login">Login</a>
  <a class="navlink" href="/pages/dashboard/home/profile.html"><img src="/assets/signup.png" alt="Profile">Profile</a>

  <h3>Prediction Forms</h3>
  <a class="navlink" href="/pages/dashboard/home/battleground_prediction_form.html"><img src="/assets/battleground_icon.png" alt="Battleground">L3Z Battleground</a>
  <a class="navlink" href="/pages/dashboard/home/bonus_hunt_slot_requests.html"><img src="/assets/bonus_hunt_icon.png" alt="Bonus Hunt">Bonus Hunt Slot Requests</a>
  <a class="navlink" href="/pages/dashboard/home/pvp_entry_form.html"><img src="/assets/pvp_icon.png" alt="PVP Entry">PVP Entry Form</a>

  <h3>LASH3Z Bets</h3>
  <a class="navlink" href="/pages/dashboard/home/lash3z_bets.html"><img src="/assets/lash3zbux_pp.png" alt="L3Z Bets">Place Bets</a>
  <a class="navlink" href="/pages/dashboard/home/my_bets.html"><img src="/assets/lash3zbux_pp.png" alt="My Bets">My Bets</a>
  <a class="navlink" href="/pages/dashboard/home/lash3zbux_info.html"><img src="/assets/lash3zbux_pp.png" alt="Info">Bux Info</a>
  <a class="navlink" href="/pages/dashboard/home/lash3zbux_score_system.html"><img src="/assets/lash3zbux_pp.png" alt="Score">Bux Scoring</a>

  <h3>Leaderboard</h3>
  <a class="navlink" href="/pages/dashboard/home/leaderboard.html"><img src="/assets/overall_icon.png" alt="Leaderboard">Overall</a>

  <h3>Live Results</h3>
  <a class="navlink" href="/pages/dashboard/home/live_unified.html"><img src="/assets/overall_icon.png" alt="Unified Live">Unified Live</a>

  <h3>Giveaways</h3>
  <a class="navlink" href="/pages/dashboard/home/raffle_live.html"><img src="/assets/vip_icon.png" alt="Raffles Live">Raffles (Live)</a>
  

  <h3>Information</h3>
  <a class="navlink" href="/pages/dashboard/home/about.html"><img src="/assets/paw.png" alt="About">About</a>
  <a class="navlink" href="/pages/dashboard/home/casino.html"><img src="/assets/mateslots_logo.png" alt="Casino">Casino</a>
  <a class="navlink" href="/pages/dashboard/home/vip.html"><img src="/assets/vip_icon.png" alt="VIP">VIP</a>
</div>

<!-- ====== MAIN ====== -->
<section class="main">
  <!-- Banner SLIDER -->
  <div class="banner">
    <div class="slider" id="homeSlider" aria-label="Promotions">
      <button class="slide-nav prev" aria-label="Previous slide">❮</button>
      <button class="slide-nav next" aria-label="Next slide">❯</button>
      <div class="dots" id="homeSliderDots" aria-hidden="true"></div>
    </div>
  </div>

  <div class="jackpot-wrap">
    <div class="jackpot">
      <div class="jp-header">
        <div class="jp-title">MONTHLY JACKPOT</div>
        <div class="jp-ctl">
          <button id="resetJackpotBtn" class="jp-reset" title="Reset this month">Reset Jackpot</button>
        </div>
      </div>

      <div class="reels">
        <div class="reel symbol"><div class="digit">$</div></div>
        <div class="reel"><div class="digit">0</div></div>
        <div class="reel"><div class="digit">0</div></div>
        <div class="reel"><div class="digit">0</div></div>
        <div class="reel"><div class="digit">0</div></div>
        <div class="sep"><strong>.</strong></div>
        <div class="reel small"><div class="digit">0</div></div>
        <div class="reel small"><div class="digit">0</div></div>
      </div>

      <div class="cap">
        Jackpots are made up of gifted subscriptions and monthly subscriptions as well as donations from Lash3z.
        The more gifted, the higher the jackpot.
      </div>
    </div>
  </div>

  <div class="tiles">
    <a class="tile" href="/pages/dashboard/home/battleground_prediction_form.html">
      <img src="/assets/lashes%20battleground.png" alt="Battle Ground"><span>Battle Ground</span>
    </a>
    <a class="tile" href="/pages/dashboard/home/bonus_hunt_slot_requests.html">
      <img src="/assets/bonus_hunt_icon.png" alt="Bonus Hunt"><span>Bonus Hunt</span>
    </a>
    <a class="tile" href="/pages/dashboard/home/leaderboard.html">
      <img src="/assets/lashes%20leaderboard.png" alt="Leaderboard"><span>Leader Board</span>
    </a>
    <a class="tile" href="/pages/dashboard/home/lash3z_bets.html">
      <img src="/assets/lash3zbux_pp.png" alt="L3Z Bets"><span>L3Z Bets</span>
    </a>
    <a class="tile" href="/pages/dashboard/home/profile.html">
      <img src="/assets/login.png" alt="Profile"><span>My Profile</span>
    </a>
    <a class="tile" href="/pages/dashboard/home/vip.html">
      <img src="/assets/vip_icon.png" alt="VIP"><span>VIP Access</span>
    </a>
    <a class="tile" href="/pages/dashboard/home/pvp_live.html">
      <img src="/assets/pvp_icon.png" alt="PVP Live"><span>PVP Live</span>
    </a>
    <a class="tile" href="/pages/dashboard/home/casino.html">
      <img src="/assets/mateslots_logo.png" alt="Casino"><span>Casino</span>
    </a>
  </div>
</section>

<!-- Slider logic -->
<script>
(function(){
  "use strict";
  const files = [
    "mates_slot1.png","mate_slot2.png","mate_slot3.png",
    "mate_slot4.png","mate_slot 6.png","mate_sltos5.png","lashes banner.png"
  ].map(n => "/assets/" + n);

  const slider = document.getElementById("homeSlider");
  const dotsBox = document.getElementById("homeSliderDots");
  if(!slider) return;

  const anchor = dotsBox;
  const slides = files.map((src,i)=>{
    const d = document.createElement("div");
    d.className = "slide" + (i===0 ? " active":"");
    const img = document.createElement("img");
    img.alt = "Promo " + (i+1);
    img.src = encodeURI(src);
    d.appendChild(img);
    slider.insertBefore(d, anchor);
    return d;
  });

  const dots = files.map((_,i)=>{
    const b = document.createElement("button");
    b.type="button"; b.className="dot" + (i===0?" active":"");
    b.addEventListener("click", ()=>go(i, true));
    dotsBox.appendChild(b);
    return b;
  });

  const prev = slider.querySelector(".slide-nav.prev");
  const next = slider.querySelector(".slide-nav.next");

  let idx=0, timer=null, hover=false;
  const INTERVAL=10000;

  function setActive(i){
    slides[idx].classList.remove("active");
    dots[idx].classList.remove("active");
    idx=i;
    slides[idx].classList.add("active");
    dots[idx].classList.add("active");
  }
  function go(i,user){
    if(i<0) i = slides.length-1;
    if(i>=slides.length) i = 0;
    setActive(i);
    if(user) restart();
  }
  function nextFn(){ go(idx+1,false); }
  function start(){ if(!timer) timer=setInterval(()=>{ if(!hover) nextFn(); }, INTERVAL); }
  function stop(){ if(timer){ clearInterval(timer); timer=null; } }
  function restart(){ stop(); start(); }

  if(prev) prev.addEventListener("click", ()=>go(idx-1,true));
  if(next) next.addEventListener("click", ()=>go(idx+1,true));

  slider.addEventListener("mouseenter", ()=>{ hover=true; });
  slider.addEventListener("mouseleave", ()=>{ hover=false; });

  let sx=0, dx=0;
  slider.addEventListener("touchstart", e=>{ sx=e.touches[0].clientX; dx=0; }, {passive:true});
  slider.addEventListener("touchmove",  e=>{ dx=e.touches[0].clientX - sx; }, {passive:true});
  slider.addEventListener("touchend",   ()=>{ if(Math.abs(dx)>40) (dx<0? nextFn(): go(idx-1,true)); dx=0; }, {passive:true});

  start();
})();
</script>

<!-- Header logic: welcome, LBX, socials, admin button -->
<script>
(function(){
  "use strict";
  const $=s=>document.querySelector(s);

  function onlyUpgradeNumber(el, value){
    if(!el) return;
    const v = Math.max(0, Math.floor(Number(value)||0));
    const cur = Math.max(0, Math.floor(Number(String(el.textContent).replace(/[^\d.-]/g,''))||0));
    // don't downgrade non-zero to 0
    if (cur !== 0 && v === 0) return;
    el.textContent = String(v);
  }

  async function refreshHeader(){
    const {username, balance} = await window.l3zGetViewer();

    const ud = $("#usernameDisplay");
    if (ud) ud.textContent = "Welcome, " + username;

    onlyUpgradeNumber($("#ubBal"), balance);

    // admin badge probe
    try{
      const r = await fetch("/api/admin/gate/check", {credentials:"include"});
      $("#adminPill").style.display = r.ok ? "inline-flex" : "none";
    }catch(_){
      $("#adminPill").style.display = "none";
    }
  }

  // socials
  const SOCIALS = [
    { href:'https://kick.com/lash3z',                src:'/assets/kick.png',        alt:'Kick' },
    { href:'https://x.com/Lash3_z',                  src:'/assets/x_twitter.png',   alt:'Twitter' },
    { href:'https://www.instagram.com/lash3z50/',    src:'/assets/instagram.png',   alt:'Instagram' },
    { href:'https://www.facebook.com/lashesslots',   src:'/assets/facebook.png',    alt:'Facebook' },
    { href:'https://www.youtube.com/@Lash3z-50',     src:'/assets/youtube.png',     alt:'YouTube' },
    { href:'https://discord.gg/fSVqK6cMmB',          src:'/assets/discord.png',     alt:'Discord' },
  ];
  function buildSocials(){
    const bar = $("#socialBar");
    if (!bar) return;
    while (bar.children.length > 2) bar.removeChild(bar.lastElementChild);
    SOCIALS.forEach(({href,src,alt})=>{
      const a = document.createElement("a"); a.className="icon-link"; a.href=href; a.target="_blank"; a.rel="noopener"; a.title=alt;
      const img = document.createElement("img"); img.className="icon-img"; img.alt=alt; img.src=src;
      img.onerror=function(){ a.style.display="grid"; a.style.placeItems="center"; a.style.fontWeight="900"; a.style.color="#cfe"; a.textContent=alt[0].toUpperCase(); this.remove(); };
      a.appendChild(img); bar.appendChild(a);
    });
  }

  window.addEventListener("storage", (e)=>{ if(["l3z:session","l3z:user","user:username","lash3z_last_user"].includes(e.key)) refreshHeader(); });

  buildSocials();
  refreshHeader();
})();
</script>

<!-- Jackpot logic -->
<script src="/assets/js/jackpot.client.js" defer></script>

<!-- viewer glue (uses unified helper; won't clobber a non-zero badge) -->
<script id="viewer-glue">
(function(){
  const S = (sel) => document.querySelector(sel);
  const SS = (sel) => Array.from(document.querySelectorAll(sel));
  const set = (sel, val) => { const n=S(sel); if(n){ n.textContent = val; n.title = val; }};

  function onlyUpgradeNumber(el, value){
    if(!el) return;
    const v = Math.max(0, Math.floor(Number(value)||0));
    const cur = Math.max(0, Math.floor(Number(String(el.textContent).replace(/[^\d.-]/g,''))||0));
    if (cur !== 0 && v === 0) return; // don't downgrade
    el.textContent = String(v);
  }

  async function loadMe(){
    const me = await window.l3zGetViewer();

    const user = (me.username||'PLAYER').toUpperCase();
    set('#helloName', user);
    set('#welcomeName', user);
    set('#usernameDisplay', 'Welcome, ' + user);
    set('#ubName', user);
    set('#playerName', user);
    set('#who', user);
    if (S('#guestChipLabel')) S('#guestChipLabel').textContent = user;

    const pretty = (Number(me.balance)||0).toFixed(0);
    set('#headerLbx', pretty+' LBX');
    set('#navLbx',    pretty);
    onlyUpgradeNumber(S('#ubBal'), pretty);
    set('#playerBalance', pretty);
    set('#walletBalance', pretty);
    set('#walletBalanceTop', pretty);

    // Hide any “Switch name” buttons in this page
    const kill = ['#btnSwitch','.btnSwitchName','#switchName','.switch-name','.switchName']
      .map(S).filter(Boolean);
    kill.forEach(n => n.style.display='none');
    SS('button').forEach(b=>{
      const t = (b.textContent||'').toLowerCase();
      if (t.includes('switch name')) b.style.display='none';
    });

    // Update any generic text pills that show “LBX 0”
    SS('.lbx-pill,.lbx,.pill-lbx').forEach(n=>{
      const m = String(n.textContent||'').match(/\b(\d+)\b/);
      if (m) n.textContent = (n.textContent||'').replace(m[1], pretty);
    });
  }
  loadMe();
  window.addEventListener('focus', loadMe);
  document.addEventListener('visibilitychange', () => { if(!document.hidden) loadMe(); });
})();
</script>
</body>
</html>
