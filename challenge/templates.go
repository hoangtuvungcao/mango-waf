package challenge

// powTemplate is the modern JS Proof-of-Work challenge page with Web Worker
var powTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check — Mango Shield</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #020617;
  --card: rgba(15, 23, 42, 0.85);
  --border: rgba(51, 65, 85, 0.6);
  --border-glow: rgba(6, 182, 212, 0.35);
  --cyan: #06b6d4;
  --green: #10b981;
  --amber: #f59e0b;
  --red: #ef4444;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background: var(--bg);
  background-image: 
    radial-gradient(circle at 50%% 20%%, rgba(6, 182, 212, 0.07) 0%%, transparent 50%%),
    radial-gradient(circle at 80%% 80%%, rgba(16, 185, 129, 0.05) 0%%, transparent 40%%);
  color: var(--text-main);
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  overflow: hidden;
}

.container { position: relative; z-index: 1; animation: fadeIn 0.5s ease-out; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }

.card {
  background: var(--card);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 44px 36px;
  max-width: 440px;
  width: 100%%;
  text-align: center;
  box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6), 0 0 30px rgba(6, 182, 212, 0.1);
  transition: border-color 0.3s;
}
.card:hover { border-color: var(--border-glow); }

.shield-svg {
  width: 52px; height: 52px;
  margin-bottom: 20px;
  display: inline-block;
  color: var(--cyan);
  filter: drop-shadow(0 0 16px rgba(6, 182, 212, 0.5));
  animation: pulseGlow 2.5s infinite ease-in-out;
}
@keyframes pulseGlow { 0%%, 100%% { transform: scale(1); opacity: 1; } 50%% { transform: scale(1.05); opacity: 0.85; } }

h1 {
  font-size: 22px;
  font-weight: 700;
  margin-bottom: 10px;
  letter-spacing: -0.3px;
  background: linear-gradient(135deg, #f8fafc, #06b6d4);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.sub { color: var(--text-muted); font-size: 13.5px; margin-bottom: 28px; line-height: 1.5; }

.progress-wrap {
  background: rgba(30, 41, 59, 0.8);
  border: 1px solid rgba(51, 65, 85, 0.5);
  border-radius: 10px;
  height: 8px;
  overflow: hidden;
  margin-bottom: 18px;
}
.progress-bar {
  height: 100%%;
  background: linear-gradient(90deg, #06b6d4, #10b981);
  border-radius: 10px;
  width: 0%%;
  transition: width 0.3s ease-out;
  box-shadow: 0 0 12px rgba(6, 182, 212, 0.5);
}

.status {
  font-size: 13px;
  color: var(--text-muted);
  margin-bottom: 26px;
  min-height: 24px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}
.spinner {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(6, 182, 212, 0.2);
  border-top-color: var(--cyan);
  border-radius: 50%%;
  animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

.stats-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-top: 20px;
  padding-top: 20px;
  border-top: 1px solid rgba(51, 65, 85, 0.4);
}
.stat-box {
  background: rgba(30, 41, 59, 0.4);
  border: 1px solid rgba(51, 65, 85, 0.4);
  border-radius: 10px;
  padding: 12px;
}
.stat-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; }
.stat-value { font-size: 17px; font-weight: 700; font-family: 'Fira Code', monospace; color: var(--cyan); margin-top: 4px; }

.success-text { color: var(--green); font-weight: 600; text-shadow: 0 0 10px rgba(16, 185, 129, 0.4); }
.error-text { color: var(--red); font-weight: 600; }

.footer { margin-top: 26px; font-size: 11.5px; color: var(--text-muted); }
.footer span.brand { color: var(--cyan); font-weight: 600; }
</style>
</head>
<body>
<div class="container">
<div class="card">
  <svg class="shield-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
  <h1>Checking Your Browser</h1>
  <p class="sub">This automatic security check protects our network from malicious DDoS traffic.</p>
  <div class="progress-wrap"><div class="progress-bar" id="pbar"></div></div>
  <div class="status" id="status"><span class="spinner"></span>Initializing security verification...</div>
  <div class="stats-grid">
    <div class="stat-box"><div class="stat-label">Hashes Evaluated</div><div class="stat-value" id="hashes">0</div></div>
    <div class="stat-box"><div class="stat-label">Compute Speed</div><div class="stat-value" id="speed">—</div></div>
  </div>
  <div class="footer">Secured by <span class="brand">Mango Shield Enterprise WAF</span> v2.0</div>
</div>
</div>
<script>
(function(){
  var challenge='%s',difficulty=%d,target=%d,redir='%s';
  var prefix='';for(var i=0;i<target;i++)prefix+='0';
  var startTime=Date.now(),hashCount=0,found=false;
  var statusEl=document.getElementById('status');
  var pbar=document.getElementById('pbar');
  var hashesEl=document.getElementById('hashes');
  var speedEl=document.getElementById('speed');

  function fmt(n){if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString();}

  if (!window.isSecureContext) {
    statusEl.innerHTML = '<span class="error-text">Secure Context Required (HTTPS)</span>';
    return;
  }
  if (!window.Worker || !window.crypto || !window.crypto.subtle) {
    statusEl.innerHTML = '<span class="error-text">Browser Incompatible</span>';
    return;
  }

  var workerCode='self.onmessage=function(e){var c=e.data.challenge,p=e.data.prefix,s=e.data.start,batch=10000;'+
    'function sha256(m){var buf=new TextEncoder().encode(m);return crypto.subtle.digest("SHA-256",buf);}'+
    'async function solve(){try{for(var i=s;i<s+batch;i++){var h=await sha256(c+i);var a=new Uint8Array(h);'+
    'var hex="";for(var j=0;j<a.length;j++)hex+=("0"+a[j].toString(16)).slice(-2);'+
    'if(hex.startsWith(p)){self.postMessage({found:true,nonce:i.toString(),hash:hex,count:i-s+1});return;}}'+
    'self.postMessage({found:false,count:batch,next:s+batch});}catch(err){self.postMessage({error:err.message});}}solve();};';

  var blob=new Blob([workerCode],{type:'application/javascript'});
  var worker;
  try { worker=new Worker(URL.createObjectURL(blob)); }
  catch (err) {
    statusEl.innerHTML = '<span class="error-text">Security Worker Initialization Failed</span>';
    return;
  }
  var totalCount=0;

  worker.onerror=function(e){
    statusEl.innerHTML = '<span class="error-text">Security Engine Error</span>';
  };

  worker.onmessage=function(e){
    var d=e.data;
    if(d.error){
       statusEl.innerHTML = '<span class="error-text">Error: '+d.error+'</span>';
       return;
    }
    totalCount+=d.count||0;
    hashCount=totalCount;
    var elapsed=(Date.now()-startTime)/1000;
    var hps=Math.round(hashCount/elapsed);
    hashesEl.textContent=fmt(hashCount);
    speedEl.textContent=fmt(hps)+'/s';
    pbar.style.width=Math.min(95,Math.log(hashCount+1)/Math.log(1e7)*100)+'%%';

    if(d.found){
      pbar.style.width='100%%';
      statusEl.innerHTML='<span class="success-text">Verified successfully. Redirecting...</span>';
      var form=document.createElement('form');form.method='POST';form.action=redir;
      var fields={challenge_type:'pow',nonce:d.nonce,challenge:challenge,difficulty:difficulty.toString()};
      for(var k in fields){var inp=document.createElement('input');inp.type='hidden';inp.name=k;inp.value=fields[k];form.appendChild(inp);}
      document.body.appendChild(form);
      setTimeout(function(){form.submit();},400);
    } else if(d.next!==undefined){
      statusEl.innerHTML='<span class="spinner"></span>Computing cryptographic proof... '+fmt(hashCount);
      worker.postMessage({challenge:challenge,prefix:prefix,start:d.next});
    }
  };

  worker.postMessage({challenge:challenge,prefix:prefix,start:0});
})();
</script>
</body>
</html>`

// silentTemplate is the invisible JS challenge (browser fingerprinting + auto-redirect)
var silentTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Verifying Connection — Mango Shield</title>
<style>
body {
  background: #020617;
  color: #f8fafc;
  font-family: 'Inter', system-ui, sans-serif;
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
  margin: 0;
}
.loader-box { text-align: center; }
.pulse-dots { display: flex; justify-content: center; gap: 8px; margin-bottom: 20px; }
.dot {
  width: 10px; height: 10px; border-radius: 50%%; background: #06b6d4;
  box-shadow: 0 0 12px rgba(6, 182, 212, 0.6);
  animation: pulse 1.2s infinite ease-in-out;
}
.dot:nth-child(2) { animation-delay: 0.2s; background: #10b981; box-shadow: 0 0 12px rgba(16, 185, 129, 0.6); }
.dot:nth-child(3) { animation-delay: 0.4s; background: #f59e0b; box-shadow: 0 0 12px rgba(245, 158, 11, 0.6); }
@keyframes pulse { 0%%, 80%%, 100%% { transform: scale(0.6); opacity: 0.4; } 40%% { transform: scale(1.2); opacity: 1; } }
.msg { font-size: 13px; color: #94a3b8; letter-spacing: 0.5px; font-weight: 500; }
</style>
</head>
<body>
<div class="loader-box">
  <div class="pulse-dots"><div class="dot"></div><div class="dot"></div><div class="dot"></div></div>
  <div class="msg">Verifying connection integrity...</div>
</div>
<script>
(function(){
  var fp={};
  try{var c=document.createElement('canvas');c.width=200;c.height=50;var x=c.getContext('2d');
  x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(20,0,100,30);
  x.fillStyle='#069';x.fillText('Mng',2,15);fp.cv=c.toDataURL().slice(-20);}catch(e){fp.cv='e';}
  try{var g=document.createElement('canvas').getContext('webgl');
  var d=g.getExtension('WEBGL_debug_renderer_info');
  fp.gl=d?g.getParameter(d.UNMASKED_RENDERER_WEBGL).slice(0,30):'n';}catch(e){fp.gl='n';}
  fp.s=screen.width+'x'+screen.height;fp.tz=new Date().getTimezoneOffset();
  fp.c=navigator.hardwareConcurrency||0;fp.l=navigator.language;fp.p=navigator.platform;
  fp.w=navigator.webdriver?1:0;fp.pl=navigator.plugins?navigator.plugins.length:-1;
  var h=0,s=JSON.stringify(fp);for(var i=0;i<s.length;i++)h=((h<<5)-h+s.charCodeAt(i))|0;
  document.cookie='mango_fp='+btoa(JSON.stringify({h:h,w:fp.w,s:fp.s}))+';path=/;max-age=3600;SameSite=Strict';
  if(!fp.w)setTimeout(function(){location.href='%s';},600);
  else document.body.innerHTML='<div style="text-align:center;padding:20px;color:#ef4444;font-family:sans-serif">Access Denied: Automated bot detected</div>';
})();
</script>
</body>
</html>`

// captchaTemplate is the Modern Hold-to-Verify UI overlay
var captchaTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Human Verification — Mango Shield</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #020617;
  --card: rgba(15, 23, 42, 0.85);
  --border: rgba(51, 65, 85, 0.6);
  --border-glow: rgba(6, 182, 212, 0.35);
  --cyan: #06b6d4;
  --green: #10b981;
  --amber: #f59e0b;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
}

* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background: var(--bg);
  background-image: radial-gradient(circle at 50%% 30%%, rgba(6, 182, 212, 0.07) 0%%, transparent 50%%);
  color: var(--text-main);
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.card {
  background: var(--card);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 40px 32px;
  width: 360px;
  text-align: center;
  box-shadow: 0 20px 50px rgba(0,0,0,0.6), 0 0 30px rgba(6, 182, 212, 0.1);
  transition: border-color 0.3s;
}
.card:hover { border-color: var(--border-glow); }

.brand-svg {
  width: 48px; height: 48px;
  margin-bottom: 16px;
  display: inline-block;
  color: var(--cyan);
  filter: drop-shadow(0 0 12px rgba(6, 182, 212, 0.5));
}
.title { font-size: 20px; font-weight: 700; margin-bottom: 8px; letter-spacing: -0.3px; }
.desc { font-size: 13px; color: var(--text-muted); margin-bottom: 28px; line-height: 1.5; }

.hold-btn {
  position: relative;
  width: 100%%;
  height: 56px;
  background: rgba(30, 41, 59, 0.8);
  border: 1px solid rgba(51, 65, 85, 0.8);
  border-radius: 28px;
  overflow: hidden;
  cursor: pointer;
  user-select: none;
  touch-action: none;
  transition: transform 0.15s, border-color 0.2s;
}
.hold-btn:hover { border-color: var(--cyan); box-shadow: 0 0 16px rgba(6, 182, 212, 0.25); }
.hold-fill {
  position: absolute; top: 0; left: 0; height: 100%%; width: 0%%;
  background: linear-gradient(90deg, #06b6d4, #10b981);
  transition: width 0.05s linear;
}
.hold-text {
  position: absolute; top: 0; left: 0; width: 100%%; height: 100%%;
  display: flex; align-items: center; justify-content: center;
  font-size: 14.5px; font-weight: 600; color: #fff;
  text-shadow: 0 1px 3px rgba(0,0,0,0.6); z-index: 2;
}

.footer { margin-top: 24px; font-size: 11.5px; color: var(--text-muted); }
.footer span.brand { color: var(--cyan); font-weight: 600; }
</style>
</head>
<body>
<div class="card">
  <svg class="brand-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
  <div class="title">Human Verification</div>
  <div class="desc">Press and hold the button below for 1.5 seconds to confirm you are a human visitor.</div>
  
  <div class="hold-btn" id="btn">
     <div class="hold-fill" id="fill"></div>
     <div class="hold-text" id="btnText">Press & Hold to Verify</div>
  </div>

  <form id="vform" method="POST" action="%s">
    <input type="hidden" name="challenge_type" value="turnstile">
    <input type="hidden" name="t_id" value="%s">
    <input type="hidden" name="t_hash" value="%s">
    <input type="hidden" name="t_data" id="tData" value="">
  </form>
  <div class="footer">Protected by <span class="brand">Mango Shield Enterprise WAF</span></div>
</div>
<script>
  var btn=document.getElementById('btn'), fill=document.getElementById('fill'), txt=document.getElementById('btnText');
  var form=document.getElementById('vform'), dataInp=document.getElementById('tData');
  var holdTime=0, holding=false, timer, events=[];
  
  function record(e) { if(events.length<10) events.push(e.type); }
  window.addEventListener('mousemove', record);
  window.addEventListener('touchstart', record);

  function startHold(e) {
     if(!e.isTrusted) return;
     holding = true;
     btn.style.transform = 'scale(0.97)';
     timer = setInterval(function() {
        holdTime += 50;
        var p = Math.min((holdTime/1500)*100, 100);
        fill.style.width = p + '%%';
        if(holdTime >= 1500) completeHold();
     }, 50);
  }
  function stopHold() {
     if(!holding) return;
     holding = false;
     clearInterval(timer);
     if(holdTime < 1500) { holdTime = 0; fill.style.width = '0%%'; btn.style.transform = 'scale(1)'; }
  }
  function completeHold() {
     clearInterval(timer);
     btn.style.pointerEvents = 'none';
     btn.style.transform = 'scale(1)';
     txt.innerText = 'Verified';
     fill.style.background = '#10b981';
     
     var ext = (window.screen?screen.width+'x'+screen.height:'0x0') + '|' + (navigator.hardwareConcurrency||0);
     var tok = btoa(events.join(',') + '|' + ext);
     dataInp.value = tok;
     
     setTimeout(function() { form.submit() }, 300);
  }

  btn.addEventListener('mousedown', startHold);
  btn.addEventListener('touchstart', startHold);
  window.addEventListener('mouseup', stopHold);
  window.addEventListener('mouseleave', stopHold);
  window.addEventListener('touchend', stopHold);
  window.addEventListener('touchcancel', stopHold);
</script>
</body>
</html>`
