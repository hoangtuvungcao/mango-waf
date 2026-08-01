package challenge

// powTemplate is the modern JS Proof-of-Work challenge page
var powTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Check — Mango Shield</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg-base: #04060f;
  --bg-card: rgba(13, 18, 36, 0.85);
  --border: rgba(30, 41, 74, 0.7);
  --border-glow: rgba(0, 242, 255, 0.3);
  --accent-cyan: #00f2ff;
  --accent-green: #00ffa3;
  --accent-red: #ff0055;
  --accent-amber: #ffb700;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --font-sans: 'Inter', system-ui, sans-serif;
  --font-mono: 'Fira Code', monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  background: var(--bg-base);
  background-image: 
    radial-gradient(circle at 50%% 20%%, rgba(0, 242, 255, 0.08) 0%%, transparent 50%%),
    radial-gradient(circle at 80%% 80%%, rgba(0, 255, 163, 0.05) 0%%, transparent 40%%);
  color: var(--text-main);
  font-family: var(--font-sans);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.card {
  background: var(--bg-card);
  backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 40px;
  max-width: 480px;
  width: 100%%;
  box-shadow: 0 20px 50px rgba(0,0,0,0.8), 0 0 30px rgba(0, 242, 255, 0.1);
}
.header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
.logo-box { display: flex; align-items: center; gap: 12px; }
.logo-icon { width: 32px; height: 32px; stroke: var(--accent-cyan); fill: none; stroke-width: 2; }
.brand-name { font-size: 16px; font-weight: 800; letter-spacing: -0.5px; }
.badge { font-size: 10px; font-family: var(--font-mono); color: var(--accent-cyan); background: rgba(0,242,255,0.1); padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(0,242,255,0.2); }
.title { font-size: 20px; font-weight: 700; margin-bottom: 8px; }
.desc { font-size: 13.5px; color: var(--text-muted); line-height: 1.5; margin-bottom: 24px; }
.progress-bar-bg { background: rgba(30, 41, 74, 0.6); border-radius: 8px; height: 8px; overflow: hidden; margin-bottom: 20px; border: 1px solid var(--border); }
.progress-bar-fill { height: 100%%; width: 0%%; background: linear-gradient(90deg, var(--accent-cyan), var(--accent-green)); transition: width 0.3s ease; box-shadow: 0 0 12px var(--accent-cyan); }
.status-text { font-size: 13px; color: var(--text-muted); margin-bottom: 24px; display: flex; align-items: center; gap: 8px; font-family: var(--font-mono); }
.spinner { width: 14px; height: 14px; border: 2px solid rgba(0,242,255,0.2); border-top-color: var(--accent-cyan); border-radius: 50%%; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; background: rgba(6, 8, 19, 0.6); padding: 16px; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 24px; }
.meta-item { display: flex; flex-direction: column; gap: 4px; }
.meta-label { font-size: 10px; font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; }
.meta-val { font-size: 12px; font-family: var(--font-mono); color: var(--text-main); font-weight: 600; word-break: break-all; }
.footer { font-size: 11.5px; color: var(--text-muted); text-align: center; }
.footer a { color: var(--accent-cyan); text-decoration: none; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="logo-box">
      <img src="/logo-mango-small.png" alt="Mango Shield" style="width:32px;height:32px;object-fit:contain">
      <div class="brand-name">MANGO SHIELD</div>
    </div>
    <div class="badge">WAF v3.0</div>
  </div>
  <div class="title">Checking Connection Integrity</div>
  <div class="desc">Please wait while Mango Shield validates your browser session before granting access to <strong>%s</strong>.</div>
  <div class="progress-bar-bg"><div class="progress-bar-fill" id="pbar"></div></div>
  <div class="status-text" id="status"><span class="spinner"></span>Solving cryptographic Proof-of-Work...</div>
  <div class="meta-grid">
    <div class="meta-item"><div class="meta-label">Client IP</div><div class="meta-val">%s</div></div>
    <div class="meta-item"><div class="meta-label">Ray ID</div><div class="meta-val">%s</div></div>
    <div class="meta-item"><div class="meta-label">Hashes Evaluated</div><div class="meta-val" id="hashes">0</div></div>
    <div class="meta-item"><div class="meta-label">Compute Speed</div><div class="meta-val" id="speed">—</div></div>
  </div>
  <div class="footer">DDoS Protection by <a href="#">Mango Shield Enterprise</a></div>
</div>
<script>
(function(){
  var challenge='%s',difficulty=%d,target=%d,redir='%s';
  var prefix='';for(var i=0;i<target;i++)prefix+='0';
  var startTime=Date.now(),hashCount=0;
  var statusEl=document.getElementById('status');
  var pbar=document.getElementById('pbar');
  var hashesEl=document.getElementById('hashes');
  var speedEl=document.getElementById('speed');

  function fmt(n){if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return n.toString();}

  var workerCode='self.onmessage=function(e){var c=e.data.challenge,p=e.data.prefix,s=e.data.start,batch=10000;'+
    'function sha256(m){var buf=new TextEncoder().encode(m);return crypto.subtle.digest("SHA-256",buf);}'+
    'async function solve(){try{for(var i=s;i<s+batch;i++){var h=await sha256(c+i);var a=new Uint8Array(h);'+
    'var hex="";for(var j=0;j<a.length;j++)hex+=("0"+a[j].toString(16)).slice(-2);'+
    'if(hex.startsWith(p)){self.postMessage({found:true,nonce:i.toString(),hash:hex,count:i-s+1});return;}}'+
    'self.postMessage({found:false,count:batch,next:s+batch});}catch(err){self.postMessage({error:err.message});}}solve();};';

  var blob=new Blob([workerCode],{type:'application/javascript'});
  var worker=new Worker(URL.createObjectURL(blob));
  var totalCount=0;

  worker.onmessage=function(e){
    var d=e.data;
    totalCount+=d.count||0;
    hashCount=totalCount;
    var elapsed=(Date.now()-startTime)/1000;
    var hps=Math.round(hashCount/elapsed);
    hashesEl.textContent=fmt(hashCount);
    speedEl.textContent=fmt(hps)+'/s';
    pbar.style.width=Math.min(95,Math.log(hashCount+1)/Math.log(1e7)*100)+'%%';

    if(d.found){
      pbar.style.width='100%%';
      statusEl.innerHTML='<span style="color:var(--accent-green)">Verification successful. Redirecting...</span>';
      var form=document.createElement('form');form.method='POST';form.action=redir;
      var fields={challenge_type:'pow',nonce:d.nonce,challenge:challenge,difficulty:difficulty.toString()};
      for(var k in fields){var inp=document.createElement('input');inp.type='hidden';inp.name=k;inp.value=fields[k];form.appendChild(inp);}
      document.body.appendChild(form);
      setTimeout(function(){form.submit();},300);
    } else if(d.next!==undefined){
      worker.postMessage({challenge:challenge,prefix:prefix,start:d.next});
    }
  };
  worker.postMessage({challenge:challenge,prefix:prefix,start:0});
})();
</script>
</body>
</html>`

// silentTemplate is the invisible browser fingerprinting challenge
var silentTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Verifying Session — Mango Shield</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
<style>
body { background: #04060f; color: #f8fafc; font-family: 'Inter', sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
.card { background: rgba(13, 18, 36, 0.85); backdrop-filter: blur(20px); border: 1px solid rgba(30, 41, 74, 0.7); border-radius: 16px; padding: 32px; text-align: center; max-width: 400px; width: 100%%; box-shadow: 0 20px 50px rgba(0,0,0,0.8); }
.dots { display: flex; justify-content: center; gap: 8px; margin-bottom: 20px; }
.dot { width: 10px; height: 10px; border-radius: 50%%; background: #00f2ff; animation: pulse 1.2s infinite ease-in-out; }
.dot:nth-child(2) { animation-delay: 0.2s; background: #00ffa3; }
.dot:nth-child(3) { animation-delay: 0.4s; background: #ffb700; }
@keyframes pulse { 0%%, 80%%, 100%% { transform: scale(0.6); opacity: 0.4; } 40%% { transform: scale(1.2); opacity: 1; } }
.msg { font-size: 13.5px; color: #94a3b8; font-family: 'Fira Code', monospace; }
</style>
</head>
<body>
<div class="card">
  <div class="dots"><div class="dot"></div><div class="dot"></div><div class="dot"></div></div>
  <div class="msg">Verifying browser security profile...</div>
</div>
<script>
(function(){
  var fp={};
  try{var c=document.createElement('canvas');c.width=200;c.height=50;var x=c.getContext('2d');
  x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(20,0,100,30);
  x.fillStyle='#069';x.fillText('Mng',2,15);fp.cv=c.toDataURL().slice(-20);}catch(e){fp.cv='e';}
  fp.s=screen.width+'x'+screen.height;fp.tz=new Date().getTimezoneOffset();
  fp.c=navigator.hardwareConcurrency||0;fp.l=navigator.language;fp.w=navigator.webdriver?1:0;
  var h=0,s=JSON.stringify(fp);for(var i=0;i<s.length;i++)h=((h<<5)-h+s.charCodeAt(i))|0;
  document.cookie='mango_fp='+btoa(JSON.stringify({h:h,w:fp.w,s:fp.s}))+';path=/;max-age=3600;SameSite=Strict';
  if(!fp.w)setTimeout(function(){location.href='%s';},400);
  else document.body.innerHTML='<div style="color:#ff0055;font-family:sans-serif;padding:20px;">Access Denied: Automated bot detected</div>';
})();
</script>
</body>
</html>`

// captchaTemplate is the Turnstile / Hold-to-Verify challenge
var captchaTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Verification — Mango Shield</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg-base: #04060f;
  --bg-card: rgba(13, 18, 36, 0.85);
  --border: rgba(30, 41, 74, 0.7);
  --accent-cyan: #00f2ff;
  --accent-green: #00ffa3;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --font-sans: 'Inter', system-ui, sans-serif;
  --font-mono: 'Fira Code', monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg-base); color: var(--text-main); font-family: var(--font-sans); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
.card { background: var(--bg-card); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 20px; padding: 40px; max-width: 440px; width: 100%%; box-shadow: 0 20px 50px rgba(0,0,0,0.8); text-align: center; }
.header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
.logo-box { display: flex; align-items: center; gap: 10px; }
.logo-icon { width: 28px; height: 28px; stroke: var(--accent-cyan); fill: none; stroke-width: 2; }
.brand-name { font-size: 15px; font-weight: 800; }
.badge { font-size: 10px; font-family: var(--font-mono); color: var(--accent-cyan); background: rgba(0,242,255,0.1); padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(0,242,255,0.2); }
.title { font-size: 20px; font-weight: 700; margin-bottom: 8px; }
.desc { font-size: 13.5px; color: var(--text-muted); line-height: 1.5; margin-bottom: 28px; }
.hold-btn { position: relative; width: 100%%; height: 56px; background: rgba(30, 41, 74, 0.6); border: 1px solid var(--border); border-radius: 28px; overflow: hidden; cursor: pointer; user-select: none; transition: border-color 0.2s; }
.hold-btn:hover { border-color: var(--accent-cyan); box-shadow: 0 0 16px rgba(0,242,255,0.2); }
.hold-fill { position: absolute; top: 0; left: 0; height: 100%%; width: 0%%; background: linear-gradient(90deg, var(--accent-cyan), var(--accent-green)); transition: width 0.05s linear; }
.hold-text { position: absolute; top: 0; left: 0; width: 100%%; height: 100%%; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: 600; color: #fff; z-index: 2; }
.meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; background: rgba(6, 8, 19, 0.6); padding: 14px; border-radius: 12px; border: 1px solid var(--border); margin-top: 24px; text-align: left; }
.meta-label { font-size: 10px; font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; }
.meta-val { font-size: 12px; font-family: var(--font-mono); color: var(--text-main); font-weight: 600; }
.footer { margin-top: 24px; font-size: 11.5px; color: var(--text-muted); }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="logo-box">
      <img src="/logo-mango-small.png" alt="Mango Shield" style="width:28px;height:28px;object-fit:contain">
      <div class="brand-name">MANGO SHIELD</div>
    </div>
    <div class="badge">WAF v3.0</div>
  </div>
  <div class="title">Human Verification</div>
  <div class="desc">Press and hold the button below for 1.5 seconds to confirm you are a human visitor to <strong>%s</strong>.</div>
  
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

  <div class="meta-grid">
    <div><div class="meta-label">Client IP</div><div class="meta-val">%s</div></div>
    <div><div class="meta-label">Ray ID</div><div class="meta-val">%s</div></div>
  </div>
  <div class="footer">Secured by Mango Shield Enterprise WAF</div>
</div>
<script>
  var btn=document.getElementById('btn'), fill=document.getElementById('fill'), txt=document.getElementById('btnText');
  var form=document.getElementById('vform'), dataInp=document.getElementById('tData');
  var holdTime=0, holding=false, timer, events=[];
  
  function record(e) { if(events.length<10) events.push(e.type); }
  window.addEventListener('mousemove', record); window.addEventListener('touchstart', record);

  function startHold(e) {
     if(!e.isTrusted) return; holding = true;
     timer = setInterval(function() {
        holdTime += 50; fill.style.width = Math.min((holdTime/1500)*100, 100) + '%%';
        if(holdTime >= 1500) completeHold();
     }, 50);
  }
  function stopHold() {
     if(!holding) return; holding = false; clearInterval(timer);
     if(holdTime < 1500) { holdTime = 0; fill.style.width = '0%%'; }
  }
  function completeHold() {
     clearInterval(timer); btn.style.pointerEvents = 'none';
     txt.innerText = 'Verified'; fill.style.background = '#00ffa3';
     dataInp.value = btoa(events.join(',') + '|' + (screen.width+'x'+screen.height));
     setTimeout(function() { form.submit() }, 300);
  }

  btn.addEventListener('mousedown', startHold); btn.addEventListener('touchstart', startHold);
  window.addEventListener('mouseup', stopHold); window.addEventListener('mouseleave', stopHold);
  window.addEventListener('touchend', stopHold);
</script>
</body>
</html>`

// blockTemplate is the commercial WAF HTTP 403 Forbidden page
var blockTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>403 Forbidden — Mango Shield WAF</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg-base: #04060f;
  --bg-card: rgba(13, 18, 36, 0.85);
  --border: rgba(30, 41, 74, 0.7);
  --accent-red: #ff0055;
  --accent-cyan: #00f2ff;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --font-sans: 'Inter', system-ui, sans-serif;
  --font-mono: 'Fira Code', monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg-base); color: var(--text-main); font-family: var(--font-sans); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
.card { background: var(--bg-card); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 20px; padding: 40px; max-width: 520px; width: 100%%; box-shadow: 0 20px 50px rgba(0,0,0,0.8), 0 0 30px rgba(255, 0, 85, 0.15); }
.header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
.logo-box { display: flex; align-items: center; gap: 10px; }
.logo-icon { width: 32px; height: 32px; stroke: var(--accent-red); fill: none; stroke-width: 2; }
.brand-name { font-size: 16px; font-weight: 800; }
.badge-red { font-size: 10px; font-family: var(--font-mono); color: var(--accent-red); background: rgba(255,0,85,0.1); padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(255,0,85,0.3); font-weight: 700; }
.title { font-size: 24px; font-weight: 800; margin-bottom: 8px; color: var(--accent-red); }
.desc { font-size: 14px; color: var(--text-muted); line-height: 1.6; margin-bottom: 24px; }
.meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; background: rgba(6, 8, 19, 0.6); padding: 16px; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 24px; }
.meta-label { font-size: 10px; font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; }
.meta-val { font-size: 12px; font-family: var(--font-mono); color: var(--text-main); font-weight: 600; word-break: break-all; margin-top: 2px; }
.notice-box { background: rgba(255,0,85,0.05); border: 1px solid rgba(255,0,85,0.2); border-radius: 10px; padding: 14px; font-size: 12.5px; color: var(--text-muted); line-height: 1.5; margin-bottom: 24px; }
.footer { font-size: 11.5px; color: var(--text-muted); text-align: center; }
.footer a { color: var(--accent-cyan); text-decoration: none; }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="logo-box">
      <img src="/logo-mango-small.png" alt="Mango Shield" style="width:32px;height:32px;object-fit:contain">
      <div class="brand-name">MANGO SHIELD</div>
    </div>
    <div class="badge-red">ACCESS BLOCKED</div>
  </div>
  <div class="title">403 Forbidden</div>
  <div class="desc">Your request to <strong>%s</strong> was intercepted and blocked by Mango Shield Web Application Firewall due to a security policy violation.</div>
  
  <div class="meta-grid">
    <div><div class="meta-label">Client IP</div><div class="meta-val">%s</div></div>
    <div><div class="meta-label">Ray ID</div><div class="meta-val">%s</div></div>
    <div><div class="meta-label">Rule Triggered</div><div class="meta-val">%s</div></div>
    <div><div class="meta-label">Timestamp</div><div class="meta-val">%s</div></div>
  </div>

  <div class="notice-box">
    If you are the website administrator or believe this request was blocked in error, please contact support and provide the Ray ID shown above.
  </div>

  <div class="footer">DDoS Protection & WAF Engine by <a href="#">Mango Shield Enterprise</a></div>
</div>
</body>
</html>`

// rateLimitTemplate is the commercial HTTP 429 Too Many Requests page
var rateLimitTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>429 Rate Limit Exceeded — Mango Shield WAF</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg-base: #04060f;
  --bg-card: rgba(13, 18, 36, 0.85);
  --border: rgba(30, 41, 74, 0.7);
  --accent-amber: #ffb700;
  --accent-cyan: #00f2ff;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --font-sans: 'Inter', system-ui, sans-serif;
  --font-mono: 'Fira Code', monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg-base); color: var(--text-main); font-family: var(--font-sans); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
.card { background: var(--bg-card); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 20px; padding: 40px; max-width: 480px; width: 100%%; box-shadow: 0 20px 50px rgba(0,0,0,0.8), 0 0 30px rgba(255, 183, 0, 0.15); text-align: center; }
.header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
.logo-box { display: flex; align-items: center; gap: 10px; }
.logo-icon { width: 32px; height: 32px; stroke: var(--accent-amber); fill: none; stroke-width: 2; }
.brand-name { font-size: 16px; font-weight: 800; }
.badge-amber { font-size: 10px; font-family: var(--font-mono); color: var(--accent-amber); background: rgba(255,183,0,0.1); padding: 3px 8px; border-radius: 4px; border: 1px solid rgba(255,183,0,0.3); font-weight: 700; }
.title { font-size: 22px; font-weight: 800; margin-bottom: 8px; color: var(--accent-amber); }
.desc { font-size: 13.5px; color: var(--text-muted); line-height: 1.5; margin-bottom: 24px; }
.timer-box { font-size: 36px; font-family: var(--font-mono); font-weight: 700; color: var(--accent-amber); margin-bottom: 20px; }
.meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; background: rgba(6, 8, 19, 0.6); padding: 14px; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 24px; text-align: left; }
.meta-label { font-size: 10px; font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; }
.meta-val { font-size: 12px; font-family: var(--font-mono); color: var(--text-main); font-weight: 600; }
.footer { font-size: 11.5px; color: var(--text-muted); }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="logo-box">
      <img src="/logo-mango-small.png" alt="Mango Shield" style="width:32px;height:32px;object-fit:contain">
      <div class="brand-name">MANGO SHIELD</div>
    </div>
    <div class="badge-amber">RATE LIMITED</div>
  </div>
  <div class="title">429 Too Many Requests</div>
  <div class="desc">You have exceeded the request rate limit configured for <strong>%s</strong>. Please wait before retrying.</div>
  
  <div class="timer-box" id="timer">%ds</div>

  <div class="meta-grid">
    <div><div class="meta-label">Client IP</div><div class="meta-val">%s</div></div>
    <div><div class="meta-label">Ray ID</div><div class="meta-val">%s</div></div>
  </div>

  <div class="footer">Rate Limiting & DDoS Shield by Mango Shield v3.0</div>
</div>
<script>
  var secs = %d;
  var timerEl = document.getElementById('timer');
  var interval = setInterval(function() {
    secs--;
    if (secs <= 0) {
      clearInterval(interval);
      timerEl.innerText = 'Ready';
      timerEl.style.color = '#00ffa3';
      setTimeout(function(){ location.reload(); }, 500);
    } else {
      timerEl.innerText = secs + 's';
    }
  }, 1000);
</script>
</body>
</html>`

// accessDeniedTemplate is the commercial HTTP 401/403 Security Policy Access Denied page
var accessDeniedTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Denied — Mango Shield WAF</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg-base: #04060f;
  --bg-card: rgba(13, 18, 36, 0.85);
  --border: rgba(30, 41, 74, 0.7);
  --accent-red: #ff0055;
  --accent-cyan: #00f2ff;
  --text-main: #f8fafc;
  --text-muted: #94a3b8;
  --font-sans: 'Inter', system-ui, sans-serif;
  --font-mono: 'Fira Code', monospace;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg-base); color: var(--text-main); font-family: var(--font-sans); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
.card { background: var(--bg-card); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 20px; padding: 40px; max-width: 480px; width: 100%%; box-shadow: 0 20px 50px rgba(0,0,0,0.8); text-align: center; }
.header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
.logo-box { display: flex; align-items: center; gap: 10px; }
.logo-icon { width: 32px; height: 32px; stroke: var(--accent-red); fill: none; stroke-width: 2; }
.brand-name { font-size: 16px; font-weight: 800; }
.title { font-size: 22px; font-weight: 800; margin-bottom: 8px; color: var(--accent-red); }
.desc { font-size: 13.5px; color: var(--text-muted); line-height: 1.5; margin-bottom: 24px; }
.meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; background: rgba(6, 8, 19, 0.6); padding: 14px; border-radius: 12px; border: 1px solid var(--border); margin-bottom: 24px; text-align: left; }
.meta-label { font-size: 10px; font-family: var(--font-mono); color: var(--text-muted); text-transform: uppercase; }
.meta-val { font-size: 12px; font-family: var(--font-mono); color: var(--text-main); font-weight: 600; }
.footer { font-size: 11.5px; color: var(--text-muted); }
</style>
</head>
<body>
<div class="card">
  <div class="header">
    <div class="logo-box">
      <img src="/logo-mango-small.png" alt="Mango Shield" style="width:32px;height:32px;object-fit:contain">
      <div class="brand-name">MANGO SHIELD</div>
    </div>
  </div>
  <div class="title">Access Denied</div>
  <div class="desc">You do not have permission to access <strong>%s</strong>. Security Policy: <strong>%s</strong></div>

  <div class="meta-grid">
    <div><div class="meta-label">Client IP</div><div class="meta-val">%s</div></div>
    <div><div class="meta-label">Ray ID</div><div class="meta-val">%s</div></div>
  </div>

  <div class="footer">Security Policy Enforced by Mango Shield v3.0</div>
</div>
</body>
</html>`
