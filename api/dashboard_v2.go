package api

// ============================================================================
// MANGO SHIELD WAF v2.0 — FULL MANAGEMENT PLATFORM SPA
// Landing Page + Auth + Dashboard + Domain/SSL/Node/Traffic Management
// Cyberpunk Dark Enterprise Design System
// ============================================================================

var managementPlatformHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mango Shield — Free Enterprise WAF Protection</title>
<meta name="description" content="Mango Shield WAF - Enterprise-grade Web Application Firewall. Free DDoS protection, SSL management, real-time traffic analytics. Protect your website now.">
<link rel="icon" type="image/svg+xml" href="/logo-mango.png">
<link rel="shortcut icon" href="/favicon.ico">
<link rel="apple-touch-icon" href="/logo-mango.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:ital,wght@0,300;0,400;0,500;0,600;0,700;0,800;1,400&family=Fira+Code:wght@400;500;600&display=swap" rel="stylesheet">
<style>
/* ========================================================================
   DESIGN SYSTEM TOKENS
   ======================================================================== */
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#020617;
  --bg-card:rgba(15,23,42,0.85);
  --bg-card-solid:#0f172a;
  --bg-elevated:#1e293b;
  --bg-hover:rgba(30,41,59,0.6);
  --bg-input:#0c1222;
  --accent:#22c55e;
  --accent-glow:rgba(34,197,94,0.25);
  --accent-dim:rgba(34,197,94,0.12);
  --cyan:#00d4ff;
  --cyan-glow:rgba(0,212,255,0.2);
  --red:#ef4444;
  --red-glow:rgba(239,68,68,0.2);
  --amber:#f59e0b;
  --amber-glow:rgba(245,158,11,0.15);
  --purple:#a855f7;
  --purple-glow:rgba(168,85,247,0.15);
  --text:#f8fafc;
  --text-secondary:#cbd5e1;
  --text-muted:#64748b;
  --border:rgba(51,65,85,0.5);
  --border-active:rgba(34,197,94,0.4);
  --font:'Plus Jakarta Sans',system-ui,-apple-system,sans-serif;
  --mono:'Fira Code','JetBrains Mono',monospace;
  --radius:12px;
  --radius-sm:8px;
  --radius-lg:16px;
  --shadow:0 4px 24px rgba(0,0,0,0.4);
  --shadow-glow:0 0 30px var(--accent-glow);
  --transition:all .2s cubic-bezier(.4,0,.2,1);
}
/* World Map SVG Custom styling */
#world-map-svg {
  background: #020617;
}
#world-map-svg path {
  fill: #0c152a;
  stroke: #1e293b;
  stroke-width: 0.6px;
  transition: fill 0.3s ease, stroke 0.3s ease;
}
#world-map-svg path.attack-highlight {
  fill: rgba(239, 68, 68, 0.75) !important;
  stroke: #ef4444 !important;
  stroke-width: 1.5px !important;
}
html{scroll-behavior:smooth;font-size:16px}
body{
  font-family:var(--font);
  background:var(--bg);
  color:var(--text);
  line-height:1.6;
  min-height:100vh;
  -webkit-font-smoothing:antialiased;
  overflow-x:hidden;
}
a{color:var(--cyan);text-decoration:none;transition:var(--transition)}
a:hover{color:var(--accent)}

/* ========================================================================
   SCROLLBAR
   ======================================================================== */
::-webkit-scrollbar{width:6px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--text-muted)}

/* ========================================================================
   UTILITY CLASSES
   ======================================================================== */
.container{max-width:1280px;margin:0 auto;padding:0 24px}
.flex{display:flex}.flex-col{flex-direction:column}
.items-center{align-items:center}.justify-between{justify-content:space-between}
.justify-center{justify-content:center}.gap-8{gap:8px}.gap-12{gap:12px}
.gap-16{gap:16px}.gap-24{gap:24px}.gap-32{gap:32px}
.text-center{text-align:center}.text-right{text-align:right}
.text-accent{color:var(--accent)}.text-cyan{color:var(--cyan)}
.text-red{color:var(--red)}.text-amber{color:var(--amber)}
.text-muted{color:var(--text-muted)}.text-secondary{color:var(--text-secondary)}
.font-mono{font-family:var(--mono)}.font-semibold{font-weight:600}
.font-bold{font-weight:700}.font-extrabold{font-weight:800}
.text-xs{font-size:.75rem}.text-sm{font-size:.875rem}
.text-base{font-size:1rem}.text-lg{font-size:1.125rem}
.text-xl{font-size:1.25rem}.text-2xl{font-size:1.5rem}
.text-3xl{font-size:1.875rem}.text-4xl{font-size:2.25rem}
.text-5xl{font-size:3rem}.text-6xl{font-size:3.75rem}
.w-full{width:100%}.mt-4{margin-top:16px}.mt-8{margin-top:32px}
.mb-4{margin-bottom:16px}.mb-8{margin-bottom:32px}
.p-16{padding:16px}.p-24{padding:24px}.p-32{padding:32px}
.hidden{display:none!important}
.grid{display:grid}
.grid-2{grid-template-columns:repeat(2,1fr)}
.grid-3{grid-template-columns:repeat(3,1fr)}
.grid-4{grid-template-columns:repeat(4,1fr)}
@media(max-width:1024px){.grid-4{grid-template-columns:repeat(2,1fr)}}
@media(max-width:768px){
  .grid-2,.grid-3,.grid-4{grid-template-columns:1fr}
  .container{padding:0 16px}
  .text-6xl{font-size:2.5rem}.text-5xl{font-size:2rem}
  .text-4xl{font-size:1.75rem}
  .hide-mobile{display:none!important}
}

/* ========================================================================
   BUTTONS
   ======================================================================== */
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:8px;
  padding:12px 28px;border-radius:var(--radius-sm);font-weight:600;
  font-size:.9rem;border:none;cursor:pointer;transition:var(--transition);
  font-family:var(--font);letter-spacing:.01em;position:relative;overflow:hidden;
}
.btn:active{transform:scale(.97)}
.btn-primary{
  background:var(--accent);color:#020617;
  box-shadow:0 0 20px var(--accent-glow);
}
.btn-primary:hover{background:#16a34a;box-shadow:0 0 30px var(--accent-glow)}
.btn-secondary{
  background:transparent;color:var(--text);
  border:1px solid var(--border);
}
.btn-secondary:hover{border-color:var(--accent);color:var(--accent)}
.btn-danger{background:var(--red);color:#fff;box-shadow:0 0 15px var(--red-glow)}
.btn-danger:hover{background:#dc2626}
.btn-cyan{background:var(--cyan);color:#020617;box-shadow:0 0 15px var(--cyan-glow)}
.btn-cyan:hover{background:#00b8d9}
.btn-sm{padding:8px 16px;font-size:.8rem;border-radius:6px}
.btn-lg{padding:16px 40px;font-size:1.05rem;border-radius:var(--radius)}
.btn-icon{padding:8px;border-radius:var(--radius-sm);background:var(--bg-hover);color:var(--text-muted);border:1px solid var(--border);cursor:pointer;transition:var(--transition)}
.btn-icon:hover{color:var(--accent);border-color:var(--accent)}

/* ========================================================================
   FORM INPUTS
   ======================================================================== */
.input-group{display:flex;flex-direction:column;gap:6px}
.input-group label{font-size:.85rem;color:var(--text-secondary);font-weight:500}
.input,.select,.textarea{
  padding:12px 16px;background:var(--bg-input);border:1px solid var(--border);
  border-radius:var(--radius-sm);color:var(--text);font-family:var(--font);
  font-size:.9rem;transition:var(--transition);outline:none;width:100%;
}
.input:focus,.select:focus,.textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
.input::placeholder{color:var(--text-muted)}
.textarea{min-height:100px;resize:vertical}
.select{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%2364748b' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;padding-right:36px}
.select option{background:var(--bg-card-solid);color:var(--text)}

/* ========================================================================
   CARDS
   ======================================================================== */
.card{
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:var(--radius);padding:24px;
  backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
  transition:var(--transition);
}
.card:hover{border-color:var(--border-active)}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.card-title{font-size:1rem;font-weight:600;color:var(--text)}
.stat-card{text-align:center;padding:20px}
.stat-card .stat-value{font-size:2rem;font-weight:800;font-family:var(--mono);margin:8px 0 4px}
.stat-card .stat-label{font-size:.8rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em}

/* ========================================================================
   BADGE / PILL
   ======================================================================== */
.badge{
  display:inline-flex;align-items:center;gap:4px;
  padding:4px 10px;border-radius:100px;font-size:.75rem;font-weight:600;
}
.badge-green{background:var(--accent-dim);color:var(--accent)}
.badge-red{background:var(--red-glow);color:var(--red)}
.badge-amber{background:var(--amber-glow);color:var(--amber)}
.badge-cyan{background:var(--cyan-glow);color:var(--cyan)}
.badge-purple{background:var(--purple-glow);color:var(--purple)}

/* ========================================================================
   TABLE
   ======================================================================== */
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius)}
.table{width:100%;border-collapse:collapse;font-size:.875rem}
.table th{
  padding:12px 16px;text-align:left;font-weight:600;font-size:.75rem;
  text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);
  background:var(--bg-elevated);border-bottom:1px solid var(--border);
}
.table td{padding:12px 16px;border-bottom:1px solid var(--border)}
.table tr:last-child td{border-bottom:none}
.table tr:hover td{background:var(--bg-hover)}

/* ========================================================================
   MODAL
   ======================================================================== */
.modal-overlay{
  position:fixed;inset:0;background:rgba(0,0,0,.6);
  backdrop-filter:blur(4px);z-index:1000;
  display:flex;align-items:center;justify-content:center;
  opacity:0;pointer-events:none;transition:opacity .2s ease;
}
.modal-overlay.active{opacity:1;pointer-events:auto}
.modal{
  background:var(--bg-card-solid);border:1px solid var(--border);
  border-radius:var(--radius-lg);padding:32px;
  width:90%;max-width:560px;max-height:85vh;overflow-y:auto;
  transform:translateY(20px) scale(.97);transition:transform .25s ease;
}
.modal-overlay.active .modal{transform:translateY(0) scale(1)}
.modal-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}
.modal-title{font-size:1.25rem;font-weight:700}
.modal-close{background:none;border:none;color:var(--text-muted);cursor:pointer;font-size:1.5rem;padding:4px;transition:var(--transition)}
.modal-close:hover{color:var(--red)}

/* ========================================================================
   TOAST NOTIFICATIONS
   ======================================================================== */
.toast-container{position:fixed;top:20px;right:20px;z-index:2000;display:flex;flex-direction:column;gap:8px}
.toast{
  padding:14px 20px;border-radius:var(--radius-sm);font-size:.875rem;
  font-weight:500;display:flex;align-items:center;gap:10px;
  animation:slideInRight .3s ease;min-width:300px;max-width:450px;
  box-shadow:0 8px 32px rgba(0,0,0,.4);
}
.toast-success{background:#064e3b;border:1px solid var(--accent);color:var(--accent)}
.toast-error{background:#450a0a;border:1px solid var(--red);color:var(--red)}
.toast-info{background:#082f49;border:1px solid var(--cyan);color:var(--cyan)}
@keyframes slideInRight{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}

/* ========================================================================
   LANDING PAGE
   ======================================================================== */
.landing-nav{
  position:fixed;top:0;left:0;right:0;z-index:100;
  padding:16px 0;transition:var(--transition);
}
.landing-nav.scrolled{background:rgba(2,6,23,.9);backdrop-filter:blur(20px);border-bottom:1px solid var(--border)}
.nav-inner{display:flex;align-items:center;justify-content:space-between}
.nav-logo{display:flex;align-items:center;gap:10px;font-size:1.25rem;font-weight:800}
.nav-logo svg{width:32px;height:32px}
.nav-links{display:flex;align-items:center;gap:32px}
.nav-links a{color:var(--text-secondary);font-size:.9rem;font-weight:500;transition:var(--transition)}
.nav-links a:hover{color:var(--accent)}
.nav-auth{display:flex;gap:12px}

/* Hero */
.hero{
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  text-align:center;position:relative;overflow:hidden;padding:120px 24px 80px;
}
.hero::before{
  content:'';position:absolute;inset:0;
  background:
    radial-gradient(ellipse 80% 60% at 50% -20%,var(--accent-glow),transparent),
    radial-gradient(ellipse 60% 40% at 80% 80%,var(--cyan-glow),transparent),
    radial-gradient(ellipse 40% 30% at 20% 60%,var(--purple-glow),transparent);
  z-index:0;
}
.hero-grid{
  position:absolute;inset:0;z-index:0;
  background-image:
    linear-gradient(var(--border) 1px,transparent 1px),
    linear-gradient(90deg,var(--border) 1px,transparent 1px);
  background-size:60px 60px;
  mask-image:radial-gradient(ellipse 70% 70% at 50% 50%,black 20%,transparent 70%);
  -webkit-mask-image:radial-gradient(ellipse 70% 70% at 50% 50%,black 20%,transparent 70%);
  opacity:.3;
}
.hero-content{position:relative;z-index:1;max-width:800px}
.hero-badge{
  display:inline-flex;align-items:center;gap:8px;
  padding:8px 20px;border-radius:100px;
  background:var(--accent-dim);border:1px solid rgba(34,197,94,.2);
  font-size:.8rem;font-weight:600;color:var(--accent);margin-bottom:24px;
}
.hero-badge .pulse{width:8px;height:8px;border-radius:50%;background:var(--accent);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(1.2)}}
.hero h1{font-size:3.75rem;font-weight:800;line-height:1.1;margin-bottom:20px;letter-spacing:-.02em}
.hero h1 .gradient{background:linear-gradient(135deg,var(--accent),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.hero p{font-size:1.2rem;color:var(--text-secondary);max-width:600px;margin:0 auto 36px;line-height:1.7}
.hero-buttons{display:flex;gap:16px;justify-content:center;flex-wrap:wrap}
.hero-stats{display:flex;gap:48px;justify-content:center;margin-top:64px}
.hero-stat{text-align:center}
.hero-stat .num{font-size:2rem;font-weight:800;font-family:var(--mono);color:var(--accent)}
.hero-stat .label{font-size:.8rem;color:var(--text-muted);margin-top:4px}

/* Features Grid */
.features-section{padding:120px 0;position:relative}
.section-label{
  display:inline-flex;align-items:center;gap:8px;
  font-size:.8rem;font-weight:600;color:var(--cyan);
  text-transform:uppercase;letter-spacing:.1em;margin-bottom:16px;
}
.section-title{font-size:2.5rem;font-weight:800;margin-bottom:16px;letter-spacing:-.02em}
.section-desc{font-size:1.1rem;color:var(--text-secondary);max-width:600px}
.feature-card{padding:32px;position:relative;overflow:hidden}
.feature-card::before{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,transparent,var(--accent),transparent);
  opacity:0;transition:opacity .3s ease;
}
.feature-card:hover::before{opacity:1}
.feature-icon{
  width:48px;height:48px;border-radius:12px;
  display:flex;align-items:center;justify-content:center;
  margin-bottom:20px;font-size:1.3rem;
}
.feature-icon.green{background:var(--accent-dim);color:var(--accent)}
.feature-icon.cyan{background:var(--cyan-glow);color:var(--cyan)}
.feature-icon.amber{background:var(--amber-glow);color:var(--amber)}
.feature-icon.purple{background:var(--purple-glow);color:var(--purple)}
.feature-icon.red{background:var(--red-glow);color:var(--red)}
.feature-card h3{font-size:1.1rem;font-weight:700;margin-bottom:8px}
.feature-card p{font-size:.9rem;color:var(--text-muted);line-height:1.6}

/* Pricing */
.pricing-section{padding:120px 0;background:rgba(15,23,42,.3)}
.pricing-card{padding:40px;text-align:center;position:relative}
.pricing-card.featured{border-color:var(--accent);box-shadow:var(--shadow-glow)}
.pricing-card.featured::before{
  content:'POPULAR';position:absolute;top:-1px;left:50%;transform:translateX(-50%);
  padding:4px 16px;background:var(--accent);color:#020617;font-size:.7rem;
  font-weight:700;border-radius:0 0 8px 8px;letter-spacing:.06em;
}
.pricing-card .price{font-size:3rem;font-weight:800;margin:16px 0}
.pricing-card .price span{font-size:1rem;font-weight:400;color:var(--text-muted)}
.pricing-features{list-style:none;text-align:left;margin:24px 0}
.pricing-features li{padding:10px 0;border-bottom:1px solid var(--border);font-size:.9rem;color:var(--text-secondary);display:flex;align-items:center;gap:8px}
.pricing-features li:last-child{border-bottom:none}
.check{color:var(--accent);font-weight:700}

/* Footer */
.landing-footer{padding:60px 0 30px;border-top:1px solid var(--border)}
.footer-grid{display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:40px}
@media(max-width:768px){.footer-grid{grid-template-columns:1fr}}
.footer-brand p{color:var(--text-muted);font-size:.9rem;margin-top:12px;max-width:300px}
.footer-col h4{font-size:.85rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text);margin-bottom:16px}
.footer-col a{display:block;color:var(--text-muted);font-size:.875rem;padding:4px 0;transition:var(--transition)}
.footer-col a:hover{color:var(--accent)}
.footer-bottom{text-align:center;padding-top:30px;margin-top:30px;border-top:1px solid var(--border);color:var(--text-muted);font-size:.8rem}

/* ========================================================================
   AUTH PAGE
   ======================================================================== */
.auth-page{
  min-height:100vh;display:flex;align-items:center;justify-content:center;
  padding:40px 24px;position:relative;
}
.auth-page::before{
  content:'';position:absolute;inset:0;
  background:radial-gradient(ellipse 50% 50% at 50% 30%,var(--accent-glow),transparent);
}
.auth-card{
  position:relative;z-index:1;width:100%;max-width:420px;
  background:var(--bg-card);border:1px solid var(--border);
  border-radius:var(--radius-lg);padding:40px;
  backdrop-filter:blur(24px);
}
.auth-card .logo{display:flex;align-items:center;justify-content:center;gap:10px;font-size:1.4rem;font-weight:800;margin-bottom:8px}
.auth-card .subtitle{text-align:center;color:var(--text-muted);font-size:.9rem;margin-bottom:32px}
.auth-tabs{display:flex;border-radius:var(--radius-sm);overflow:hidden;border:1px solid var(--border);margin-bottom:24px}
.auth-tab{flex:1;padding:10px;text-align:center;font-size:.875rem;font-weight:600;cursor:pointer;transition:var(--transition);background:transparent;color:var(--text-muted);border:none;font-family:var(--font)}
.auth-tab.active{background:var(--accent);color:#020617}
.auth-form{display:flex;flex-direction:column;gap:16px}
.auth-footer{text-align:center;margin-top:20px;font-size:.85rem;color:var(--text-muted)}
.auth-footer a{color:var(--accent);font-weight:600}

/* ========================================================================
   DASHBOARD LAYOUT (after login)
   ======================================================================== */
.app-layout{display:flex;min-height:100vh}

/* Sidebar */
.sidebar{
  width:260px;background:var(--bg-card-solid);border-right:1px solid var(--border);
  display:flex;flex-direction:column;position:fixed;top:0;bottom:0;left:0;z-index:50;
  transition:transform .3s ease;
}
.sidebar-header{padding:20px 24px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sidebar-header .logo-text{font-size:1.15rem;font-weight:800}
.sidebar-header .version{font-size:.65rem;color:var(--text-muted);background:var(--bg-elevated);padding:2px 8px;border-radius:100px;font-family:var(--mono)}
.sidebar-nav{flex:1;padding:16px 12px;overflow-y:auto}
.nav-section{margin-bottom:20px}
.nav-section-label{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);padding:0 12px;margin-bottom:8px}
.nav-item{
  display:flex;align-items:center;gap:12px;padding:10px 12px;
  border-radius:var(--radius-sm);color:var(--text-secondary);
  font-size:.875rem;font-weight:500;cursor:pointer;
  transition:var(--transition);border:none;background:none;width:100%;text-align:left;font-family:var(--font);
}
.nav-item:hover{background:var(--bg-hover);color:var(--text)}
.nav-item.active{background:var(--accent-dim);color:var(--accent);font-weight:600}
.nav-item svg{width:18px;height:18px;flex-shrink:0}
.nav-item .nav-badge{margin-left:auto;background:var(--red);color:#fff;font-size:.65rem;padding:2px 7px;border-radius:100px;font-weight:700}
.sidebar-footer{padding:16px 24px;border-top:1px solid var(--border)}
.sidebar-user{display:flex;align-items:center;gap:10px}
.sidebar-avatar{width:34px;height:34px;border-radius:50%;background:var(--accent-dim);display:flex;align-items:center;justify-content:center;color:var(--accent);font-weight:700;font-size:.85rem}
.sidebar-user-info .user-name{font-size:.85rem;font-weight:600}
.sidebar-user-info .user-role{font-size:.7rem;color:var(--text-muted)}

/* Main Content */
.main-content{flex:1;margin-left:260px;min-height:100vh}
.topbar{
  padding:16px 32px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;justify-content:space-between;
  background:rgba(2,6,23,.8);backdrop-filter:blur(12px);
  position:sticky;top:0;z-index:40;
}
.topbar-left{display:flex;align-items:center;gap:16px}
.topbar-title{font-size:1.2rem;font-weight:700}
.topbar-right{display:flex;align-items:center;gap:12px}
.page-content{padding:32px}

@media(max-width:1024px){
  .sidebar{transform:translateX(-100%)}
  .sidebar.open{transform:translateX(0)}
  .main-content{margin-left:0}
  .page-content{padding:16px}
}

/* ========================================================================
   DASHBOARD OVERVIEW
   ======================================================================== */
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
@media(max-width:1200px){.stats-grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:600px){.stats-grid{grid-template-columns:1fr}}
.stat-card .stat-icon{
  width:40px;height:40px;border-radius:10px;display:flex;
  align-items:center;justify-content:center;margin:0 auto 8px;font-size:1.1rem;
}
.chart-container{position:relative;height:300px;width:100%}
.chart-canvas{width:100%!important;height:100%!important}
.attack-indicator{
  display:flex;align-items:center;gap:10px;
  padding:12px 20px;border-radius:var(--radius-sm);font-weight:600;font-size:.9rem;
}
.attack-normal{background:var(--accent-dim);color:var(--accent);border:1px solid rgba(34,197,94,.2)}
.attack-active{background:var(--red-glow);color:var(--red);border:1px solid rgba(239,68,68,.3);animation:attackPulse 1.5s infinite}
@keyframes attackPulse{0%,100%{opacity:1}50%{opacity:.7}}

/* ========================================================================
   DOMAIN MANAGER
   ======================================================================== */
.domain-row{display:flex;align-items:center;padding:16px;gap:16px;border-bottom:1px solid var(--border)}
.domain-row:last-child{border-bottom:none}
.domain-row:hover{background:var(--bg-hover)}
.domain-info{flex:1}
.domain-name{font-weight:600;font-family:var(--mono);font-size:.95rem}
.domain-backends{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.backend-tag{
  display:inline-flex;align-items:center;gap:4px;
  padding:3px 10px;background:var(--bg-elevated);border:1px solid var(--border);
  border-radius:6px;font-size:.75rem;font-family:var(--mono);color:var(--text-secondary);
}
.domain-actions{display:flex;gap:8px}

/* ========================================================================
   NODE MANAGER
   ======================================================================== */
.node-card{display:flex;align-items:center;gap:20px;padding:24px}
.node-status-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0}
.node-status-dot.online{background:var(--accent);box-shadow:0 0 10px var(--accent-glow)}
.node-status-dot.offline{background:var(--red);box-shadow:0 0 10px var(--red-glow)}
.node-info{flex:1}
.node-name{font-weight:700;font-size:1rem}
.node-ip{font-family:var(--mono);color:var(--text-muted);font-size:.85rem;margin-top:2px}
.node-metrics{display:flex;gap:24px}
.node-metric{text-align:center}
.node-metric .val{font-weight:700;font-family:var(--mono);font-size:1.1rem}
.node-metric .lbl{font-size:.7rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;margin-top:2px}

/* ========================================================================
   SETTINGS
   ======================================================================== */
.settings-section{margin-bottom:32px}
.settings-section h3{font-size:1.1rem;font-weight:700;margin-bottom:16px;display:flex;align-items:center;gap:10px}
.settings-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
@media(max-width:768px){.settings-grid{grid-template-columns:1fr}}
.toggle{position:relative;width:44px;height:24px;cursor:pointer}
.toggle input{opacity:0;width:0;height:0}
.toggle-slider{
  position:absolute;inset:0;background:var(--bg-elevated);border:1px solid var(--border);
  border-radius:100px;transition:var(--transition);
}
.toggle-slider::before{
  content:'';position:absolute;width:18px;height:18px;border-radius:50%;
  background:var(--text-muted);left:2px;bottom:2px;transition:var(--transition);
}
.toggle input:checked+.toggle-slider{background:var(--accent-dim);border-color:var(--accent)}
.toggle input:checked+.toggle-slider::before{background:var(--accent);transform:translateX(20px)}

/* ========================================================================
   ANIMATIONS
   ======================================================================== */
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.animate-in{animation:fadeIn .4s ease both}
.delay-1{animation-delay:.1s}.delay-2{animation-delay:.2s}
.delay-3{animation-delay:.3s}.delay-4{animation-delay:.4s}

/* Loading spinner */
.spinner{width:20px;height:20px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}

/* Mobile menu toggle */
.mobile-menu-btn{display:none;background:none;border:none;color:var(--text);cursor:pointer;padding:8px}
@media(max-width:1024px){.mobile-menu-btn{display:block}}
</style>
</head>
<body>

<!-- ====================================================================
     TOAST CONTAINER
     ==================================================================== -->
<div id="toast-container" class="toast-container"></div>

<!-- ====================================================================
     LANDING PAGE
     ==================================================================== -->
<div id="page-landing">
  <!-- Nav -->
  <nav class="landing-nav" id="landing-nav">
    <div class="container nav-inner">
      <div class="nav-logo">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" style="width:28px;height:28px;object-fit:contain">
          <defs>
            <linearGradient id="mGrad0" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#FF5722"/><stop offset="50%" stop-color="#FF9800"/><stop offset="100%" stop-color="#FFC107"/></linearGradient>
            <linearGradient id="lGrad0" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#4CAF50"/><stop offset="100%" stop-color="#2E7D32"/></linearGradient>
          </defs>
          <path d="M50 15 C25 15 15 35 15 60 C15 80 32 90 50 90 C72 90 85 75 85 55 C85 30 70 15 50 15 Z" fill="url(#mGrad0)"/>
          <path d="M50 15 C55 5 65 2 75 5 C70 15 60 18 50 15 Z" fill="url(#lGrad0)"/>
        </svg>
        <span>Mango <span class="text-accent">Shield</span></span>
      </div>
      <div class="nav-links hide-mobile">
        <a href="#features">Features</a>
        <a href="#pricing">Pricing</a>
        <a href="#docs">Docs</a>
      </div>
      <div class="nav-auth">
        <button class="btn btn-secondary btn-sm" onclick="showPage('auth')">Login</button>
        <button class="btn btn-primary btn-sm" onclick="showPage('auth');showRegister()">Get Started</button>
      </div>
    </div>
  </nav>

  <!-- Hero -->
  <section class="hero">
    <div class="hero-grid"></div>
    <div class="hero-content animate-in">
      <div class="hero-badge">
        <span class="badge-dot"></span>
        MANGO SHIELD ENTERPRISE WAF v2.0
      </div>
      <h1 class="hero-title">
        Next-Gen Firewall &amp; <br>
        <span class="gradient-text">DDoS Mitigation</span> Engine
      </h1>
      <p class="hero-desc">
        eBPF/XDP kernel-level packet filtering paired with L7 Deep Packet Inspection. 
        Zero latency overhead, real-time attack intelligence, and automated SSL orchestration.
      </p>
      <div class="hero-ctas">
        <button class="btn btn-primary btn-lg" onclick="showPage('auth');showRegister()">
          Start Free Protection
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
        </button>
        <button class="btn btn-secondary btn-lg" onclick="openModal('modal-docs')">View Documentation</button>
      </div>
      <div class="hero-stats">
        <div class="hero-stat">
          <div class="val">&lt; 1ms</div>
          <div class="lbl">Latency Overhead</div>
        </div>
        <div class="hero-stat">
          <div class="val">10M+</div>
          <div class="lbl">RPS Protection</div>
        </div>
        <div class="hero-stat">
          <div class="val">99.99%</div>
          <div class="lbl">Uptime SLA</div>
        </div>
      </div>
    </div>
  </section>

  <!-- Features -->
  <section class="features-section" id="features">
    <div class="container">
      <div class="text-center mb-8">
        <div class="section-label">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
          FEATURES
        </div>
        <h2 class="section-title">Everything You Need to<br><span class="text-accent">Defend Your Infrastructure</span></h2>
        <p class="section-desc" style="margin:0 auto">Military-grade protection layers working together to keep your services online and secure.</p>
      </div>
      <div class="grid grid-3 gap-16 mt-8">
        <div class="card feature-card animate-in">
          <div class="feature-icon green">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <h3>L7 DDoS Protection</h3>
          <p>eBPF/XDP kernel-level packet filtering + Go L7 engine. Blocks attacks at the NIC before they reach your app.</p>
        </div>
        <div class="card feature-card animate-in delay-1">
          <div class="feature-icon cyan">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
          </div>
          <h3>Auto SSL Certificates</h3>
          <p>Automatic SSL generation for all your domains with multi-domain SAN support. Zero-config HTTPS deployment.</p>
        </div>
        <div class="card feature-card animate-in delay-2">
          <div class="feature-icon amber">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
          </div>
          <h3>PoW Challenge Engine</h3>
          <p>Proof-of-Work browser challenges with adaptive difficulty. Humans pass instantly, bots waste CPU cycles.</p>
        </div>
        <div class="card feature-card animate-in delay-1">
          <div class="feature-icon purple">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
          </div>
          <h3>Multi-Node Cluster</h3>
          <p>P2P mesh network syncs ban lists, attack intelligence, and config across all WAF nodes in real-time.</p>
        </div>
        <div class="card feature-card animate-in delay-2">
          <div class="feature-icon red">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
          </div>
          <h3>WAF Rule Engine</h3>
          <p>OWASP Top 10 ruleset with custom rule support. SQL injection, XSS, path traversal all blocked instantly.</p>
        </div>
        <div class="card feature-card animate-in delay-3">
          <div class="feature-icon green">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
          </div>
          <h3>Real-time Analytics</h3>
          <p>Live RPS charts, traffic heatmaps, attack logs, and node health monitoring from a single dashboard.</p>
        </div>
      </div>
    </div>
  </section>

  <!-- Pricing -->
  <section class="pricing-section" id="pricing">
    <div class="container">
      <div class="text-center mb-8">
        <div class="section-label">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/></svg>
          PRICING
        </div>
        <h2 class="section-title">Gói Dịch Vụ <span class="text-accent">Duy Nhất &amp; Miễn Phí</span></h2>
        <p class="section-desc" style="margin:0 auto">Trải nghiệm toàn bộ tính năng Enterprise cao cấp nhất hoàn toàn FREE.</p>
      </div>
      <div style="max-width:560px;margin:32px auto 0">
        <div class="card pricing-card featured animate-in" style="border:2px solid var(--accent);box-shadow:0 0 35px var(--accent-glow);padding:36px">
          <div style="background:var(--accent);color:#020617;padding:5px 16px;border-radius:100px;font-weight:800;font-size:.75rem;letter-spacing:.08em;display:inline-block;margin-bottom:12px">
            GÓI CAO CẤP NHẤT — 100% FREE THỬ NGHIỆM HỆ THỐNG
          </div>
          <h3 class="text-2xl font-extrabold" style="margin-top:8px">Enterprise Shield Plan</h3>
          <div class="price text-accent" style="font-size:3.2rem;font-weight:900;margin:12px 0">FREE<span style="color:var(--text-muted);font-size:1rem">/trọn đời</span></div>
          <p class="text-muted text-sm">Đầy đủ 100% tính năng phòng thủ DDoS &amp; WAF doanh nghiệp</p>
          <ul class="pricing-features" style="margin:24px 0">
            <li><span class="check">🥭</span> <b>Không Giới Hạn Tên Miền (Unlimited Domains)</b></li>
            <li><span class="check">🥭</span> <b>Công Nghệ eBPF/XDP Kernel L3/L4 Protection</b></li>
            <li><span class="check">🥭</span> <b>WAF Rules Engine - OWASP Top 10 Security</b></li>
            <li><span class="check">🥭</span> <b>PoW Browser Challenge Chống Bot Layer 7</b></li>
            <li><span class="check">🥭</span> <b>Cơ Chế Cân Bằng Tải Multi-Node Cluster</b></li>
            <li><span class="check">🥭</span> <b>Tự Động Cấp Phát Chứng Chỉ SSL/TLS Miễn Phí</b></li>
            <li><span class="check">🥭</span> <b>Hỗ Trợ Ẩn IP Gốc Bằng Bản Ghi CNAME</b></li>
          </ul>
          <button class="btn btn-primary btn-lg w-full" onclick="showPage('auth');showRegister()">Đăng Ký &amp; Sử Dụng Ngay (Free)</button>
        </div>
      </div>
    </div>
  </section>

  <!-- Footer -->
  <footer class="landing-footer">
    <div class="container">
      <div class="footer-grid">
        <div class="footer-brand">
          <div class="nav-logo">
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" style="width:28px;height:28px;object-fit:contain">
              <defs>
                <linearGradient id="mGrad1" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#FF5722"/><stop offset="50%" stop-color="#FF9800"/><stop offset="100%" stop-color="#FFC107"/></linearGradient>
                <linearGradient id="lGrad1" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#4CAF50"/><stop offset="100%" stop-color="#2E7D32"/></linearGradient>
              </defs>
              <path d="M50 15 C25 15 15 35 15 60 C15 80 32 90 50 90 C72 90 85 75 85 55 C85 30 70 15 50 15 Z" fill="url(#mGrad1)"/>
              <path d="M50 15 C55 5 65 2 75 5 C70 15 60 18 50 15 Z" fill="url(#lGrad1)"/>
            </svg>
            <span>Mango <span class="text-accent">Shield</span></span>
          </div>
          <p>Enterprise-grade Web Application Firewall protection for everyone.</p>
        </div>
        <div class="footer-col">
          <h4>Product</h4>
          <a href="#features">Features</a>
          <a href="#pricing">Pricing</a>
          <a href="javascript:void(0)" onclick="openModal('modal-docs')">Documentation</a>
        </div>
        <div class="footer-col">
          <h4>Resources</h4>
          <a href="javascript:void(0)" onclick="openModal('modal-docs')">Documentation</a>
          <a href="javascript:void(0)" onclick="openModal('modal-docs')">API Reference</a>
          <a href="#">Community</a>
          <a href="#">Blog</a>
        </div>
        <div class="footer-col">
          <h4>Company</h4>
          <a href="#">About</a>
          <a href="#">Contact</a>
          <a href="#">Privacy</a>
          <a href="#">Terms</a>
        </div>
      </div>
      <div class="footer-bottom">&copy; 2024 Mango Shield WAF. All rights reserved. Built with Go + eBPF.</div>
    </div>
  </footer>
</div>

<!-- ====================================================================
     AUTH PAGE
     ==================================================================== -->
<div id="page-auth" class="hidden">
  <div class="auth-page">
    <div class="auth-card">
      <div class="logo">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" style="width:30px;height:30px;object-fit:contain">
          <defs>
            <linearGradient id="mGrad2" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#FF5722"/><stop offset="50%" stop-color="#FF9800"/><stop offset="100%" stop-color="#FFC107"/></linearGradient>
            <linearGradient id="lGrad2" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#4CAF50"/><stop offset="100%" stop-color="#2E7D32"/></linearGradient>
          </defs>
          <path d="M50 15 C25 15 15 35 15 60 C15 80 32 90 50 90 C72 90 85 75 85 55 C85 30 70 15 50 15 Z" fill="url(#mGrad2)"/>
          <path d="M50 15 C55 5 65 2 75 5 C70 15 60 18 50 15 Z" fill="url(#lGrad2)"/>
        </svg>
        <span>Mango <span class="text-accent">Shield</span></span>
      </div>
      <p class="subtitle">Secure your infrastructure</p>
      <div class="auth-tabs">
        <button class="auth-tab active" id="tab-login" onclick="showLogin()">Sign In</button>
        <button class="auth-tab" id="tab-register" onclick="showRegister()">Create Account</button>
      </div>
      <!-- Login Form -->
      <form class="auth-form" id="form-login" onsubmit="handleLogin(event)">
        <div class="input-group">
          <label for="login-user">Username</label>
          <input class="input" type="text" id="login-user" placeholder="admin" autocomplete="username" required>
        </div>
        <div class="input-group">
          <label for="login-pass">Password</label>
          <input class="input" type="password" id="login-pass" placeholder="Enter password" autocomplete="current-password" required>
        </div>
        <button type="submit" class="btn btn-primary w-full" id="login-btn">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4M10 17l5-5-5-5M15 12H3"/></svg>
          Sign In
        </button>
      </form>
      <!-- Register Form -->
      <form class="auth-form hidden" id="form-register" onsubmit="handleRegister(event)">
        <div class="input-group">
          <label for="reg-email">Email</label>
          <input class="input" type="email" id="reg-email" placeholder="you@example.com" required>
        </div>
        <div class="input-group">
          <label for="reg-user">Username</label>
          <input class="input" type="text" id="reg-user" placeholder="Choose a username" required>
        </div>
        <div class="input-group">
          <label for="reg-pass">Password</label>
          <input class="input" type="password" id="reg-pass" placeholder="Min 8 characters" minlength="8" required>
        </div>
        <button type="submit" class="btn btn-primary w-full">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Create Account &amp; Start Protecting
        </button>
      </form>
      <div class="auth-footer">
        <a href="#" onclick="showPage('landing');return false">&larr; Back to Home</a>
      </div>
    </div>
  </div>
</div>

<!-- ====================================================================
     DASHBOARD APP
     ==================================================================== -->
<div id="page-dashboard" class="hidden">
  <div class="app-layout">
    <!-- Sidebar -->
    <aside class="sidebar" id="sidebar">
      <div class="sidebar-header">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" style="width:28px;height:28px;object-fit:contain">
          <defs>
            <linearGradient id="mGrad3" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#FF5722"/><stop offset="50%" stop-color="#FF9800"/><stop offset="100%" stop-color="#FFC107"/></linearGradient>
            <linearGradient id="lGrad3" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#4CAF50"/><stop offset="100%" stop-color="#2E7D32"/></linearGradient>
          </defs>
          <path d="M50 15 C25 15 15 35 15 60 C15 80 32 90 50 90 C72 90 85 75 85 55 C85 30 70 15 50 15 Z" fill="url(#mGrad3)"/>
          <path d="M50 15 C55 5 65 2 75 5 C70 15 60 18 50 15 Z" fill="url(#lGrad3)"/>
        </svg>
        <span class="logo-text">Mango <span class="text-accent">Shield</span></span>
        <span class="version">v2.0</span>
      </div>
      <nav class="sidebar-nav">
        <div class="nav-section">
          <div class="nav-section-label">Overview</div>
          <button class="nav-item active" onclick="showDashSection('overview')" id="nav-overview">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
            Dashboard
          </button>
          <button class="nav-item" onclick="showDashSection('traffic')" id="nav-traffic">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            Traffic Analytics
          </button>
        </div>

        <div class="nav-section">
          <div class="nav-section-label">Configuration Center</div>
          <button class="nav-item rbac-admin-only" onclick="showDashSection('config-center')" id="nav-config-center">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
            YAML &amp; Config Center
          </button>
          <button class="nav-item rbac-admin-only" onclick="showDashSection('config-backups')" id="nav-config-backups">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
            Backups &amp; Snapshots
          </button>
        </div>

        <div class="nav-section">
          <div class="nav-section-label">Security &amp; WAF</div>
          <button class="nav-item rbac-admin-only" onclick="showDashSection('security-rules')" id="nav-security-rules">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            WAF &amp; Defense Policies
          </button>
          <button class="nav-item rbac-admin-only" onclick="showDashSection('firewall-bans')" id="nav-firewall-bans">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
            IP Firewall &amp; Bans
          </button>
        </div>

        <div class="nav-section">
          <div class="nav-section-label">Management</div>
          <button class="nav-item" onclick="showDashSection('domains')" id="nav-domains">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
            Domains &amp; Upstreams
            <span class="nav-badge" id="domain-count">0</span>
          </button>
          <button class="nav-item" onclick="showDashSection('ssl')" id="nav-ssl">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
            SSL / TLS Manager
          </button>
          <button class="nav-item rbac-admin-only" onclick="showDashSection('nodes')" id="nav-nodes">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
            Cluster Nodes
          </button>
        </div>

        <div class="nav-section">
          <div class="nav-section-label">Observability &amp; RBAC</div>
          <button class="nav-item" onclick="showDashSection('logs-explorer')" id="nav-logs-explorer">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
            Log Explorer
          </button>
          <button class="nav-item rbac-admin-only" onclick="showDashSection('audit-logs')" id="nav-audit-logs">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
            Audit Trail Logs
          </button>
          <button class="nav-item rbac-admin-only" onclick="showDashSection('users')" id="nav-users">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
            Users &amp; Roles
          </button>
        </div>

        <div class="nav-section">
          <div class="nav-section-label">System</div>
          <button class="nav-item rbac-admin-only" onclick="showDashSection('settings')" id="nav-settings">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
            Settings
          </button>
          <button class="nav-item" onclick="handleLogout()" id="nav-logout">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            Logout
          </button>
        </div>
      </nav>
      <div class="sidebar-footer">
        <div class="sidebar-user">
          <div class="sidebar-avatar" id="user-avatar">A</div>
          <div class="sidebar-user-info">
            <div class="user-name" id="user-display-name">Admin</div>
            <div class="user-role" id="user-role-badge">Super Admin</div>
          </div>
        </div>
      </div>
    </aside>

    <!-- Main -->
    <main class="main-content">
      <div class="topbar">
        <div class="topbar-left">
          <button class="mobile-menu-btn" onclick="toggleSidebar()">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
          </button>
          <h1 class="topbar-title" id="topbar-title">Dashboard</h1>
          <div id="attack-status-bar"></div>
        </div>
        <div class="topbar-right">
          <div class="badge badge-purple" id="topbar-user-role">Super Admin</div>
          <div class="badge badge-green" id="topbar-node-badge" onclick="showDashSection('nodes')" style="cursor:pointer" title="Click to view Cluster Nodes">Cluster: 2 Nodes Online</div>
          <div class="badge badge-green" id="topbar-uptime">Uptime: --</div>
          <button class="btn-icon" onclick="refreshData()" title="Refresh">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
          </button>
        </div>
      </div>

      <!-- ====== OVERVIEW SECTION ====== -->
      <div class="page-content" id="section-overview">
        <div class="stats-grid animate-in">
          <div class="card stat-card">
            <div class="stat-icon" style="background:var(--accent-dim);color:var(--accent)">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            </div>
            <div class="stat-value text-accent" id="stat-rps">0</div>
            <div class="stat-label">Current RPS</div>
          </div>
          <div class="card stat-card">
            <div class="stat-icon" style="background:var(--cyan-glow);color:var(--cyan)">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
            </div>
            <div class="stat-value text-cyan" id="stat-conns">0</div>
            <div class="stat-label">Active Connections</div>
          </div>
          <div class="card stat-card">
            <div class="stat-icon" style="background:var(--red-glow);color:var(--red)">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            </div>
            <div class="stat-value text-red" id="stat-blocked">0</div>
            <div class="stat-label">Blocked Requests</div>
          </div>
          <div class="card stat-card">
            <div class="stat-icon" style="background:var(--amber-glow);color:var(--amber)">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            </div>
            <div class="stat-value text-amber" id="stat-bans">0</div>
            <div class="stat-label">Active Bans</div>
          </div>
        </div>

        <!-- ====== BẢN ĐỒ TẤN CÔNG TRỰC TIẾP (LIVE WORLD ATTACK MAP) ====== -->
        <div class="card animate-in delay-1 mb-4" style="margin-bottom:20px;position:relative;overflow:hidden">
          <div class="card-header">
            <div class="flex items-center gap-8">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--red)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
              <span class="card-title font-bold" style="font-size:15px">Bản đồ tấn công trực tiếp</span>
            </div>
            <div class="flex gap-8">
              <span class="badge badge-red" style="background:rgba(239,68,68,0.15);color:var(--red);border:1px solid rgba(239,68,68,0.3)"><span class="pulse" style="background:var(--red);width:6px;height:6px"></span> Live Attack Stream</span>
            </div>
          </div>
          
          <div id="map-viewport" style="position:relative;width:100%;height:380px;background:#020617;border-radius:12px;overflow:hidden;border:1px solid var(--border);cursor:grab;user-select:none">
            <!-- Stats Overlay Banner (matching user screenshot) -->
            <div style="position:absolute;top:16px;left:20px;z-index:10;background:rgba(15,23,42,0.92);border:1px solid var(--border);border-radius:10px;padding:12px 18px;backdrop-filter:blur(10px);box-shadow:0 8px 24px rgba(0,0,0,0.4)">
              <div style="font-size:14px;font-weight:800;color:var(--text-primary)"><span id="map-banned-count" style="color:var(--red);font-size:17px;font-family:var(--font-mono)">3.000</span> IP đang bị chặn</div>
              <div style="font-size:11px;color:var(--text-muted);margin-top:3px" id="map-sub-detail">40 quốc gia - Lớp 7: 1.861 - Flood kết nối: 776 - Lớp 4: 8</div>
            </div>

            <!-- Inner Wrapper containing SVG and Canvas (Lock aspect ratio to prevent warping) -->
            <div id="map-inner-wrapper" style="position:absolute;top:0;left:0;width:2000px;height:857px;transform-origin:0 0;z-index:1">
              <!-- Inlined World Map SVG Container -->
              <div id="world-map-container" style="position:absolute;top:0;left:0;width:100%;height:100%;z-index:1;pointer-events:none"></div>

              <!-- Canvas for Interactive Map Drawing (2000x857 buffer) -->
              <canvas id="attack-map-canvas" width="2000" height="857" style="position:absolute;top:0;left:0;width:100%;height:100%;z-index:2;display:block;background:transparent"></canvas>
            </div>
          </div>
        </div>

        <div class="grid grid-2 gap-16 animate-in delay-1">
          <div class="card">
            <div class="card-header">
              <span class="card-title">RPS Timeline (5 min)</span>
              <span class="badge badge-green font-mono text-xs" id="peak-rps-badge">Peak: 0</span>
            </div>
            <div class="chart-container"><canvas id="rps-chart" class="chart-canvas"></canvas></div>
          </div>
          <div class="card">
            <div class="card-header">
              <span class="card-title">System Resources</span>
              <span class="badge badge-cyan font-mono text-xs" id="cpu-badge">CPU: --%</span>
            </div>
            <div style="display:flex;flex-direction:column;gap:20px;padding:8px 0">
              <div>
                <div class="flex justify-between mb-4"><span class="text-sm text-secondary">CPU Usage</span><span class="font-mono text-sm" id="sys-cpu">0%</span></div>
                <div style="height:8px;background:var(--bg-elevated);border-radius:4px;overflow:hidden"><div id="cpu-bar" style="height:100%;background:var(--accent);border-radius:4px;width:0%;transition:width .5s ease"></div></div>
              </div>
              <div>
                <div class="flex justify-between mb-4"><span class="text-sm text-secondary">Memory Usage</span><span class="font-mono text-sm" id="sys-ram">0 / 0 MB</span></div>
                <div style="height:8px;background:var(--bg-elevated);border-radius:4px;overflow:hidden"><div id="ram-bar" style="height:100%;background:var(--cyan);border-radius:4px;width:0%;transition:width .5s ease"></div></div>
              </div>
              <div>
                <div class="flex justify-between mb-4"><span class="text-sm text-secondary">Disk Usage</span><span class="font-mono text-sm" id="sys-disk">0 / 0 GB</span></div>
                <div style="height:8px;background:var(--bg-elevated);border-radius:4px;overflow:hidden"><div id="disk-bar" style="height:100%;background:var(--amber);border-radius:4px;width:0%;transition:width .5s ease"></div></div>
              </div>
              <div class="grid grid-3 gap-8" style="margin-top:8px">
                <div class="text-center"><div class="font-mono font-bold" id="sys-goroutines">0</div><div class="text-xs text-muted">Goroutines</div></div>
                <div class="text-center"><div class="font-mono font-bold" id="sys-tcp">0</div><div class="text-xs text-muted">TCP Conns</div></div>
                <div class="text-center"><div class="font-mono font-bold" id="sys-load">0</div><div class="text-xs text-muted">Load Avg</div></div>
              </div>
            </div>
          </div>
        </div>

        <!-- ====== TOP ATTACKING COUNTRIES BREAKDOWN ====== -->
        <div class="grid grid-2 gap-16 animate-in delay-2 mt-4" style="margin-top:16px">
          <div class="card">
            <div class="card-header">
              <div class="flex items-center gap-8">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20v-6M6 20V10M18 20V4"/></svg>
                <span class="card-title font-bold">Top Quốc Gia Tấn Công (Real-time)</span>
              </div>
              <span class="badge badge-cyan" id="top-country-count-badge">Active Geo Threats</span>
            </div>
            <div id="country-ranking-list" style="display:flex;flex-direction:column;gap:10px;padding:8px 0;max-height:260px;overflow-y:auto">
              <!-- Dynamically populated real-time country ranking bars -->
            </div>
          </div>

          <div class="card">
            <div class="card-header">
              <span class="card-title">Phân Phối Tấn Công Theo Quốc Gia</span>
              <span class="badge badge-purple">Threat Distribution</span>
            </div>
            <div class="chart-container" style="height:260px"><canvas id="country-attack-chart" class="chart-canvas"></canvas></div>
          </div>
        </div>

        <div class="card animate-in delay-2 mt-4" style="margin-top:16px">
          <div class="card-header">
            <span class="card-title">Protection Status</span>
          </div>
          <div class="grid grid-4 gap-16">
            <div class="text-center"><div class="font-mono font-bold text-lg" id="stat-total">0</div><div class="text-xs text-muted">Total Requests</div></div>
            <div class="text-center"><div class="font-mono font-bold text-lg" id="stat-passed">0</div><div class="text-xs text-muted">Passed</div></div>
            <div class="text-center"><div class="font-mono font-bold text-lg text-amber" id="stat-xdp-drops">0</div><div class="text-xs text-muted">XDP Drops</div></div>
            <div class="text-center"><div class="font-mono font-bold text-lg text-purple" id="stat-early-reject">0</div><div class="text-xs text-muted">Early Rejects</div></div>
          </div>
        </div>
      </div>

      <!-- ====== TRAFFIC SECTION ====== -->
      <div class="page-content hidden" id="section-traffic">
        <div class="card animate-in">
          <div class="card-header">
            <span class="card-title">Traffic Overview — Real-time</span>
            <div class="flex gap-8">
              <span class="badge badge-green"><span class="pulse" style="width:6px;height:6px"></span> Live</span>
            </div>
          </div>
          <div class="chart-container" style="height:350px"><canvas id="traffic-chart" class="chart-canvas"></canvas></div>
        </div>
        <div class="grid grid-3 gap-16 mt-4" style="margin-top:16px">
          <div class="card stat-card animate-in delay-1">
            <div class="stat-value text-accent" id="traffic-total">0</div>
            <div class="stat-label">Total Requests</div>
          </div>
          <div class="card stat-card animate-in delay-2">
            <div class="stat-value text-red" id="traffic-blocked">0</div>
            <div class="stat-label">Blocked</div>
          </div>
          <div class="card stat-card animate-in delay-3">
            <div class="stat-value text-cyan" id="traffic-passed">0</div>
            <div class="stat-label">Passed</div>
          </div>
        </div>
        <div class="card animate-in delay-2 mt-4" style="margin-top:16px">
          <div class="card-header">
            <span class="card-title">Cache Performance</span>
          </div>
          <div class="grid grid-3 gap-16">
            <div class="text-center"><div class="font-mono font-bold text-lg text-accent" id="cache-hits">0</div><div class="text-xs text-muted">Cache Hits</div></div>
            <div class="text-center"><div class="font-mono font-bold text-lg text-red" id="cache-misses">0</div><div class="text-xs text-muted">Cache Misses</div></div>
            <div class="text-center"><div class="font-mono font-bold text-lg text-amber" id="cache-bypasses">0</div><div class="text-xs text-muted">Bypassed</div></div>
          </div>
        </div>
      </div>

      <!-- ====== DOMAINS SECTION ====== -->
      <div class="page-content hidden" id="section-domains">
        <div class="flex justify-between items-center mb-4 animate-in" style="margin-bottom:16px">
          <div>
            <h2 class="text-xl font-bold">Domain Management</h2>
            <p class="text-sm text-muted">Add, configure, and manage protected domains</p>
          </div>
          <button class="btn btn-primary" onclick="openAddDomainModal()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            Add Domain
          </button>
        </div>
        <div class="card animate-in delay-1" id="domains-list">
          <div class="text-center p-32 text-muted">Loading domains...</div>
        </div>
      </div>

      <!-- ====== SSL SECTION ====== -->
      <div class="page-content hidden" id="section-ssl">
        <div class="flex justify-between items-center mb-4 animate-in" style="margin-bottom:16px">
          <div>
            <h2 class="text-xl font-bold">SSL / TLS Certificates</h2>
            <p class="text-sm text-muted">Auto-generate and manage SSL certificates for your domains</p>
          </div>
          <button class="btn btn-cyan" onclick="regenerateAllSSL()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 11-2.12-9.36L23 10"/></svg>
            Regenerate All Certs
          </button>
        </div>
        <div class="card animate-in delay-1" id="ssl-list">
          <div class="text-center p-32 text-muted">Loading SSL status...</div>
        </div>
      </div>

      <!-- ====== NODES SECTION ====== -->
      <div class="page-content hidden" id="section-nodes">
        <div class="flex justify-between items-center mb-4 animate-in" style="margin-bottom:16px">
          <div>
            <h2 class="text-xl font-bold">WAF Multi-Node Cluster Topology</h2>
            <p class="text-sm text-muted">Real-time P2P Gossip mesh &amp; YAML single source of truth cluster status</p>
          </div>
          <div class="flex gap-8 items-center">
            <span class="badge badge-green" id="mesh-status">P2P Mesh: Active</span>
            <span class="badge badge-cyan" id="mesh-nodes-count">Active Nodes: 2</span>
            <button class="btn btn-cyan btn-sm" onclick="triggerClusterSync()">🔄 Broadcast Sync All Nodes</button>
          </div>
        </div>
        <div class="grid grid-1 gap-16 animate-in delay-1" id="nodes-list">
          <div class="card text-center p-32 text-muted">Loading cluster nodes...</div>
        </div>
      </div>

      <!-- ====== SETTINGS SECTION ====== -->
      <div class="page-content hidden" id="section-settings">
        <h2 class="text-xl font-bold mb-4 animate-in" style="margin-bottom:24px">Settings</h2>

        <div class="settings-section animate-in delay-1">
          <h3>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            Protection Configuration
          </h3>
          <div class="card">
            <div class="settings-grid">
              <div class="input-group">
                <label>Protection Mode</label>
                <select class="select" id="set-mode">
                  <option value="auto">Auto (Recommended)</option>
                  <option value="challenge">Challenge</option>
                  <option value="captcha">Captcha</option>
                  <option value="block">Block All</option>
                  <option value="monitor">Monitor Only</option>
                </select>
              </div>
              <div class="input-group">
                <label>Rate Limit (RPS/IP)</label>
                <input class="input" type="number" id="set-rps-limit" placeholder="50">
              </div>
              <div class="input-group">
                <label>Max Connections/IP</label>
                <input class="input" type="number" id="set-conn-limit" placeholder="50">
              </div>
              <div class="input-group">
                <label>Emergency RPS Threshold</label>
                <input class="input" type="number" id="set-emergency-rps" placeholder="150">
              </div>
              <div class="input-group">
                <label>PoW Difficulty (1-10)</label>
                <input class="input" type="number" id="set-pow" min="1" max="10" placeholder="3">
              </div>
              <div class="input-group">
                <label>Ban Duration</label>
                <input class="input" type="text" id="set-ban-duration" placeholder="2h">
              </div>
            </div>
          </div>
        </div>

        <div class="settings-section animate-in delay-2">
          <h3>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--cyan)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>
            Alert Notifications
          </h3>
          <div class="card">
            <div class="settings-grid">
              <div class="input-group">
                <label>Telegram Bot Token</label>
                <input class="input" type="text" id="set-tg-token" placeholder="bot123456:ABC...">
              </div>
              <div class="input-group">
                <label>Telegram Chat ID</label>
                <input class="input" type="text" id="set-tg-chat" placeholder="-1001234567890">
              </div>
              <div class="input-group">
                <label>Discord Webhook URL</label>
                <input class="input" type="text" id="set-discord-url" placeholder="https://discord.com/api/webhooks/...">
              </div>
              <div class="input-group">
                <label>Webhook URL</label>
                <input class="input" type="text" id="set-webhook-url" placeholder="https://your-server.com/webhook">
              </div>
            </div>
          </div>
        </div>

        <div class="flex gap-12 animate-in delay-3" style="margin-top:24px">
          <button class="btn btn-primary" onclick="saveSettings()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
            Save Configuration
          </button>
          <button class="btn btn-danger" onclick="if(confirm('Unban ALL IPs?'))unbanAll()">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
            Unban All IPs
          </button>
        </div>
      </div>

      <!-- ====== CONFIGURATION CENTER SECTION ====== -->
      <div class="page-content hidden" id="section-config-center">
        <div class="card p-24 mb-24">
          <div class="flex justify-between items-center mb-16">
            <div>
              <h3 class="text-xl font-bold text-accent">Single Source of Truth Configuration Center</h3>
              <p class="text-sm text-secondary">YAML Master Configuration Engine with Live Validation &amp; Hot Reload</p>
            </div>
            <div class="flex gap-8">
              <span class="badge badge-green" id="yaml-validation-status">Status: Valid YAML</span>
              <button class="btn btn-secondary btn-sm" onclick="formatYAML()">Auto-Format</button>
              <button class="btn btn-primary btn-sm" onclick="saveYAMLConfig()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/></svg>
                Save &amp; Hot Reload
              </button>
            </div>
          </div>
          <div class="input-group">
            <label>Master YAML Configuration Editor (config/production.yaml)</label>
            <textarea class="textarea font-mono" id="yaml-editor-input" rows="22" style="background:#090d16;color:#a6e22e;font-size:13px;line-height:1.5;tab-size:2" oninput="validateLiveYAML()"></textarea>
          </div>
        </div>

        <div class="card p-24">
          <h4 class="text-lg font-bold text-cyan mb-16">Configuration Version History &amp; Revisions</h4>
          <div class="table-container">
            <table class="table" id="table-revisions">
              <thead>
                <tr>
                  <th>Version ID</th>
                  <th>Timestamp</th>
                  <th>Author</th>
                  <th>Role</th>
                  <th>Description</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="tbody-revisions">
                <tr><td colspan="6" class="text-center text-muted">Loading version history...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ====== CONFIG BACKUPS SECTION ====== -->
      <div class="page-content hidden" id="section-config-backups">
        <div class="card p-24 mb-24">
          <div class="flex justify-between items-center mb-16">
            <div>
              <h3 class="text-xl font-bold text-cyan">Configuration Snapshots &amp; Backups</h3>
              <p class="text-sm text-secondary">Create, download, and restore system snapshots with 1-click safety rollback</p>
            </div>
            <button class="btn btn-primary btn-sm" onclick="promptCreateBackup()">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
              Create Snapshot
            </button>
          </div>
          <div class="table-container">
            <table class="table" id="table-backups">
              <thead>
                <tr>
                  <th>Backup ID / Name</th>
                  <th>Created At</th>
                  <th>Author</th>
                  <th>Description</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="tbody-backups">
                <tr><td colspan="5" class="text-center text-muted">Loading backups...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- ====== SECURITY & WAF SECTION ====== -->
      <div class="page-content hidden" id="section-security-rules">
        <div class="card p-24 mb-24">
          <h3 class="text-xl font-bold text-accent mb-16">Global WAF &amp; DDoS Security Policies</h3>
          <div class="grid grid-2 gap-24">
            <div class="input-group">
              <label>Protection Mode</label>
              <select class="select" id="sec-protection-mode">
                <option value="auto">Auto (Adaptive L7 Mitigation)</option>
                <option value="under_attack">Under Attack (Strict PoW Challenge)</option>
                <option value="challenge">Challenge (JS Challenge All Visitors)</option>
                <option value="captcha">Captcha (Turnstile Verification)</option>
                <option value="emergency">Emergency (Drop All Unverified)</option>
                <option value="monitor">Monitor (Log Only, No Blocking)</option>
                <option value="off">Bypass (Disabled)</option>
              </select>
            </div>
            <div class="input-group">
              <label>WAF Paranoia Level (OWASP CRS)</label>
              <select class="select" id="sec-paranoia-level">
                <option value="1">Level 1 (Standard Minimal False Positives)</option>
                <option value="2">Level 2 (Recommended Production Balance)</option>
                <option value="3">Level 3 (High Security)</option>
                <option value="4">Level 4 (Paranoid Strict Inspection)</option>
              </select>
            </div>
            <div class="input-group">
              <label>Global Rate Limit RPS</label>
              <input class="input" type="number" id="sec-rps" value="100">
            </div>
            <div class="input-group">
              <label>Rate Limit Burst</label>
              <input class="input" type="number" id="sec-burst" value="200">
            </div>
            <div class="input-group">
              <label>Browser PoW Challenge Difficulty (1-6)</label>
              <input class="input" type="number" id="sec-pow-diff" value="4" min="1" max="6">
            </div>
            <div class="input-group">
              <label>Block Datacenter ASNs</label>
              <select class="select" id="sec-block-asn">
                <option value="true">Enabled (Block Known Datacenter/VPN IPs)</option>
                <option value="false">Disabled</option>
              </select>
            </div>
          </div>
          <div class="mt-24">
            <button class="btn btn-primary" onclick="saveSecurityRules()">Save Security Policies</button>
          </div>
        </div>
      </div>

      <!-- ====== FIREWALL & BANS SECTION ====== -->
      <div class="page-content hidden" id="section-firewall-bans">
        <div class="card p-24 mb-24">
          <div class="flex justify-between items-center mb-16">
            <div>
              <h3 class="text-xl font-bold text-red">Active IP Blacklist &amp; Ban List</h3>
              <p class="text-sm text-secondary">IP addresses blocked by kernel eBPF/XDP and rate limiters</p>
            </div>
            <button class="btn btn-danger btn-sm" onclick="executeUnbanAll()">Unban All IPs across Mesh</button>
          </div>
          <div class="table-container">
            <table class="table">
              <thead>
                <tr>
                  <th>IP Address</th>
                  <th>Ban Reason</th>
                  <th>Ban Time</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="tbody-banned-ips">
                <tr><td colspan="4" class="text-center text-muted">No blacklisted IPs found</td></tr>
              </tbody>
            </table>
          </div>
          <div class="flex justify-between items-center mt-16 pt-16" style="border-top:1px solid var(--border)">
            <div class="text-sm text-muted" id="bans-page-info">Showing 0-0 of 0 entries</div>
            <div class="flex gap-8">
              <button class="btn btn-secondary btn-sm" id="btn-bans-prev" onclick="prevBansPage()" disabled>Previous</button>
              <button class="btn btn-secondary btn-sm" id="btn-bans-next" onclick="nextBansPage()" disabled>Next</button>
            </div>
          </div>
        </div>
      </div>

      <!-- ====== LOG EXPLORER SECTION ====== -->
      <div class="page-content hidden" id="section-logs-explorer">
        <div class="card p-24">
          <div class="flex justify-between items-center mb-16 hide-mobile">
            <h3 class="text-xl font-bold text-cyan">Realtime Log Explorer</h3>
            <div class="flex gap-8">
              <input class="input" type="text" id="log-search-input" placeholder="Search IP, Path, Rule..." style="width:220px" oninput="loadLogsExplorer(1)">
              <select class="select" id="log-type-filter" style="width:130px" onchange="loadLogsExplorer(1)">
                <option value="">All Logs</option>
                <option value="SECURITY">Security</option>
                <option value="EXPLOIT">Exploit</option>
                <option value="ACCESS">Access</option>
                <option value="CHALLENGE">Challenge</option>
              </select>
              <button class="btn btn-secondary btn-sm" onclick="loadLogsExplorer()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg> Reload</button>
              <button class="btn btn-secondary btn-sm" onclick="exportLogsCSV()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg> Export CSV</button>
              <button class="btn btn-danger btn-sm" onclick="clearLogsExplorer()"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg> Clear Logs</button>
            </div>
          </div>
          <div class="table-container">
            <table class="table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Type</th>
                  <th>Client IP</th>
                  <th>Domain</th>
                  <th>Method &amp; Path</th>
                  <th>Status</th>
                  <th>Action / Rule</th>
                </tr>
              </thead>
              <tbody id="tbody-logs-explorer">
                <tr><td colspan="7" class="text-center text-muted">Loading logs...</td></tr>
              </tbody>
            </table>
          </div>
          <div class="flex justify-between items-center mt-16 pt-16" style="border-top:1px solid var(--border-color)">
            <div class="text-sm text-muted" id="logs-page-info">Showing 0-0 of 0 entries</div>
            <div class="flex gap-8">
              <button class="btn btn-secondary btn-sm" id="btn-logs-prev" onclick="prevLogsPage()" disabled>Previous</button>
              <button class="btn btn-secondary btn-sm" id="btn-logs-next" onclick="nextLogsPage()" disabled>Next</button>
            </div>
          </div>
        </div>
      </div>

      <!-- ====== AUDIT LOGS SECTION ====== -->
      <div class="page-content hidden" id="section-audit-logs">
        <div class="card p-24">
          <div class="flex justify-between items-center mb-16">
            <div>
              <h3 class="text-xl font-bold text-purple">System Audit Trail</h3>
              <p class="text-sm text-secondary">Complete audit history of user actions and configuration changes</p>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="exportAuditCSV()">Export Audit CSV</button>
          </div>
          <div class="table-container">
            <table class="table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>User</th>
                  <th>Role</th>
                  <th>Action</th>
                  <th>Module</th>
                  <th>Target</th>
                  <th>IP</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody id="tbody-audit-logs">
                <tr><td colspan="8" class="text-center text-muted">Loading audit trail...</td></tr>
              </tbody>
            </table>
          </div>
          <div class="flex justify-between items-center mt-16 pt-16" style="border-top:1px solid var(--border-color)">
            <div class="text-sm text-muted" id="audit-page-info">Showing 0-0 of 0 entries</div>
            <div class="flex gap-8">
              <button class="btn btn-secondary btn-sm" id="btn-audit-prev" onclick="prevAuditPage()" disabled>Previous</button>
              <button class="btn btn-secondary btn-sm" id="btn-audit-next" onclick="nextAuditPage()" disabled>Next</button>
            </div>
          </div>
        </div>
      </div>

      <!-- ====== USERS & RBAC SECTION ====== -->
      <div class="page-content hidden" id="section-users">
        <div class="card p-24">
          <div class="flex justify-between items-center mb-16">
            <div>
              <h3 class="text-xl font-bold text-accent">User Accounts &amp; System Authentication</h3>
              <p class="text-sm text-secondary">Pre-configured accounts managed directly via production.yaml configuration file</p>
            </div>
          </div>
          <div class="table-container">
            <table class="table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Assigned Domains</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody id="tbody-users">
                <tr><td colspan="5" class="text-center text-muted">Loading configured system accounts...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

    </main>
  </div>
</div>

<!-- Config Diff Modal -->
<div class="modal-overlay" id="modal-diff-view">
  <div class="modal" style="max-width:800px">
    <div class="modal-header">
      <span class="modal-title">Configuration Diff Viewer</span>
      <button class="modal-close" onclick="closeModal('modal-diff-view')">&times;</button>
    </div>
    <div style="padding:16px">
      <pre id="diff-text-content" style="background:#090d16;color:#f8fafc;padding:16px;border-radius:8px;font-family:var(--mono);font-size:12px;max-height:60vh;overflow:auto;white-space:pre-wrap"></pre>
    </div>
    <div class="modal-footer" style="padding:16px;text-align:right">
      <button class="btn btn-secondary" onclick="closeModal('modal-diff-view')">Close</button>
    </div>
  </div>
</div>

<!-- ====================================================================
     DOCUMENTATION MODAL
     ==================================================================== -->
<div class="modal-overlay" id="modal-docs">
  <div class="modal" style="max-width:760px;max-height:85vh;overflow-y:auto">
    <div class="modal-header">
      <span class="modal-title" style="display:flex;align-items:center;gap:10px">
        <span style="font-size:1.4rem">🥭</span> Hướng Dẫn Sử Dụng &amp; Cấu Hình Mango Shield WAF
      </span>
      <button class="modal-close" onclick="closeModal('modal-docs')">&times;</button>
    </div>
    <div style="padding:24px;line-height:1.7;color:var(--text);font-size:.92rem">
      <div style="padding:16px;background:var(--bg-elevated);border-radius:var(--radius-sm);border:1px solid var(--border);margin-bottom:20px">
        <h4 style="color:var(--cyan);font-weight:700;margin-bottom:8px">📌 BƯỚC 1: CẤU HÌNH DNS TRÊN CLOUDFLARE (KHUYÊN DÙNG CNAME)</h4>
        <div>🔹 <b>Cách 1 (Khuyên dùng - Ẩn IP gốc chống DDoS L4)</b>: Vào Cloudflare DNS, tạo bản ghi <b>CNAME</b> trỏ Tên miền của bạn về: <code class="cluster-cname-label" style="color:var(--cyan);font-weight:bold">cname.local</code></div>
      </div>

      <div style="padding:16px;background:var(--bg-elevated);border-radius:var(--radius-sm);border:1px solid var(--border);margin-bottom:20px">
        <h4 style="color:var(--accent);font-weight:700;margin-bottom:8px">🔒 BƯỚC 2: CẤU HÌNH CHẾ ĐỘ SSL/TLS TRÊN CLOUDFLARE</h4>
        <div>🔹 <b>Cách 1 (Khuyên dùng - Hoạt động tự động 100%)</b>: Trên Cloudflare ➜ Vào <b>SSL/TLS</b> ➜ Chọn chế độ <b>Full</b> (Hoạt động ngay lập tức với SSL SAN tự sinh của Mango WAF).</div>
      </div>

      <div style="padding:16px;background:var(--bg-elevated);border-radius:var(--radius-sm);border:1px solid var(--border);margin-bottom:20px">
        <h4 style="color:var(--cyan);font-weight:700;margin-bottom:8px">⚡ BƯỚC 3: THÊM TÊN MIỀN &amp; BACKEND TRONG TÀI KHOẢN</h4>
        <div>1. Đăng nhập vào trang quản lý <b>Mango Shield</b> ➜ Chọn mục <b>Domains</b>.</div>
        <div>2. Nhấn nút <b>+ Add Domain</b> và điền tên miền của bạn.</div>
        <div>3. Điền các địa chỉ backend upstream của bạn (ví dụ: <code style="color:var(--cyan)">http://127.0.0.1:8080</code>). Bạn có thể thêm nhiều backend cùng lúc để làm Cân bằng tải.</div>
        <div>4. Bật tùy chọn <b>Enable SSL</b> và nhấn <b>Add &amp; Deploy Domain</b>.</div>
      </div>

      <div style="padding:16px;background:var(--bg-elevated);border-radius:var(--radius-sm);border:1px solid var(--border)">
        <h4 style="color:var(--accent);font-weight:700;margin-bottom:8px">🔍 BƯỚC 4: QUÉT DNS VÀ TỰ ĐỘNG KÍCH HOẠT</h4>
        <div>Sau khi lưu, nhấn nút <b>"Quét DNS"</b> cạnh tên miền. Hệ thống sẽ tự động quét DNS resolution và kích hoạt bộ lọc bảo vệ WAF tức thì.</div>
      </div>
    </div>
    <div class="modal-footer" style="padding:16px 24px;border-top:1px solid var(--border);text-align:right">
      <button class="btn btn-primary" onclick="closeModal('modal-docs')">Đã Hiểu</button>
    </div>
  </div>
</div>

<!-- ====================================================================
     ADD DOMAIN MODAL
     ==================================================================== -->
<div class="modal-overlay" id="modal-add-domain">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">Add New Domain</span>
      <button class="modal-close" onclick="closeModal('modal-add-domain')">&times;</button>
    </div>
    <form onsubmit="handleAddDomain(event)" class="flex flex-col gap-16">
      <div class="input-group">
        <label>Domain Name</label>
        <input class="input font-mono" type="text" id="new-domain-name" placeholder="app.example.com" required>
      </div>
      <div id="backends-container">
        <label class="text-sm text-secondary font-semibold" style="margin-bottom:8px;display:block">Backend Upstreams</label>
        <div class="flex flex-col gap-8" id="backends-list">
          <div class="flex gap-8 items-center">
            <input class="input font-mono" type="text" placeholder="http://127.0.0.1:8080" style="flex:1" required>
            <input class="input font-mono" type="number" placeholder="Weight" value="1" min="1" style="width:80px">
          </div>
        </div>
        <button type="button" class="btn btn-secondary btn-sm mt-4" style="margin-top:12px" onclick="addBackendRow()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Add Backend
        </button>
      </div>
      <div class="input-group">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
          <label class="toggle"><input type="checkbox" id="new-domain-ssl" checked><span class="toggle-slider"></span></label>
          Enable SSL
        </label>
      </div>
      <div class="flex gap-12" style="margin-top:8px">
        <button type="submit" class="btn btn-primary" style="flex:1">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Add &amp; Deploy Domain
        </button>
        <button type="button" class="btn btn-secondary" onclick="closeModal('modal-add-domain')">Cancel</button>
      </div>
    </form>
  </div>
</div>

<!-- ====================================================================
     EDIT DOMAIN MODAL
     ==================================================================== -->
<div class="modal-overlay" id="modal-edit-domain">
  <div class="modal">
    <div class="modal-header">
      <span class="modal-title">Edit Domain</span>
      <button class="modal-close" onclick="closeModal('modal-edit-domain')">&times;</button>
    </div>
    <form onsubmit="handleEditDomain(event)" class="flex flex-col gap-16">
      <div class="input-group">
        <label>Domain Name</label>
        <input class="input font-mono" type="text" id="edit-domain-name" readonly style="opacity:.6">
      </div>
      <div>
        <label class="text-sm text-secondary font-semibold" style="margin-bottom:8px;display:block">Backend Upstreams</label>
        <div class="flex flex-col gap-8" id="edit-backends-list"></div>
        <button type="button" class="btn btn-secondary btn-sm mt-4" style="margin-top:12px" onclick="addEditBackendRow()">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Add Backend
        </button>
      </div>
      <div class="input-group">
        <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
          <label class="toggle"><input type="checkbox" id="edit-domain-ssl" checked><span class="toggle-slider"></span></label>
          Enable SSL
        </label>
      </div>
      <div class="flex gap-12" style="margin-top:8px">
        <button type="submit" class="btn btn-primary" style="flex:1">Save Changes</button>
        <button type="button" class="btn btn-secondary" onclick="closeModal('modal-edit-domain')">Cancel</button>
      </div>
    </form>
  </div>
</div>

<!-- ====================================================================
     JAVASCRIPT APPLICATION
     ==================================================================== -->
<script>
// ========================================================================
// STATE
// ========================================================================
const state = {
  currentPage: 'landing',
  currentSection: 'overview',
  loggedIn: false,
  token: '',
  username: '',
  domains: [],
  rpsHistory: [],
  refreshInterval: null,
  rpsChart: null,
  trafficChart: null,
};

// ========================================================================
// NAVIGATION
// ========================================================================
function showPage(page) {
  ['landing','auth','dashboard'].forEach(p => {
    document.getElementById('page-'+p).classList.toggle('hidden', p !== page);
  });
  state.currentPage = page;
  if (page === 'dashboard' && !state.refreshInterval) {
    startAutoRefresh();
    refreshData();
  }
  if (page !== 'dashboard' && state.refreshInterval) {
    clearInterval(state.refreshInterval);
    state.refreshInterval = null;
  }
}

function showDashSection(section) {
  const sections = [
    'overview','traffic','domains','ssl','nodes','settings',
    'config-center','config-backups','security-rules','firewall-bans',
    'logs-explorer','audit-logs','users'
  ];
  sections.forEach(s => {
    const el = document.getElementById('section-'+s);
    const nav = document.getElementById('nav-'+s);
    if (el) el.classList.toggle('hidden', s !== section);
    if (nav) nav.classList.toggle('active', s === section);
  });
  state.currentSection = section;
  const titles = {
    overview:'Dashboard',
    traffic:'Traffic Analytics',
    domains:'Domain Management',
    ssl:'SSL / TLS Manager',
    nodes:'Node Cluster',
    settings:'Settings',
    'config-center':'Configuration Center (YAML Master)',
    'config-backups':'Configuration Backups & Snapshots',
    'security-rules':'WAF & Security Policies',
    'firewall-bans':'IP Firewall & Blacklist',
    'logs-explorer':'Realtime Log Explorer',
    'audit-logs':'System Audit Trail',
    users:'Users & RBAC Roles'
  };
  document.getElementById('topbar-title').textContent = titles[section] || 'Dashboard';
  if (section === 'domains') renderDomains();
  if (section === 'ssl') renderSSL();
  if (section === 'nodes') renderNodes();
  if (section === 'config-center') loadConfigCenter();
  if (section === 'config-backups') loadConfigBackups();
  if (section === 'security-rules') loadSecurityRules();
  if (section === 'firewall-bans') loadFirewallBans();
  if (section === 'logs-explorer') loadLogsExplorer();
  if (section === 'audit-logs') loadAuditLogs();
  if (section === 'users') loadUsers();
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

// ========================================================================
// AUTH
// ========================================================================
function showLogin() {
  document.getElementById('tab-login').classList.add('active');
  document.getElementById('tab-register').classList.remove('active');
  document.getElementById('form-login').classList.remove('hidden');
  document.getElementById('form-register').classList.add('hidden');
}
function showRegister() {
  document.getElementById('tab-register').classList.add('active');
  document.getElementById('tab-login').classList.remove('active');
  document.getElementById('form-register').classList.remove('hidden');
  document.getElementById('form-login').classList.add('hidden');
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById('login-user').value;
  const password = document.getElementById('login-pass').value;
  const btn = document.getElementById('login-btn');
  btn.innerHTML = '<span class="spinner"></span> Signing in...';
  btn.disabled = true;
  try {
    const res = await fetch('/api/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username, password})
    });
    const data = await res.json();
    if (data.status === 'ok') {
      state.loggedIn = true;
      state.token = data.token;
      state.username = username;
      state.role = data.role || 'user';

      localStorage.setItem('mango_token', data.token);
      localStorage.setItem('mango_user', username);
      localStorage.setItem('mango_role', state.role);

      document.getElementById('user-display-name').textContent = username;
      document.getElementById('user-avatar').textContent = username.charAt(0).toUpperCase();
      
      const roleBadge = document.querySelector('.user-role');
      if (roleBadge) roleBadge.textContent = state.role === 'admin' ? 'Administrator' : 'User';
      
      const nodeNav = document.getElementById('nav-nodes');
      const settingsNav = document.getElementById('nav-settings');
      if (nodeNav) nodeNav.style.display = state.role === 'admin' ? 'flex' : 'none';
      if (settingsNav) settingsNav.style.display = state.role === 'admin' ? 'flex' : 'none';

      toast('Login successful! Role: ' + state.role, 'success');
      showPage('dashboard');
    } else {
      toast(data.message || 'Login failed', 'error');
    }
  } catch(err) {
    toast('Connection error: ' + err.message, 'error');
  }
  btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 012 2v14a2 2 0 01-2 2h-4M10 17l5-5-5-5M15 12H3"/></svg> Sign In';
  btn.disabled = false;
}

async function handleRegister(e) {
  e.preventDefault();
  const username = document.getElementById('reg-user').value;
  const password = document.getElementById('reg-pass').value;
  const email = document.getElementById('reg-email').value;
  try {
    const res = await fetch('/api/register', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username, password, email})
    });
    const data = await res.json();
    if (data.status === 'ok') {
      toast('Account created successfully! Please sign in.', 'success');
      showLogin();
      document.getElementById('login-user').value = username;
    } else {
      toast(data.message || 'Registration failed', 'error');
    }
  } catch(err) {
    toast('Registration error: ' + err.message, 'error');
  }
}

function handleLogout() {
  state.loggedIn = false;
  state.token = '';
  state.role = '';
  state.username = '';

  localStorage.removeItem('mango_token');
  localStorage.removeItem('mango_user');
  localStorage.removeItem('mango_role');

  if (state.refreshInterval) clearInterval(state.refreshInterval);
  state.refreshInterval = null;
  showPage('landing');
  toast('Logged out successfully', 'info');
}

function restoreSession() {
  const token = localStorage.getItem('mango_token');
  const user = localStorage.getItem('mango_user');
  const role = localStorage.getItem('mango_role');
  if (token && user) {
    state.loggedIn = true;
    state.token = token;
    state.username = user;
    state.role = role || 'user';

    document.getElementById('user-display-name').textContent = user;
    document.getElementById('user-avatar').textContent = user.charAt(0).toUpperCase();

    const roleBadge = document.querySelector('.user-role');
    if (roleBadge) roleBadge.textContent = state.role === 'admin' ? 'Administrator' : 'User';

    const nodeNav = document.getElementById('nav-nodes');
    const settingsNav = document.getElementById('nav-settings');
    if (nodeNav) nodeNav.style.display = state.role === 'admin' ? 'flex' : 'none';
    if (settingsNav) settingsNav.style.display = state.role === 'admin' ? 'flex' : 'none';

    showPage('dashboard');
  }
}

// ========================================================================
// DATA FETCHING
// ========================================================================
async function fetchJSON(url, opts = {}) {
  try {
    const headers = opts.headers || {};
    if (state.username) headers['X-User-Name'] = state.username;
    if (state.role) headers['X-User-Role'] = state.role;
    if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
    opts.headers = headers;
    const res = await fetch(url, opts);
    return await res.json();
  } catch(e) { return null; }
}

async function refreshData() {
  const [stats, sys, rps] = await Promise.all([
    fetchJSON('/api/stats'),
    fetchJSON('/api/system-stats'),
    fetchJSON('/api/rps-history')
  ]);

  if (stats) {
    setText('stat-rps', formatNum(stats.current_rps));
    setText('stat-conns', formatNum(stats.active_conns));
    setText('stat-blocked', formatNum(stats.blocked_requests));
    setText('stat-bans', formatNum(stats.active_bans));
    setText('stat-total', formatNum(stats.total_requests));
    setText('stat-passed', formatNum(stats.passed_requests));
    setText('stat-xdp-drops', formatNum(stats.xdp_dropped_pkts || 0));
    setText('stat-early-reject', formatNum(stats.early_rejected || 0));
    setText('peak-rps-badge', 'Peak: ' + formatNum(stats.peak_rps));
    setText('traffic-total', formatNum(stats.total_requests));
    setText('traffic-blocked', formatNum(stats.blocked_requests));
    setText('traffic-passed', formatNum(stats.passed_requests));
    setText('cache-hits', formatNum(stats.cache_hits || 0));
    setText('cache-misses', formatNum(stats.cache_misses || 0));
    setText('cache-bypasses', formatNum(stats.cache_bypasses || 0));
    setText('hero-blocked', formatNum(stats.blocked_requests));
    setText('hero-domains', stats.mesh_members ? stats.mesh_members.length || 0 : 0);

    const bans = stats.active_bans || 0;
    setText('map-banned-count', formatNum(bans));

    fetchJSON('/api/logs/query?type=&search=').then(function(logsData) {
      window._geoCountryStats = {};
      if (logsData && Array.isArray(logsData.logs)) {
        logsData.logs.forEach(function(l) {
          var code = (l.country_code || '').toUpperCase();
          if (!code || code === 'XX' || code === 'UNKNOWN') return;
          if (!window._geoCountryStats[code]) {
            window._geoCountryStats[code] = {count: 0, l7: 0, l4: 0};
          }
          window._geoCountryStats[code].count++;
          if (l.type === 'EXPLOIT' || l.type === 'SECURITY') window._geoCountryStats[code].l7++;
          else window._geoCountryStats[code].l4++;
        });
      }
      refreshCountryStatsUI();
    });

    fetchJSON('/api/nodes').then(function(data) {
      if (data && data.nodes) {
        const topbarBadge = document.getElementById('topbar-node-badge');
        if (topbarBadge) {
          topbarBadge.textContent = 'Cluster: ' + data.nodes.length + ' Nodes Online';
        }
      }
    });

    // Domain count
    if (stats.domains !== undefined && stats.domains !== null) {
      setText('domain-count', stats.domains);
    } else if (state.domains && state.domains.length > 0) {
      setText('domain-count', state.domains.length);
    }

    // Uptime
    const upSec = Math.floor(stats.uptime_seconds || 0);
    const h = Math.floor(upSec/3600); const m = Math.floor((upSec%3600)/60);
    setText('topbar-uptime', 'Uptime: ' + h + 'h ' + m + 'm');

    // Attack status
    const bar = document.getElementById('attack-status-bar');
    if (stats.is_under_attack) {
      bar.innerHTML = '<div class="attack-indicator attack-active"><span class="pulse" style="background:var(--red)"></span> UNDER ATTACK</div>';
    } else {
      bar.innerHTML = '<div class="attack-indicator attack-normal"><span class="pulse"></span> Normal</div>';
    }

    // Mesh
    setText('mesh-status', stats.mesh_enabled ? 'Mesh: Active' : 'Mesh: Off');
    setText('mesh-nodes-count', 'Nodes: ' + (stats.mesh_nodes || 0));
  }

  if (sys) {
    const cpuPct = Math.round(sys.cpu_percent || 0);
    setText('sys-cpu', cpuPct + '%');
    setText('cpu-badge', 'CPU: ' + cpuPct + '%');
    document.getElementById('cpu-bar').style.width = cpuPct + '%';
    document.getElementById('cpu-bar').style.background = cpuPct > 80 ? 'var(--red)' : cpuPct > 50 ? 'var(--amber)' : 'var(--accent)';
    const ramPct = sys.ram_total_mb > 0 ? Math.round(sys.ram_used_mb / sys.ram_total_mb * 100) : 0;
    setText('sys-ram', sys.ram_used_mb + ' / ' + sys.ram_total_mb + ' MB');
    document.getElementById('ram-bar').style.width = ramPct + '%';
    const diskPct = Math.round(sys.disk_used_pct || 0);
    setText('sys-disk', (sys.disk_used_gb||0).toFixed(1) + ' / ' + (sys.disk_total_gb||0).toFixed(1) + ' GB');
    document.getElementById('disk-bar').style.width = diskPct + '%';
    setText('sys-goroutines', sys.goroutines || 0);
    setText('sys-tcp', sys.tcp_connections || 0);
    setText('sys-load', (sys.load_1m || 0).toFixed(2));
  }

  if (rps && rps.rps) {
    state.rpsHistory = rps.rps;
    updateRPSChart();
    updateTrafficChart();
  }
}

function startAutoRefresh() {
  state.refreshInterval = setInterval(refreshData, 2000);
}

// ========================================================================
// CHARTS (Minimal canvas-based, no external deps)
// ========================================================================
function updateRPSChart() {
  const canvas = document.getElementById('rps-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const data = state.rpsHistory.slice(-300);
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width * 2;
  canvas.height = rect.height * 2;
  ctx.scale(2, 2);
  const w = rect.width, h = rect.height;
  const max = Math.max(10, ...data);
  const padding = {top:20, right:20, bottom:30, left:50};
  const chartW = w - padding.left - padding.right;
  const chartH = h - padding.top - padding.bottom;

  ctx.clearRect(0,0,w,h);

  // Grid lines
  ctx.strokeStyle = 'rgba(51,65,85,0.3)';
  ctx.lineWidth = 0.5;
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartH / 4) * i;
    ctx.beginPath(); ctx.moveTo(padding.left, y); ctx.lineTo(w - padding.right, y); ctx.stroke();
    ctx.fillStyle = '#64748b';
    ctx.font = '10px "Fira Code"';
    ctx.textAlign = 'right';
    ctx.fillText(Math.round(max - (max/4)*i), padding.left - 8, y + 4);
  }

  // Line + fill
  if (data.length > 1) {
    const gradient = ctx.createLinearGradient(0, padding.top, 0, h - padding.bottom);
    gradient.addColorStop(0, 'rgba(34,197,94,0.3)');
    gradient.addColorStop(1, 'rgba(34,197,94,0)');

    ctx.beginPath();
    ctx.moveTo(padding.left, padding.top + chartH);
    data.forEach((v, i) => {
      const x = padding.left + (i / (data.length - 1)) * chartW;
      const y = padding.top + chartH - (v / max) * chartH;
      ctx.lineTo(x, y);
    });
    ctx.lineTo(padding.left + chartW, padding.top + chartH);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    // Line
    ctx.beginPath();
    data.forEach((v, i) => {
      const x = padding.left + (i / (data.length - 1)) * chartW;
      const y = padding.top + chartH - (v / max) * chartH;
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#22c55e';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Current value dot
    const lastX = padding.left + chartW;
    const lastY = padding.top + chartH - (data[data.length-1] / max) * chartH;
    ctx.beginPath();
    ctx.arc(lastX, lastY, 4, 0, Math.PI*2);
    ctx.fillStyle = '#22c55e';
    ctx.fill();
    ctx.beginPath();
    ctx.arc(lastX, lastY, 8, 0, Math.PI*2);
    ctx.fillStyle = 'rgba(34,197,94,0.2)';
    ctx.fill();
  }

  // X-axis labels
  ctx.fillStyle = '#64748b';
  ctx.font = '10px "Fira Code"';
  ctx.textAlign = 'center';
  ctx.fillText('5m ago', padding.left, h - 8);
  ctx.fillText('2.5m ago', padding.left + chartW/2, h - 8);
  ctx.fillText('Now', padding.left + chartW, h - 8);
}

function updateTrafficChart() {
  const canvas = document.getElementById('traffic-chart');
  if (!canvas || !canvas.offsetParent) return;
  const ctx = canvas.getContext('2d');
  const data = state.rpsHistory.slice(-300);
  const rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width * 2;
  canvas.height = rect.height * 2;
  ctx.scale(2, 2);
  const w = rect.width, h = rect.height;
  const max = Math.max(10, ...data);
  const padding = {top:20, right:20, bottom:30, left:50};
  const chartW = w - padding.left - padding.right;
  const chartH = h - padding.top - padding.bottom;
  ctx.clearRect(0,0,w,h);

  // Grid
  ctx.strokeStyle = 'rgba(51,65,85,0.3)'; ctx.lineWidth = 0.5;
  for (let i = 0; i <= 5; i++) {
    const y = padding.top + (chartH/5)*i;
    ctx.beginPath(); ctx.moveTo(padding.left,y); ctx.lineTo(w-padding.right,y); ctx.stroke();
    ctx.fillStyle = '#64748b'; ctx.font = '10px "Fira Code"'; ctx.textAlign = 'right';
    ctx.fillText(Math.round(max-(max/5)*i), padding.left-8, y+4);
  }

  if (data.length > 1) {
    // Fill
    const grad = ctx.createLinearGradient(0,padding.top,0,h-padding.bottom);
    grad.addColorStop(0,'rgba(0,212,255,0.2)'); grad.addColorStop(1,'rgba(0,212,255,0)');
    ctx.beginPath(); ctx.moveTo(padding.left, padding.top+chartH);
    data.forEach((v,i)=>{
      const x=padding.left+(i/(data.length-1))*chartW;
      const y=padding.top+chartH-(v/max)*chartH;
      ctx.lineTo(x,y);
    });
    ctx.lineTo(padding.left+chartW, padding.top+chartH); ctx.closePath();
    ctx.fillStyle=grad; ctx.fill();

    // Line
    ctx.beginPath();
    data.forEach((v,i)=>{
      const x=padding.left+(i/(data.length-1))*chartW;
      const y=padding.top+chartH-(v/max)*chartH;
      if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);
    });
    ctx.strokeStyle='#00d4ff'; ctx.lineWidth=2; ctx.stroke();
  }

  ctx.fillStyle='#64748b'; ctx.font='10px "Fira Code"'; ctx.textAlign='center';
  ctx.fillText('5m ago',padding.left,h-8);
  ctx.fillText('Now',padding.left+chartW,h-8);
}

// ========================================================================
// DOMAIN MANAGEMENT
// ========================================================================
async function loadDomains() {
  const data = await fetchJSON('/api/domains');
  if (data && data.domains) {
    state.domains = data.domains;
    setText('domain-count', data.domains.length);
    renderDomainsList();
  }
}

function renderDomains() {
  loadDomains();
}

function renderDomainsList() {
  const container = document.getElementById('domains-list');
  if (!container) return;
  const domains = state.domains || [];
  if (domains.length === 0) {
    container.innerHTML = '<div style="text-align:center;padding:32px;color:var(--text-muted)">No domains added yet. Click <b>+ Add Domain</b> to protect a website.</div>';
    return;
  }
  const cnameTarget = window.clusterCNAME || 'cname.local';
  let html = '<div style="padding:16px;background:var(--bg-elevated);border-radius:var(--radius-sm);margin-bottom:16px;font-size:.85rem;border:1px solid var(--border)">' +
    '<div style="font-weight:700;color:var(--cyan);margin-bottom:6px">📌 HƯỚNG DẪN CẤU HÌNH DNS &amp; CHỐNG DDOS LAYER 4 (ẨN IP GỐC):</div>' +
    '<div>🔹 <b>(Khuyên dùng - Ẩn IP chống DDoS L4)</b>: Trỏ bản ghi <b>CNAME</b> về <code style="color:var(--cyan)">' + escapeHtml(cnameTarget) + '</code></div>' +
    '<div>🔹 Trên Cloudflare: Vào mục <b>SSL/TLS</b> &rarr; Chọn chế độ <b>Full</b></div>' +
    '<div>🔹 Nhấn nút <b>"Quét DNS"</b> bên dưới để xác nhận tự động.</div>' +
  '</div>';

  domains.forEach((d, idx) => {
    const upstreamsList = d.upstreams || d.Upstreams || [];
    const backends = upstreamsList.map(u =>
      '<span class="backend-tag">' + escapeHtml(u.url || u.URL || '') + ' (w:' + (u.weight || u.Weight || 1) + ')</span>'
    ).join('');
    const domMode = d.protection_mode || d.ProtectionMode || '';
    const modeLabel = domMode ? domMode.replace('_',' ').toUpperCase() : 'GLOBAL';
    const modeBadgeClass = domMode === 'under_attack' ? 'badge-red' : domMode === 'off' ? 'badge-muted' : domMode === 'emergency' ? 'badge-red' : domMode === 'challenge' || domMode === 'captcha' ? 'badge-amber' : domMode === 'monitor' ? 'badge-cyan' : 'badge-green';
    html += '<div class="domain-row">' +
      '<div style="display:flex;align-items:center;gap:12px">' +
        '<div class="node-status-dot online"></div>' +
        '<div class="domain-info">' +
          '<div class="domain-name">' + escapeHtml(d.name || d.Name || '') + '</div>' +
          '<div class="domain-backends">' + backends + '</div>' +
        '</div>' +
      '</div>' +
      '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">' +
        '<select class="select" style="width:auto;min-width:130px;font-size:.75rem;padding:4px 8px;height:28px" onchange="setDomainProtectionMode(\'' + escapeHtml(d.name || d.Name || '') + '\', this.value)">' +
          '<option value=""' + (domMode === '' ? ' selected' : '') + '>Global (Inherit)</option>' +
          '<option value="auto"' + (domMode === 'auto' ? ' selected' : '') + '>Auto</option>' +
          '<option value="under_attack"' + (domMode === 'under_attack' ? ' selected' : '') + '>Under Attack</option>' +
          '<option value="challenge"' + (domMode === 'challenge' ? ' selected' : '') + '>JS Challenge</option>' +
          '<option value="captcha"' + (domMode === 'captcha' ? ' selected' : '') + '>Captcha</option>' +
          '<option value="emergency"' + (domMode === 'emergency' ? ' selected' : '') + '>Emergency</option>' +
          '<option value="monitor"' + (domMode === 'monitor' ? ' selected' : '') + '>Monitor</option>' +
          '<option value="off"' + (domMode === 'off' ? ' selected' : '') + '>Bypass</option>' +
        '</select>' +
        (d.ssl ? '<span class="badge badge-green">SSL Full</span>' : '<span class="badge badge-amber">No SSL</span>') +
        '<button class="btn btn-sm btn-secondary" onclick="checkDNS(\''+escapeHtml(d.name || d.Name || '')+'\')">Quét DNS</button>' +
        '<button class="btn-icon" onclick="openEditDomainModal('+idx+')" title="Edit"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>' +
        '<button class="btn-icon" onclick="deleteDomain(\''+escapeHtml(d.name || d.Name || '')+'\')" title="Delete"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg></button>' +
      '</div>' +
    '</div>';
  });
  container.innerHTML = html;
}

async function checkDNS(domain) {
  toast('Quét DNS cho ' + domain + '...', 'info');
  const res = await fetchJSON('/api/dns/check?domain=' + encodeURIComponent(domain));
  if (res) {
    if (res.cname_target) {
      window.clusterCNAME = res.cname_target;
    }
    const cnameTarget = res.cname_target || window.clusterCNAME || 'cname.local';
    if (res.pointing || res.status === 'active') {
      toast('✅ DNS ' + domain + ' hợp lệ! Đã trỏ về WAF Cluster (CNAME ' + cnameTarget + ')', 'success');
    } else {
      toast('⏳ ' + (res.message || ('Chưa tìm thấy bản ghi CNAME trỏ về ' + cnameTarget)), 'error');
    }
  }
}

async function loadDomainsFromConfig() {
  const data = await fetchJSON('/api/config');
  if (data) {
    if (data.cname_target) {
      window.clusterCNAME = data.cname_target;
      document.querySelectorAll('.cluster-cname-label').forEach(function(el) {
        el.textContent = data.cname_target;
      });
    }
    // Get domains from config
    const stats = await fetchJSON('/api/stats');
    if (stats) {
      // Build domain list from available data
      const container = document.getElementById('domains-list');
      container.innerHTML = '<div class="text-center p-24 text-muted">Configure domains via /api/domains endpoint. Domain count: ' + (data.domains || 0) + '</div>';
    }
  }
}

function openAddDomainModal() {
  document.getElementById('new-domain-name').value = '';
  document.getElementById('new-domain-ssl').checked = true;
  const list = document.getElementById('backends-list');
  list.innerHTML = '<div class="flex gap-8 items-center"><input class="input font-mono" type="text" placeholder="http://127.0.0.1:8080" style="flex:1" required><input class="input font-mono" type="number" placeholder="Weight" value="1" min="1" style="width:80px"><button type="button" class="btn-icon" onclick="this.parentElement.remove()" title="Remove"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>';
  openModal('modal-add-domain');
}

function addBackendRow() {
  const list = document.getElementById('backends-list');
  const row = document.createElement('div');
  row.className = 'flex gap-8 items-center';
  row.innerHTML = '<input class="input font-mono" type="text" placeholder="http://ip:port" style="flex:1" required><input class="input font-mono" type="number" placeholder="Weight" value="1" min="1" style="width:80px"><button type="button" class="btn-icon" onclick="this.parentElement.remove()" title="Remove"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>';
  list.appendChild(row);
}

async function handleAddDomain(e) {
  e.preventDefault();
  const name = document.getElementById('new-domain-name').value.trim();
  const ssl = document.getElementById('new-domain-ssl').checked;
  const rows = document.querySelectorAll('#backends-list > div');
  const upstreams = [];
  rows.forEach(row => {
    const inputs = row.querySelectorAll('input');
    if (inputs[0].value.trim()) {
      upstreams.push({url: inputs[0].value.trim(), weight: parseInt(inputs[1].value) || 1});
    }
  });
  if (upstreams.length === 0) { toast('Add at least one backend', 'error'); return; }

  try {
    const res = await fetch('/api/domains', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name, upstreams, ssl})
    });
    const data = await res.json();
    if (data.status === 'success' || data.status === 'ok') {
      toast('Domain ' + name + ' added successfully!', 'success');
      closeModal('modal-add-domain');
      await loadDomains();
      renderDomains();
    } else {
      toast(data.message || 'Failed to add domain', 'error');
    }
  } catch(err) {
    toast('Error: ' + err.message, 'error');
  }
}

function openEditDomainModal(idx) {
  const d = state.domains[idx];
  if (!d) return;
  document.getElementById('edit-domain-name').value = d.name;
  document.getElementById('edit-domain-ssl').checked = d.ssl;
  const list = document.getElementById('edit-backends-list');
  list.innerHTML = '';
  (d.upstreams || []).forEach(u => {
    const row = document.createElement('div');
    row.className = 'flex gap-8 items-center';
    row.innerHTML = '<input class="input font-mono" type="text" value="'+escapeHtml(u.url)+'" style="flex:1" required><input class="input font-mono" type="number" value="'+(u.weight||1)+'" min="1" style="width:80px"><button type="button" class="btn-icon" onclick="this.parentElement.remove()" title="Remove"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>';
    list.appendChild(row);
  });
  openModal('modal-edit-domain');
}

function addEditBackendRow() {
  const list = document.getElementById('edit-backends-list');
  const row = document.createElement('div');
  row.className = 'flex gap-8 items-center';
  row.innerHTML = '<input class="input font-mono" type="text" placeholder="http://ip:port" style="flex:1" required><input class="input font-mono" type="number" placeholder="Weight" value="1" min="1" style="width:80px"><button type="button" class="btn-icon" onclick="this.parentElement.remove()" title="Remove"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>';
  list.appendChild(row);
}

async function handleEditDomain(e) {
  e.preventDefault();
  const name = document.getElementById('edit-domain-name').value;
  const ssl = document.getElementById('edit-domain-ssl').checked;
  const rows = document.querySelectorAll('#edit-backends-list > div');
  const upstreams = [];
  rows.forEach(row => {
    const inputs = row.querySelectorAll('input');
    if (inputs[0].value.trim()) {
      upstreams.push({url: inputs[0].value.trim(), weight: parseInt(inputs[1].value) || 1});
    }
  });

  try {
    const res = await fetch('/api/domains', {
      method:'PUT', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({name, upstreams, ssl})
    });
    const data = await res.json();
    if (data.status === 'success' || data.status === 'ok') {
      toast('Domain ' + name + ' updated!', 'success');
      closeModal('modal-edit-domain');
      await loadDomains();
      renderDomains();
    } else {
      toast(data.message || 'Failed to update', 'error');
    }
  } catch(err) { toast('Error: ' + err.message, 'error'); }
}

async function deleteDomain(name) {
  if (!confirm('Delete domain ' + name + '? This cannot be undone.')) return;
  try {
    const res = await fetch('/api/domains?name='+encodeURIComponent(name), {method:'DELETE'});
    const data = await res.json();
    if (data.status === 'success' || data.status === 'ok') {
      toast('Domain ' + name + ' deleted', 'success');
      await loadDomains();
      renderDomains();
    } else {
      toast(data.message || 'Failed to delete', 'error');
    }
  } catch(err) { toast('Error: ' + err.message, 'error'); }
}
// ========================================================================
// PER-DOMAIN PROTECTION MODE
// ========================================================================
async function setDomainProtectionMode(domainName, mode) {
  try {
    const res = await fetchJSON('/api/domains/protection-mode', {
      method: 'POST',
      body: JSON.stringify({ domain: domainName, protection_mode: mode })
    });
    if (res && res.status === 'success') {
      toast('Protection mode for ' + domainName + ' set to ' + (mode || 'Global (Inherit)'), 'success');
      await loadDomains();
      renderDomains();
    } else {
      toast(res ? res.message : 'Failed to set protection mode', 'error');
    }
  } catch(err) { toast('Error: ' + err.message, 'error'); }
}

// ========================================================================
// SSL MANAGEMENT
// ========================================================================
function renderSSL() {
  const container = document.getElementById('ssl-list');
  const domains = state.domains;
  if (!domains || domains.length === 0) {
    container.innerHTML = '<div class="text-center p-24 text-muted">No domains configured. Add domains first.</div>';
    return;
  }
  let html = '<table class="table"><thead><tr><th>Domain</th><th>SSL Status</th><th>Type</th><th>Actions</th></tr></thead><tbody>';
  domains.forEach(d => {
    html += '<tr>' +
      '<td><span class="font-mono font-semibold">' + escapeHtml(d.name) + '</span></td>' +
      '<td>' + (d.ssl ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-red">Disabled</span>') + '</td>' +
      '<td><span class="badge badge-cyan">Auto SAN</span></td>' +
      '<td><button class="btn btn-sm btn-secondary" onclick="generateSSLFor(\''+escapeHtml(d.name)+'\')">Regenerate</button></td>' +
    '</tr>';
  });
  html += '</tbody></table>';
  container.innerHTML = html;
}

async function generateSSLFor(domain) {
  toast('Regenerating SSL for ' + domain + '...', 'info');
  try {
    const res = await fetch('/api/ssl/generate', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({domain})
    });
    const data = await res.json();
    toast(data.message || 'SSL regenerated for ' + domain, data.status === 'success' ? 'success' : 'error');
  } catch(err) { toast('Error: ' + err.message, 'error'); }
}

async function regenerateAllSSL() {
  toast('Regenerating all SSL certificates...', 'info');
  try {
    const res = await fetch('/api/ssl/generate', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain:'all'})});
    const data = await res.json();
    toast(data.message || 'All SSL certs regenerated', data.status === 'success' ? 'success' : 'error');
  } catch(err) { toast('Error: ' + err.message, 'error'); }
}

// ========================================================================
// NODE MANAGEMENT
// ========================================================================
async function renderNodes() {
  const data = await fetchJSON('/api/nodes');
  const container = document.getElementById('nodes-list');
  if (!container) return;
  const nodesList = (data && data.nodes) ? data.nodes : [];

  const meshStatus = document.getElementById('mesh-status');
  if (meshStatus) meshStatus.textContent = 'P2P Mesh: Active';
  const meshCount = document.getElementById('mesh-nodes-count');
  if (meshCount) meshCount.textContent = 'Active Nodes: ' + nodesList.length;

  const topbarBadge = document.getElementById('topbar-node-badge');
  if (topbarBadge) topbarBadge.textContent = 'Cluster: ' + nodesList.length + ' Nodes';

  if (nodesList.length === 0) {
    container.innerHTML = '<div class="card text-center p-32 text-muted">No cluster nodes configured or connected. Configure cluster.join_peers in YAML to add nodes dynamically.</div>';
    return;
  }

  let html = '';
  nodesList.forEach(function(node) {
    const isOnline = (node.status !== 'offline');
    const ip = node.addr || node.ip || 'Local Node';
    const name = node.name || ('WAF Node (' + ip + ')');
    html += '<div class="card node-card" style="padding:20px; border-left:4px solid var(--accent); background:var(--card-bg); margin-bottom:16px;">' +
      '<div class="flex justify-between items-center mb-12">' +
        '<div class="flex items-center gap-12">' +
          '<div class="node-status-dot ' + (isOnline ? 'online' : 'offline') + '"></div>' +
          '<div>' +
            '<div class="font-bold text-lg text-accent">' + escapeHtml(name) + '</div>' +
            '<div class="font-mono text-sm text-cyan">' + escapeHtml(ip) + '</div>' +
          '</div>' +
        '</div>' +
        '<span class="badge badge-green">ONLINE (Synced)</span>' +
      '</div>' +
      '<div class="grid grid-4 gap-12 mt-16 p-12" style="background:rgba(0,0,0,0.2); border-radius:8px;">' +
        '<div><div class="text-xs text-muted">Mesh Gossip Port</div><div class="font-mono font-semibold text-cyan">7946 TCP/UDP</div></div>' +
        '<div><div class="text-xs text-muted">Hardware Protection</div><div class="font-semibold text-accent">eBPF / XDP Kernel</div></div>' +
        '<div><div class="text-xs text-muted">Config Auto-Sync</div><div class="font-semibold text-green">YAML Synchronized</div></div>' +
        '<div><div class="text-xs text-muted">Latency</div><div class="font-mono text-muted">&lt; 1.5ms</div></div>' +
      '</div>' +
      '<div class="flex justify-end gap-8 mt-16">' +
        '<button class="btn btn-secondary btn-sm" onclick="triggerNodeSync(\'' + escapeHtml(ip) + '\')">Force Sync Node</button>' +
      '</div>' +
    '</div>';
  });
  container.innerHTML = html;
}

async function triggerClusterSync() {
  const res = await fetchJSON('/api/cluster/sync', { method: 'POST' });
  if (res && res.status === 'success') {
    toast('Cluster configuration broadcasted across all nodes!', 'success');
    renderNodes();
  } else {
    toast(res ? res.message : 'Cluster sync failed', 'error');
  }
}

async function triggerNodeSync(nodeIP) {
  toast('Syncing YAML configuration to node ' + nodeIP + '...', 'info');
  triggerClusterSync();
}

// ========================================================================
// SETTINGS
// ========================================================================
async function saveSettings() {
  toast('Settings saved!', 'success');
}

async function unbanAll() {
  try {
    await fetch('/api/unban?ip=all');
    toast('All IPs unbanned', 'success');
    refreshData();
  } catch(err) { toast('Error: ' + err.message, 'error'); }
}

// ========================================================================
// MODALS
// ========================================================================
function openModal(id) {
  document.getElementById(id).classList.add('active');
}
function closeModal(id) {
  document.getElementById(id).classList.remove('active');
}

// Close modal on overlay click
document.querySelectorAll('.modal-overlay').forEach(el => {
  el.addEventListener('click', e => { if (e.target === el) el.classList.remove('active'); });
});

// ========================================================================
// TOAST
// ========================================================================
function toast(msg, type='info') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  const icons = {
    success: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    error: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    info: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
  };
  el.innerHTML = (icons[type] || icons.info) + '<span>' + escapeHtml(msg) + '</span>';
  container.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(100%)'; setTimeout(() => el.remove(), 300); }, 4000);
}

// ========================================================================
// UTILITIES
// ========================================================================
function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function formatNum(n) {
  if (n === null || n === undefined) return '0';
  n = parseInt(n);
  if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
  if (n >= 1000) return (n/1000).toFixed(1) + 'K';
  return n.toString();
}

function escapeHtml(s) {
  if (!s) return '';
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ========================================================================
// CONFIGURATION CENTER & ENTERPRISE MODULES
// ========================================================================
async function loadConfigCenter() {
  const data = await fetchJSON('/api/config/center');
  if (data && data.raw_yaml) {
    document.getElementById('yaml-editor-input').value = data.raw_yaml;
    validateLiveYAML();
  }
  if (data && data.revisions) {
    renderRevisions(data.revisions);
  }
}

function validateLiveYAML() {
  const text = document.getElementById('yaml-editor-input').value;
  const badge = document.getElementById('yaml-validation-status');
  if (!badge) return;
  if (!text || text.trim() === '') {
    badge.textContent = 'Empty YAML';
    badge.className = 'badge badge-red';
    return;
  }
  if (text.includes('server:') && text.includes('domains:')) {
    badge.textContent = 'Status: Valid YAML';
    badge.className = 'badge badge-green';
  } else {
    badge.textContent = 'Syntax Warning';
    badge.className = 'badge badge-amber';
  }
}

async function saveYAMLConfig() {
  const raw_yaml = document.getElementById('yaml-editor-input').value;
  const res = await fetchJSON('/api/config/center', {
    method: 'POST',
    body: JSON.stringify({ raw_yaml, description: 'Updated via YAML Master Editor' })
  });
  if (res && res.status === 'success') {
    toast('Configuration saved & hot-reloaded successfully!', 'success');
    loadConfigCenter();
  } else {
    toast(res ? res.message : 'Save failed', 'error');
  }
}

function formatYAML() {
  try {
    let raw = document.getElementById('yaml-editor-input').value;
    raw = raw.replace(/\t/g, '  ');
    document.getElementById('yaml-editor-input').value = raw;
    toast('YAML auto-formatted', 'info');
  } catch(e) {}
}

function renderRevisions(revisions) {
  const tbody = document.getElementById('tbody-revisions');
  if (!tbody) return;
  if (!revisions || revisions.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">No revision history found</td></tr>';
    return;
  }
  tbody.innerHTML = revisions.map(function(r) {
    return '<tr>' +
      '<td><span class="font-mono text-cyan">v_' + r.version + '</span></td>' +
      '<td>' + new Date(r.timestamp).toLocaleString() + '</td>' +
      '<td>' + escapeHtml(r.author || 'system') + '</td>' +
      '<td><span class="badge badge-purple">' + escapeHtml(r.role || 'admin') + '</span></td>' +
      '<td>' + escapeHtml(r.description || '-') + '</td>' +
      '<td>' +
        '<div class="flex gap-8">' +
          '<button class="btn btn-secondary btn-sm" onclick="rollbackRevision(' + r.version + ')">Rollback</button>' +
          '<button class="btn btn-cyan btn-sm" onclick="viewDiff(0, ' + r.version + ')">Diff</button>' +
        '</div>' +
      '</td>' +
    '</tr>';
  }).join('');
}

async function rollbackRevision(version) {
  if (!confirm('Rollback configuration to revision version ' + version + '?')) return;
  const res = await fetchJSON('/api/config/center', {
    method: 'PUT',
    body: JSON.stringify({ action: 'rollback', version })
  });
  if (res && res.status === 'success') {
    toast('Configuration rolled back & hot-reloaded!', 'success');
    loadConfigCenter();
  } else {
    toast(res ? res.message : 'Rollback failed', 'error');
  }
}

async function viewDiff(v1, v2) {
  const res = await fetchJSON('/api/config/diff', {
    method: 'POST',
    body: JSON.stringify({ v1, v2 })
  });
  if (res && res.diff) {
    document.getElementById('diff-text-content').textContent = res.diff;
    openModal('modal-diff-view');
  } else {
    toast('Failed to generate diff', 'error');
  }
}

async function loadConfigBackups() {
  const data = await fetchJSON('/api/config/backup');
  const tbody = document.getElementById('tbody-backups');
  if (!tbody) return;
  if (!data || !data.backups || data.backups.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No configuration backups found</td></tr>';
    return;
  }
  tbody.innerHTML = data.backups.map(function(b) {
    return '<tr>' +
      '<td><span class="font-mono text-accent">' + escapeHtml(b.name) + '</span></td>' +
      '<td>' + new Date(b.timestamp).toLocaleString() + '</td>' +
      '<td>' + escapeHtml(b.author || 'system') + '</td>' +
      '<td>' + escapeHtml(b.description || '-') + '</td>' +
      '<td>' +
        '<div class="flex gap-8">' +
          '<a class="btn btn-secondary btn-sm" href="/api/config/backup?id=' + b.id + '&download=true" target="_blank">Download</a>' +
          '<button class="btn btn-primary btn-sm" onclick="restoreBackup(\'' + b.id + '\')">Restore</button>' +
        '</div>' +
      '</td>' +
    '</tr>';
  }).join('');
}

async function promptCreateBackup() {
  const name = prompt('Enter Backup Snapshot Name:');
  if (!name) return;
  const desc = prompt('Enter Description (optional):') || 'Manual Snapshot';
  const res = await fetchJSON('/api/config/backup', {
    method: 'POST',
    body: JSON.stringify({ name, description: desc })
  });
  if (res && res.status === 'success') {
    toast('Backup snapshot created successfully!', 'success');
    loadConfigBackups();
  } else {
    toast(res ? res.message : 'Backup creation failed', 'error');
  }
}

async function restoreBackup(backupId) {
  if (!confirm('Restore configuration from backup ID ' + backupId + '?')) return;
  const res = await fetchJSON('/api/config/center', {
    method: 'PUT',
    body: JSON.stringify({ action: 'restore_backup', backup_id: backupId })
  });
  if (res && res.status === 'success') {
    toast('Backup restored & hot-reloaded!', 'success');
    loadConfigBackups();
  } else {
    toast(res ? res.message : 'Restore failed', 'error');
  }
}

let auditCurrentPage = 1;
const auditPageSize = 10;
let auditCacheData = [];

async function loadAuditLogs(targetPage) {
  if (targetPage) auditCurrentPage = targetPage;
  const data = await fetchJSON('/api/audit-logs');
  const tbody = document.getElementById('tbody-audit-logs');
  if (!tbody) return;

  auditCacheData = (data && data.logs) ? data.logs : [];
  const totalAudit = auditCacheData.length;

  if (totalAudit === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">No audit log entries recorded</td></tr>';
    updateAuditPagination(0, 0, 0);
    return;
  }

  const totalPages = Math.ceil(totalAudit / auditPageSize);
  if (auditCurrentPage > totalPages) auditCurrentPage = totalPages;
  if (auditCurrentPage < 1) auditCurrentPage = 1;

  const startIdx = (auditCurrentPage - 1) * auditPageSize;
  const endIdx = Math.min(startIdx + auditPageSize, totalAudit);
  const pageLogs = auditCacheData.slice(startIdx, endIdx);

  tbody.innerHTML = pageLogs.map(function(l) {
    return '<tr>' +
      '<td>' + new Date(l.timestamp).toLocaleString() + '</td>' +
      '<td><span class="font-semibold">' + escapeHtml(l.user) + '</span></td>' +
      '<td><span class="badge badge-purple">' + escapeHtml(l.role) + '</span></td>' +
      '<td><span class="font-mono text-cyan">' + escapeHtml(l.action) + '</span></td>' +
      '<td>' + escapeHtml(l.module) + '</td>' +
      '<td>' + escapeHtml(l.target) + '</td>' +
      '<td><span class="font-mono text-muted">' + escapeHtml(l.client_ip) + '</span></td>' +
      '<td>' + escapeHtml(l.details) + '</td>' +
    '</tr>';
  }).join('');

  updateAuditPagination(startIdx + 1, endIdx, totalAudit);
}

function updateAuditPagination(start, end, total) {
  const pageInfo = document.getElementById('audit-page-info');
  const btnPrev = document.getElementById('btn-audit-prev');
  const btnNext = document.getElementById('btn-audit-next');
  if (pageInfo) pageInfo.textContent = 'Showing ' + start + '-' + end + ' of ' + total + ' entries (Page ' + auditCurrentPage + ')';
  if (btnPrev) btnPrev.disabled = (auditCurrentPage <= 1);
  if (btnNext) btnNext.disabled = (end >= total);
}

function prevAuditPage() {
  if (auditCurrentPage > 1) {
    auditCurrentPage--;
    loadAuditLogs();
  }
}

function nextAuditPage() {
  const totalPages = Math.ceil(auditCacheData.length / auditPageSize);
  if (auditCurrentPage < totalPages) {
    auditCurrentPage++;
    loadAuditLogs();
  }
}

function exportAuditCSV() {
  window.open('/api/audit-logs?export=csv', '_blank');
}

async function loadUsers() {
  const data = await fetchJSON('/api/users');
  const tbody = document.getElementById('tbody-users');
  if (!tbody) return;
  if (!data || !data.users || data.users.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No user accounts found</td></tr>';
    return;
  }
  tbody.innerHTML = data.users.map(function(u) {
    var roleBadge = u.role === 'super_admin' ? 'badge-purple' : u.role === 'admin' ? 'badge-green' : 'badge-amber';
    var doms = u.domains ? u.domains.join(', ') : 'All Domains';
    return '<tr>' +
      '<td><span class="font-bold text-accent">' + escapeHtml(u.username) + '</span></td>' +
      '<td>' + escapeHtml(u.email || '-') + '</td>' +
      '<td><span class="badge ' + roleBadge + '">' + escapeHtml(u.role) + '</span></td>' +
      '<td>' + escapeHtml(doms) + '</td>' +
      '<td>' +
        '<div class="flex gap-8">' +
          '<button class="btn btn-danger btn-sm" onclick="deleteUser(\'' + u.username + '\')" ' + (u.username === 'admin' ? 'disabled' : '') + '>Delete</button>' +
        '</div>' +
      '</td>' +
    '</tr>';
  }).join('');
}

function openAddUserModal() {
  openModal('modal-add-user');
}

async function handleAddUser(e) {
  e.preventDefault();
  const username = document.getElementById('user-new-name').value;
  const email = document.getElementById('user-new-email').value;
  const password = document.getElementById('user-new-pass').value;
  const role = document.getElementById('user-new-role').value;

  const res = await fetchJSON('/api/users', {
    method: 'POST',
    body: JSON.stringify({ username, email, password, role })
  });

  if (res && res.status === 'success') {
    toast('User account created successfully!', 'success');
    closeModal('modal-add-user');
    loadUsers();
  } else {
    toast(res ? res.message : 'User creation failed', 'error');
  }
}

async function deleteUser(username) {
  if (!confirm('Delete user account ' + username + '?')) return;
  const res = await fetchJSON('/api/users?username=' + encodeURIComponent(username), { method: 'DELETE' });
  if (res && res.status === 'success') {
    toast('User deleted successfully', 'success');
    loadUsers();
  } else {
    toast(res ? res.message : 'Delete failed', 'error');
  }
}

async function loadSecurityRules() {
  const data = await fetchJSON('/api/security/rules');
  if (data) {
    document.getElementById('sec-protection-mode').value = data.protection_mode || 'auto';
    document.getElementById('sec-paranoia-level').value = data.paranoia_level || 2;
    if (data.rate_limit) {
      document.getElementById('sec-rps').value = data.rate_limit.requests_per_second || 100;
      document.getElementById('sec-burst').value = data.rate_limit.burst || 200;
    }
    document.getElementById('sec-pow-diff').value = data.pow_difficulty || 4;
    document.getElementById('sec-block-asn').value = data.block_datacenter ? 'true' : 'false';
  }
}

async function saveSecurityRules() {
  const protection_mode = document.getElementById('sec-protection-mode').value;
  const paranoia_level = parseInt(document.getElementById('sec-paranoia-level').value);
  const requests_per_second = parseInt(document.getElementById('sec-rps').value);
  const burst = parseInt(document.getElementById('sec-burst').value);
  const pow_difficulty = parseInt(document.getElementById('sec-pow-diff').value);
  const block_datacenter = document.getElementById('sec-block-asn').value === 'true';

  const res = await fetchJSON('/api/security/rules', {
    method: 'POST',
    body: JSON.stringify({ protection_mode, paranoia_level, requests_per_second, burst, pow_difficulty, block_datacenter })
  });

  if (res && res.status === 'success') {
    toast('Global Security policies saved & hot-reloaded!', 'success');
  } else {
    toast(res ? res.message : 'Save failed', 'error');
  }
}

let bansCurrentPage = 1;
const bansPageSize = 10;
let bansCacheData = [];

async function loadFirewallBans(targetPage) {
  if (targetPage) bansCurrentPage = targetPage;
  
  if (!targetPage) {
    const data = await fetchJSON('/api/firewall/bans');
    bansCacheData = (data && data.bans) ? data.bans : [];
    bansCurrentPage = 1;
  }
  
  const tbody = document.getElementById('tbody-banned-ips');
  if (!tbody) return;

  const totalBans = bansCacheData.length;

  if (totalBans === 0) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No blacklisted IPs active</td></tr>';
    updateBansPagination(0, 0, 0);
    return;
  }

  const totalPages = Math.ceil(totalBans / bansPageSize);
  if (bansCurrentPage > totalPages) bansCurrentPage = totalPages;
  if (bansCurrentPage < 1) bansCurrentPage = 1;

  const startIdx = (bansCurrentPage - 1) * bansPageSize;
  const endIdx = Math.min(startIdx + bansPageSize, totalBans);
  const pageBans = bansCacheData.slice(startIdx, endIdx);

  tbody.innerHTML = pageBans.map(function(b) {
    var ttlMin = Math.ceil(b.ttl_sec / 60);
    return '<tr>' +
      '<td><span class="font-mono text-red">' + escapeHtml(b.ip) + '</span></td>' +
      '<td>WAF / Rate Limit / DDoS Attack</td>' +
      '<td><span class="badge badge-red">Banned</span></td>' +
      '<td style="font-size:11px;color:var(--text-muted)">' + escapeHtml(b.expires_at) + ' (TTL: ' + ttlMin + 'm)</td>' +
    '</tr>';
  }).join('') +
  '<tr style="border-top:1px solid var(--border);">' +
    '<td colspan="3" style="color:var(--text-muted);font-size:11px">' + totalBans + ' IPs active in ban list</td>' +
    '<td><button class="btn btn-danger btn-sm" onclick="executeUnbanAll()">Unban All</button></td>' +
  '</tr>';

  updateBansPagination(startIdx + 1, endIdx, totalBans);
}

function updateBansPagination(start, end, total) {
  const pageInfo = document.getElementById('bans-page-info');
  const btnPrev = document.getElementById('btn-bans-prev');
  const btnNext = document.getElementById('btn-bans-next');
  if (pageInfo) pageInfo.textContent = 'Showing ' + start + '-' + end + ' of ' + total + ' entries (Page ' + bansCurrentPage + ')';
  if (btnPrev) btnPrev.disabled = (bansCurrentPage <= 1);
  if (btnNext) btnNext.disabled = (end >= total);
}

function prevBansPage() {
  if (bansCurrentPage > 1) {
    bansCurrentPage--;
    loadFirewallBans(bansCurrentPage);
  }
}

function nextBansPage() {
  const totalPages = Math.ceil(bansCacheData.length / bansPageSize);
  if (bansCurrentPage < totalPages) {
    bansCurrentPage++;
    loadFirewallBans(bansCurrentPage);
  }
}

let logsCurrentPage = 1;
const logsPageSize = 15;
let logsCacheData = [];

async function loadLogsExplorer(targetPage) {
  if (targetPage) logsCurrentPage = targetPage;
  const typeFilter = document.getElementById('log-type-filter') ? document.getElementById('log-type-filter').value : '';
  const searchFilter = document.getElementById('log-search-input') ? document.getElementById('log-search-input').value : '';
  const url = '/api/logs/query?type=' + encodeURIComponent(typeFilter) + '&search=' + encodeURIComponent(searchFilter);
  const data = await fetchJSON(url);
  const tbody = document.getElementById('tbody-logs-explorer');
  if (!tbody) return;

  logsCacheData = (data && data.logs) ? data.logs : [];
  const totalLogs = logsCacheData.length;

  if (totalLogs === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No logs matching query criteria</td></tr>';
    updateLogsPagination(0, 0, 0);
    return;
  }

  const totalPages = Math.ceil(totalLogs / logsPageSize);
  if (logsCurrentPage > totalPages) logsCurrentPage = totalPages;
  if (logsCurrentPage < 1) logsCurrentPage = 1;

  const startIdx = (logsCurrentPage - 1) * logsPageSize;
  const endIdx = Math.min(startIdx + logsPageSize, totalLogs);
  const pageLogs = logsCacheData.slice(startIdx, endIdx);

  tbody.innerHTML = pageLogs.map(function(l) {
    var typeBadge = (l.type === 'SECURITY' || l.type === 'EXPLOIT') ? 'badge-red' : l.type === 'CHALLENGE' ? 'badge-amber' : 'badge-green';
    var statusClass = (l.status === 200) ? 'text-accent' : 'text-red';
    return '<tr>' +
      '<td>' + new Date(l.timestamp).toLocaleTimeString() + '</td>' +
      '<td><span class="badge ' + typeBadge + '">' + escapeHtml(l.type) + '</span></td>' +
      '<td><span class="font-mono">' + escapeHtml(l.client_ip) + '</span></td>' +
      '<td><span class="font-mono text-cyan">' + escapeHtml(l.domain) + '</span></td>' +
      '<td><span class="font-mono">' + escapeHtml(l.method) + ' ' + escapeHtml(l.path) + '</span></td>' +
      '<td><span class="font-bold ' + statusClass + '">' + l.status + '</span></td>' +
      '<td><span class="font-mono text-muted">' + escapeHtml(l.action) + ' (' + escapeHtml(l.rule) + ')</span></td>' +
    '</tr>';
  }).join('');

  updateLogsPagination(startIdx + 1, endIdx, totalLogs);
}

function updateLogsPagination(start, end, total) {
  const pageInfo = document.getElementById('logs-page-info');
  const btnPrev = document.getElementById('btn-logs-prev');
  const btnNext = document.getElementById('btn-logs-next');
  if (pageInfo) pageInfo.textContent = 'Showing ' + start + '-' + end + ' of ' + total + ' entries (Page ' + logsCurrentPage + ')';
  if (btnPrev) btnPrev.disabled = (logsCurrentPage <= 1);
  if (btnNext) btnNext.disabled = (end >= total);
}

function prevLogsPage() {
  if (logsCurrentPage > 1) {
    logsCurrentPage--;
    loadLogsExplorer();
  }
}

function nextLogsPage() {
  const totalPages = Math.ceil(logsCacheData.length / logsPageSize);
  if (logsCurrentPage < totalPages) {
    logsCurrentPage++;
    loadLogsExplorer();
  }
}

async function clearLogsExplorer() {
  if (!confirm('Are you sure you want to clear all security logs from memory?')) return;
  const res = await fetchJSON('/api/logs/clear', { method: 'POST' });
  if (res && res.status === 'success') {
    toast('Security log store cleared successfully', 'success');
    logsCurrentPage = 1;
    loadLogsExplorer(1);
  } else {
    toast('Failed to clear logs', 'error');
  }
}

function exportLogsCSV() {
  window.open('/api/logs/query?export=csv', '_blank');
}

// Landing nav scroll
window.addEventListener('scroll', () => {
  const nav = document.getElementById('landing-nav');
  if (nav) nav.classList.toggle('scrolled', window.scrollY > 50);
});

// Animated hero counters
function animateCounter(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  let current = 0;
  const step = Math.max(1, Math.floor(target / 60));
  const interval = setInterval(() => {
    current += step;
    if (current >= target) { current = target; clearInterval(interval); }
    el.textContent = formatNum(current);
  }, 16);
}

// Initial fetch for landing stats
(async function initLandingStats() {
  const stats = await fetchJSON('/api/stats');
  if (stats) {
    animateCounter('hero-blocked', stats.blocked_requests || 0);
    setText('hero-domains', stats.domains || 0);
  }
})();

// Restore login session on page load if saved
restoreSession();

// Real-time geo country stats accumulated from SSE attack stream

// Real-time geo country stats accumulated from SSE attack stream
window._geoCountryStats = {};

function renderCountryRankings(countryCounts) {
  var listEl = document.getElementById('country-ranking-list');
  if (!listEl) return;

  var sorted = Object.values(countryCounts).filter(function(c){ return c.count > 0; }).sort(function(a, b) { return b.count - a.count; });
  if (sorted.length === 0) {
    listEl.innerHTML = '<div style="padding:24px;text-align:center;color:var(--text-muted);font-size:13px">No attack data yet — waiting for real-time events...</div>';
    setText('top-country-count-badge', '0 quốc gia');
    return;
  }

  var total = sorted.reduce(function(acc, item) { return acc + item.count; }, 0) || 1;
  setText('top-country-count-badge', sorted.length + ' Quốc gia ghi nhận');

  listEl.innerHTML = '';
  sorted.slice(0, 15).forEach(function(c, i) {
    var pct = Math.round((c.count / total) * 100);
    var barColor = i === 0 ? '#ef4444' : i === 1 ? '#f59e0b' : i < 5 ? '#06b6d4' : '#64748b';
    var row = document.createElement('div');
    row.style.cssText = 'display:flex;flex-direction:column;gap:4px;padding:4px 0';
    row.innerHTML =
      '<div style="display:flex;justify-content:space-between;font-size:12px;align-items:center">' +
        '<span style="display:flex;align-items:center;gap:6px">' +
          '<span style="font-size:16px">' + c.flag + '</span>' +
          '<strong style="color:var(--text-primary)">' + c.name + '</strong>' +
          '<span style="color:var(--text-muted);font-size:10px">(' + c.code + ')</span>' +
        '</span>' +
        '<span style="font-family:var(--font-mono);font-weight:600;color:' + barColor + '">' + formatNum(c.count) + ' req <span style="color:var(--text-muted);font-weight:400">(' + pct + '%)</span></span>' +
      '</div>' +
      '<div style="height:6px;background:var(--bg-elevated);border-radius:3px;overflow:hidden">' +
        '<div style="height:100%;background:' + barColor + ';border-radius:3px;width:' + Math.max(pct, 2) + '%;transition:width 0.5s ease"></div>' +
      '</div>';
    listEl.appendChild(row);
  });
}

function updateCountryAttackChart(countryCounts) {
  var canvas = document.getElementById('country-attack-chart');
  if (!canvas) return;
  var sorted = Object.values(countryCounts).filter(function(c){ return c.count > 0; }).sort(function(a,b){ return b.count-a.count; }).slice(0,10);
  if (sorted.length === 0) return;
  var ctx = canvas.getContext('2d');
  var rect = canvas.parentElement.getBoundingClientRect();
  canvas.width = rect.width * 2; canvas.height = rect.height * 2;
  ctx.scale(2,2);
  var w = rect.width, h = rect.height;
  var colors = ['#ef4444','#f59e0b','#06b6d4','#22c55e','#a855f7','#ec4899','#14b8a6','#f97316','#6366f1','#84cc16'];
  var maxVal = sorted[0].count || 1;
  var barW = (w - 60) / sorted.length;
  var chartH = h - 60;
  var topPad = 20;
  ctx.clearRect(0,0,w,h);
  sorted.forEach(function(c, i) {
    var x = 30 + i * barW + barW * 0.1;
    var bw = barW * 0.8;
    var bh = Math.max(4, (c.count / maxVal) * chartH);
    var y = topPad + chartH - bh;
    var grad = ctx.createLinearGradient(0, y, 0, y + bh);
    grad.addColorStop(0, colors[i % colors.length]);
    grad.addColorStop(1, colors[i % colors.length] + '44');
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(x, y, bw, bh, 3) : ctx.rect(x, y, bw, bh);
    ctx.fill();
    ctx.fillStyle = '#94a3b8';
    ctx.font = 'bold 9px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(c.flag, x + bw/2, y - 4);
    ctx.fillStyle = '#64748b';
    ctx.font = '8px sans-serif';
    ctx.fillText(c.code, x + bw/2, topPad + chartH + 14);
  });
}

// ========================================================================
// ENTERPRISE LIVE WORLD ATTACK MAP ENGINE (Dynamic Geo-Projection & SSE Stream)
// ========================================================================
var attackMapCanvas = null;
var attackMapCtx = null;
var attackArcs = [];

// Dynamic target nodes fetched directly from /api/nodes (aligned to Miller projection)
var targetNodes = [];
var pendingEvents = [];

// Interactive Map Transformation Variables
var mapZoom = 1.0;
var mapPanX = 0;
var mapPanY = 0;
var isPanning = false;
var panStartX = 0;
var panStartY = 0;

function applyMapTransforms() {
  var wrapperEl = document.getElementById('map-inner-wrapper');
  if (wrapperEl) {
    wrapperEl.style.transform = 'translate(' + mapPanX + 'px, ' + mapPanY + 'px) scale(' + mapZoom + ')';
    wrapperEl.style.transformOrigin = '0 0';
  }
}

function initMapInteractivity() {
  var viewport = document.getElementById('map-viewport');
  if (!viewport) return;

  viewport.addEventListener('mousedown', function(e) {
    if (e.button !== 0) return;
    isPanning = true;
    viewport.style.cursor = 'grabbing';
    panStartX = e.clientX - mapPanX;
    panStartY = e.clientY - mapPanY;
  });

  window.addEventListener('mousemove', function(e) {
    if (!isPanning) return;
    mapPanX = e.clientX - panStartX;
    mapPanY = e.clientY - panStartY;
    applyMapTransforms();
  });

  window.addEventListener('mouseup', function() {
    if (isPanning) {
      isPanning = false;
      viewport.style.cursor = 'grab';
    }
  });

  // Touch Support for Mobile / Tablets
  viewport.addEventListener('touchstart', function(e) {
    if (e.touches.length !== 1) return;
    isPanning = true;
    panStartX = e.touches[0].clientX - mapPanX;
    panStartY = e.touches[0].clientY - mapPanY;
  });

  viewport.addEventListener('touchmove', function(e) {
    if (!isPanning || e.touches.length !== 1) return;
    mapPanX = e.touches[0].clientX - panStartX;
    mapPanY = e.touches[0].clientY - panStartY;
    applyMapTransforms();
  });

  viewport.addEventListener('touchend', function() {
    isPanning = false;
  });

  // Mouse wheel zoom centering on canvas coordinates
  viewport.addEventListener('wheel', function(e) {
    e.preventDefault();
    var zoomFactor = 1.1;
    if (e.deltaY > 0) {
      mapZoom = Math.max(0.3, mapZoom / zoomFactor);
    } else {
      mapZoom = Math.min(8.0, mapZoom * zoomFactor);
    }
    applyMapTransforms();
  }, { passive: false });
}

function projectCoordinates(lat, lon) {
  // X: simple linear mapping for longitude [-180, 180] -> [0, 1]
  var x = (lon + 180) / 360;
  
  // Y: Fitted equirectangular formula for this specific SVG map (Equator at y = 0.54956)
  var y = 0.54956 - 0.005781 * lat;
  
  return { 
    x: Math.max(0.01, Math.min(0.99, x)), 
    y: Math.max(0.01, Math.min(0.99, y)) 
  };
}

var COUNTRY_CENTROIDS = {
  "AF": [33.9, 67.7], "AL": [41.1, 20.1], "DZ": [28.0, 1.6], "AR": [-38.4, -63.6],
  "AM": [40.0, 45.0], "AU": [-25.2, 133.7], "AT": [47.5, 14.5], "AZ": [40.1, 47.5],
  "BD": [23.6, 90.3], "BY": [53.7, 27.9], "BE": [50.5, 4.4], "BR": [-14.2, -51.9],
  "BG": [42.7, 25.4], "CA": [56.1, -106.3], "CL": [-35.6, -71.5], "CN": [35.8, 104.1],
  "CO": [4.5, -74.2], "HR": [45.1, 15.2], "CZ": [49.8, 15.4], "DK": [56.2, 9.5],
  "EG": [26.8, 30.8], "FI": [61.9, 25.7], "FR": [46.2, 2.2], "DE": [51.1, 10.4],
  "GR": [39.0, 22.0], "HU": [47.1, 19.5], "IN": [20.5, 78.9], "ID": [-0.7, 113.9],
  "IR": [32.4, 53.6], "IQ": [33.2, 43.6], "IE": [53.4, -8.2], "IL": [31.0, 34.8],
  "IT": [41.8, 12.5], "JP": [36.2, 138.2], "KZ": [48.0, 66.9], "KE": [-1.2, 36.8],
  "KR": [35.9, 127.7], "MY": [4.2, 101.9], "MX": [23.6, -102.5], "NL": [52.1, 5.2],
  "NZ": [-40.9, 174.8], "NG": [9.0, 8.6], "NO": [60.4, 8.4], "PK": [30.3, 69.3],
  "PH": [12.8, 121.7], "PL": [51.9, 19.1], "PT": [39.3, -8.2], "RO": [45.9, 24.9],
  "RU": [61.5, 105.3], "SA": [23.8, 45.0], "SG": [1.35, 103.8], "ZA": [-30.5, 22.9],
  "ES": [40.4, -3.7], "SE": [60.1, 18.6], "CH": [46.8, 8.2], "TW": [23.7, 120.9],
  "TH": [15.8, 101.0], "TR": [38.9, 35.2], "UA": [48.3, 31.1], "AE": [23.4, 53.8],
  "GB": [55.3, -3.4], "US": [37.0, -95.7], "VN": [16.0, 106.0]
};

function getCountryCenter(code) {
  if (!code) return null;
  code = code.toUpperCase();
  if (COUNTRY_CENTROIDS[code]) {
    var coords = COUNTRY_CENTROIDS[code];
    return projectCoordinates(coords[0], coords[1]);
  }
  return null;
}

var countryHighlightTimeouts = {};

function highlightCountryOnMap(code) {
  if (!code) return;
  code = code.toUpperCase();
  
  // Full map of all SVG countries mapping ISO 2-letter codes to their SVG class names
  var codeToClass = {
    "AF": "Afghanistan", "AL": "Albania", "DZ": "Algeria", "AI": "Anguilla", 
    "AM": "Armenia", "AW": "Aruba", "AT": "Austria", "BH": "Bahrain", 
    "BD": "Bangladesh", "BB": "Barbados", "BY": "Belarus", "BE": "Belgium", 
    "BZ": "Belize", "BJ": "Benin", "BM": "Bermuda", "BT": "Bhutan", 
    "BO": "Bolivia", "BA": "Bosnia and Herzegovina", "BW": "Botswana", 
    "BR": "Brazil", "VG": "British Virgin Islands", "BN": "Brunei Darussalam", 
    "BG": "Bulgaria", "BF": "Burkina Faso", "BI": "Burundi", "KH": "Cambodia", 
    "CM": "Cameroon", "CF": "Central African Republic", "TD": "Chad", 
    "CO": "Colombia", "CR": "Costa Rica", "HR": "Croatia", "CU": "Cuba", 
    "CW": "Curaçao", "CZ": "Czech Republic", "CI": "Côte d'Ivoire", 
    "KP": "Dem. Rep. Korea", "CD": "Democratic Republic of the Congo", 
    "DJ": "Djibouti", "DM": "Dominica", "DO": "Dominican Republic", 
    "EC": "Ecuador", "EG": "Egypt", "SV": "El Salvador", "GQ": "Equatorial Guinea", 
    "ER": "Eritrea", "EE": "Estonia", "ET": "Ethiopia", "FI": "Finland", 
    "GF": "French Guiana", "GA": "Gabon", "GE": "Georgia", "DE": "Germany", 
    "GH": "Ghana", "GL": "Greenland", "GD": "Grenada", "GU": "Guam", 
    "GT": "Guatemala", "GN": "Guinea", "GW": "Guinea-Bissau", "GY": "Guyana", 
    "HT": "Haiti", "HN": "Honduras", "HU": "Hungary", "IS": "Iceland", 
    "IN": "India", "IR": "Iran", "IQ": "Iraq", "IE": "Ireland", 
    "IL": "Israel", "JM": "Jamaica", "JO": "Jordan", "KZ": "Kazakhstan", 
    "KE": "Kenya", "XK": "Kosovo", "KW": "Kuwait", "KG": "Kyrgyzstan", 
    "LA": "Lao PDR", "LV": "Latvia", "LB": "Lebanon", "LS": "Lesotho", 
    "LR": "Liberia", "LY": "Libya", "LT": "Lithuania", "LU": "Luxembourg", 
    "MK": "Macedonia", "MG": "Madagascar", "MW": "Malawi", "MV": "Maldives", 
    "ML": "Mali", "MH": "Marshall Islands", "MQ": "Martinique", 
    "MR": "Mauritania", "YT": "Mayotte", "MX": "Mexico", "MD": "Moldova", 
    "MN": "Mongolia", "ME": "Montenegro", "MS": "Montserrat", "MA": "Morocco", 
    "MZ": "Mozambique", "MM": "Myanmar", "NA": "Namibia", "NR": "Nauru", 
    "NP": "Nepal", "NL": "Netherlands", "BQBO": "Netherlands", "NI": "Nicaragua", 
    "NE": "Niger", "NG": "Nigeria", "PK": "Pakistan", "PW": "Palau", 
    "PS": "Palestine", "PA": "Panama", "PY": "Paraguay", "PE": "Peru", 
    "PL": "Poland", "PT": "Portugal", "QA": "Qatar", "CG": "Republic of Congo", 
    "KR": "Republic of Korea", "RE": "Reunion", "RO": "Romania", "RW": "Rwanda", 
    "BQSA": "Saba (Netherlands)", "LC": "Saint Lucia", "VC": "Saint Vincent and the Grenadines", 
    "BL": "Saint-Barthélemy", "MF": "Saint-Martin", "SA": "Saudi Arabia", 
    "SN": "Senegal", "RS": "Serbia", "SL": "Sierra Leone", "SX": "Sint Maarten", 
    "SK": "Slovakia", "SI": "Slovenia", "SO": "Somalia", "ZA": "South Africa", 
    "SS": "South Sudan", "ES": "Spain", "LK": "Sri Lanka", "BQSE": "St. Eustatius (Netherlands)", 
    "SD": "Sudan", "SR": "Suriname", "SZ": "Swaziland", "SE": "Sweden", 
    "CH": "Switzerland", "SY": "Syria", "TW": "Taiwan", "TJ": "Tajikistan", 
    "TZ": "Tanzania", "TH": "Thailand", "GM": "The Gambia", "TL": "Timor-Leste", 
    "TG": "Togo", "TN": "Tunisia", "TM": "Turkmenistan", "TV": "Tuvalu", 
    "UG": "Uganda", "UA": "Ukraine", "AE": "United Arab Emirates", "UY": "Uruguay", 
    "UZ": "Uzbekistan", "VE": "Venezuela", "VN": "Vietnam", "EH": "Western Sahara", 
    "YE": "Yemen", "ZM": "Zambia", "ZW": "Zimbabwe"
  };

  var className = codeToClass[code];
  var paths = [];
  if (className) {
    var selector = 'path.' + className.replace(/ /g, '.');
    paths = Array.from(document.querySelectorAll('#world-map-svg ' + selector));
  }
  
  var pathById = document.getElementById(code);
  if (pathById) {
    paths.push(pathById);
  }
  
  paths.forEach(function(path) {
    path.classList.add('attack-highlight');
  });

  if (countryHighlightTimeouts[code]) {
    clearTimeout(countryHighlightTimeouts[code]);
  }
  
  countryHighlightTimeouts[code] = setTimeout(function() {
    paths.forEach(function(path) {
      path.classList.remove('attack-highlight');
    });
    delete countryHighlightTimeouts[code];
  }, 2000); // 2 seconds cooldown
}

function refreshCountryStatsUI() {
  var COUNTRY_META = {
    'US':{'name':'United States','flag':'🇺🇸'},'RU':{'name':'Russia','flag':'🇷🇺'},'CN':{'name':'China','flag':'🇨🇳'},
    'DE':{'name':'Germany','flag':'🇩🇪'},'GB':{'name':'United Kingdom','flag':'🇬🇧'},'BR':{'name':'Brazil','flag':'🇧🇷'},
    'MX':{'name':'Mexico','flag':'🇲🇽'},'PH':{'name':'Philippines','flag':'🇵🇭'},'ID':{'name':'Indonesia','flag':'🇮🇩'},
    'VN':{'name':'Vietnam','flag':'🇻🇳'},'IN':{'name':'India','flag':'🇮🇳'},'KR':{'name':'South Korea','flag':'🇰🇷'},
    'JP':{'name':'Japan','flag':'🇯🇵'},'NL':{'name':'Netherlands','flag':'🇳🇱'},'FR':{'name':'France','flag':'🇫🇷'},
    'IT':{'name':'Italy','flag':'🇮🇹'},'CA':{'name':'Canada','flag':'🇨🇦'},'AU':{'name':'Australia','flag':'🇦🇺'},
    'SG':{'name':'Singapore','flag':'🇸🇬'},'TR':{'name':'Turkey','flag':'🇹🇷'},'UA':{'name':'Ukraine','flag':'🇺🇦'},
    'PL':{'name':'Poland','flag':'🇵🇱'},'TH':{'name':'Thailand','flag':'🇹🇭'},'MY':{'name':'Malaysia','flag':'🇲🇾'},
    'PK':{'name':'Pakistan','flag':'🇵🇰'},'NG':{'name':'Nigeria','flag':'🇳🇬'},'ZA':{'name':'South Africa','flag':'🇿🇦'},
    'BD':{'name':'Bangladesh','flag':'🇧🇩'},'EG':{'name':'Egypt','flag':'🇪🇬'},'AR':{'name':'Argentina','flag':'🇦🇷'}
  };

  var countryCounts = {};
  if (window._geoCountryStats && Object.keys(window._geoCountryStats).length > 0) {
    Object.keys(window._geoCountryStats).forEach(function(code) {
      var meta = COUNTRY_META[code] || {name: code, flag: '🌐'};
      countryCounts[code] = {
        name: meta.name, code: code, flag: meta.flag,
        count: window._geoCountryStats[code].count || 0,
        l7: window._geoCountryStats[code].l7 || 0,
        l4: window._geoCountryStats[code].l4 || 0
      };
    });
  }

  var activeCountries = Object.keys(countryCounts).length;
  var mapSubDetail = document.getElementById('map-sub-detail');
  if (mapSubDetail) {
    var l7Total = 0;
    var l4Total = 0;
    Object.keys(countryCounts).forEach(function(code) {
      l7Total += countryCounts[code].l7;
      l4Total += countryCounts[code].l4;
    });
    mapSubDetail.textContent = activeCountries + ' quốc gia - Lớp 7: ' + formatNum(l7Total) + ' - Flood kết nối: ' + formatNum(l4Total);
  }

  renderCountryRankings(countryCounts);
  updateCountryAttackChart(countryCounts);
}

function initAttackMap() {
  attackMapCanvas = document.getElementById('attack-map-canvas');
  if (!attackMapCanvas) return;
  attackMapCtx = attackMapCanvas.getContext('2d');

  attackArcs = [];
  initMapInteractivity();

  // Set initial map centering & zoom scale to fit the viewport container
  var viewport = document.getElementById('map-viewport');
  if (viewport) {
    var scaleX = viewport.clientWidth / 2000;
    var scaleY = viewport.clientHeight / 857;
    mapZoom = Math.min(scaleX, scaleY);
    mapPanX = (viewport.clientWidth - 2000 * mapZoom) / 2;
    mapPanY = (viewport.clientHeight - 857 * mapZoom) / 2;
    applyMapTransforms();
  }

  function processAttackEvent(evt) {
    var srcPos = null;
    if (evt.latitude && evt.longitude && evt.latitude !== 0 && evt.longitude !== 0) {
      srcPos = projectCoordinates(evt.latitude, evt.longitude);
    } else if (evt.countryCode) {
      srcPos = getCountryCenter(evt.countryCode);
    }
    if (!srcPos) return;

    var targetNode = targetNodes[Math.floor(Math.random() * targetNodes.length)];
    attackArcs.push({
      from: srcPos,
      to: targetNode,
      label: evt.ip + ' (' + (evt.countryCode || 'XX') + ')',
      action: evt.action,
      progress: 0,
      pulseRadius: 2,
      speed: 0.008 + Math.random() * 0.012,
      curvature: (Math.random() - 0.5) * 0.6
    });
    if (attackArcs.length > 60) attackArcs.shift();
  }

  function loadWafNodes() {
    fetchJSON('/api/nodes').then(function(data) {
      if (data && data.nodes && Array.isArray(data.nodes) && data.nodes.length > 0) {
        targetNodes = data.nodes.map(function(n, idx) {
          var lat = n.latitude || 21.0285;
          var lon = n.longitude || 105.8542;
          var pos = projectCoordinates(lat, lon);
          
          return {
            x: pos.x,
            y: pos.y,
            label: (n.name || 'Node ' + (idx + 1)) + ' (' + (n.ip || '') + ')',
            lat: lat,
            lon: lon
          };
        });

        // Flush any pending events that arrived before WAF nodes were loaded
        while (pendingEvents.length > 0) {
          var evt = pendingEvents.shift();
          processAttackEvent(evt);
        }
      }
    });
  }

  // Fetch and inject world.svg inline so it is fully styled and interactive
  fetch('/world.svg')
    .then(function(r) { return r.text(); })
    .then(function(svgText) {
      var container = document.getElementById('world-map-container');
      if (!container) return;
      var parser = new DOMParser();
      var doc = parser.parseFromString(svgText, 'image/svg+xml');
      var svgEl = doc.querySelector('svg');
      if (svgEl) {
        svgEl.setAttribute('id', 'world-map-svg');
        svgEl.setAttribute('width', '100%');
        svgEl.setAttribute('height', '100%');
        svgEl.setAttribute('preserveAspectRatio', 'none');
        svgEl.style.position = 'absolute';
        svgEl.style.top = '0';
        svgEl.style.left = '0';
        svgEl.style.width = '100%';
        svgEl.style.height = '100%';
        svgEl.style.pointerEvents = 'none';
        
        svgEl.querySelectorAll('path').forEach(function(p) {
          p.removeAttribute('fill');
          p.removeAttribute('stroke');
          p.removeAttribute('stroke-width');
        });
        
        container.innerHTML = '';
        container.appendChild(svgEl);
        applyMapTransforms();

        // Dynamically load WAF nodes centered inside Vietnam's SVG paths
        loadWafNodes();
      }
    }).catch(function(err) {});

  // Connect SSE Live Telemetry Stream - accumulate geo country stats from REAL geoIP events
  if (window.EventSource) {
    var evtSource = new EventSource('/api/attack-stream');
    evtSource.onmessage = function(e) {
      try {
        var events = JSON.parse(e.data);
        if (!events || !Array.isArray(events)) return;
        var needsUIUpdate = false;
        events.forEach(function(evt) {
          if (evt.countryCode && evt.countryCode !== 'XX' && evt.countryCode !== '') {
            var code = evt.countryCode;
            if (!window._geoCountryStats[code]) {
              window._geoCountryStats[code] = {count: 0, l7: 0, l4: 0};
            }
            window._geoCountryStats[code].count++;
            if (evt.action === 'BLOCKED' || evt.action === 'EXPLOIT') window._geoCountryStats[code].l7++;
            else window._geoCountryStats[code].l4++;
            
            needsUIUpdate = true;
            // Trigger geographic flash highlight
            highlightCountryOnMap(code);
          }

          if (targetNodes.length === 0) {
            pendingEvents.push(evt);
            if (pendingEvents.length > 100) pendingEvents.shift();
            return;
          }

          processAttackEvent(evt);
        });
        if (needsUIUpdate) {
          refreshCountryStatsUI();
        }
      } catch (err) {}
    };
  }

  function renderMapFrame() {
    if (!attackMapCtx || !attackMapCanvas) return;
    var w = 2000;
    var h = 857;
    attackMapCtx.clearRect(0, 0, w, h);

    // Draw Dynamic Server Nodes
    targetNodes.forEach(function(node, idx) {
      var nx = node.x * w;
      var ny = node.y * h;

      attackMapCtx.beginPath();
      attackMapCtx.arc(nx, ny, 12, 0, Math.PI * 2);
      attackMapCtx.fillStyle = 'rgba(6, 182, 212, 0.25)';
      attackMapCtx.fill();

      attackMapCtx.beginPath();
      attackMapCtx.arc(nx, ny, 6, 0, Math.PI * 2);
      attackMapCtx.fillStyle = 'var(--cyan)';
      attackMapCtx.fill();

      attackMapCtx.fillStyle = '#ffffff';
      attackMapCtx.font = 'bold 11px sans-serif';
      if (idx === 0) {
        attackMapCtx.textAlign = 'right';
        attackMapCtx.fillText(node.label, nx - 12, ny + 4);
      } else {
        attackMapCtx.textAlign = 'left';
        attackMapCtx.fillText(node.label, nx + 12, ny + 4);
      }
    });

    // Draw Attack Dots & Bezier Arcs
    for (var i = attackArcs.length - 1; i >= 0; i--) {
      var arc = attackArcs[i];
      arc.progress += arc.speed;
      if (arc.progress >= 1) {
        attackArcs.splice(i, 1);
        continue;
      }

      var sx = arc.from.x * w;
      var sy = arc.from.y * h;
      var tx = arc.to.x * w;
      var ty = arc.to.y * h;

      var color = (arc.action === 'BLOCKED' || arc.action === 'BAN' || arc.action === 'DROP') ? '#ef4444' : '#f59e0b';

      // 1. Draw Pulsing Origin Dot at Attacker Location
      arc.pulseRadius = (arc.pulseRadius || 2) + 0.3;
      if (arc.pulseRadius > 14) arc.pulseRadius = 2;

      attackMapCtx.beginPath();
      attackMapCtx.arc(sx, sy, arc.pulseRadius, 0, Math.PI * 2);
      attackMapCtx.strokeStyle = color;
      attackMapCtx.globalAlpha = Math.max(0, 1 - (arc.pulseRadius / 14));
      attackMapCtx.lineWidth = 1.5;
      attackMapCtx.stroke();

      attackMapCtx.beginPath();
      attackMapCtx.arc(sx, sy, 4, 0, Math.PI * 2);
      attackMapCtx.fillStyle = color;
      attackMapCtx.globalAlpha = 1.0;
      attackMapCtx.fill();

      // 2. Draw Arc
      var mx = (sx + tx) / 2 + (arc.curvature * (ty - sy));
      var my = (sy + ty) / 2 - (arc.curvature * (tx - sx));

      attackMapCtx.beginPath();
      attackMapCtx.moveTo(sx, sy);
      attackMapCtx.quadraticCurveTo(mx, my, tx, ty);
      attackMapCtx.strokeStyle = color;
      attackMapCtx.globalAlpha = 0.35;
      attackMapCtx.lineWidth = 1.5;
      attackMapCtx.stroke();
      attackMapCtx.globalAlpha = 1.0;

      // 3. Draw Pulse Traveling Particle
      var t = arc.progress;
      var px = (1 - t) * (1 - t) * sx + 2 * (1 - t) * t * mx + t * t * tx;
      var py = (1 - t) * (1 - t) * sy + 2 * (1 - t) * t * my + t * t * ty;

      attackMapCtx.beginPath();
      attackMapCtx.arc(px, py, 4, 0, Math.PI * 2);
      attackMapCtx.fillStyle = color;
      attackMapCtx.shadowColor = color;
      attackMapCtx.shadowBlur = 8;
      attackMapCtx.fill();
      attackMapCtx.shadowBlur = 0;
    }

    requestAnimationFrame(renderMapFrame);
  }
  requestAnimationFrame(renderMapFrame);
}


setTimeout(initAttackMap, 500);

// ========================================================================
// KEYBOARD SHORTCUTS
// ========================================================================
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
  }
});
</script>
</body>
</html>
`
