const express=require('express'),fs=require('fs'),path=require('path'),crypto=require('crypto'),bcrypt=require('bcryptjs');
const DIR=process.env.DATA_DIR||'/data',PORT=process.env.PORT||3000;fs.mkdirSync(DIR,{recursive:true});
const F={st:DIR+'/state.json',us:DIR+'/users.json',au:DIR+'/audit.log',sec:DIR+'/secret'};
const SHEETS=['assump','tx','daily','hr','roi','bank','act','vt','fz','ot','sl','fp'],ROLES=['superadmin','admin','entry','viewer'];
const rd=(f,d)=>{try{return JSON.parse(fs.readFileSync(f,'utf8'))}catch(e){return d}};
const wr=(f,o)=>{fs.writeFileSync(f+'.tmp',JSON.stringify(o));fs.renameSync(f+'.tmp',f)};
let state=rd(F.st,null),users=rd(F.us,{});
const SECRET=process.env.SESSION_SECRET||(fs.existsSync(F.sec)?fs.readFileSync(F.sec,'utf8'):(()=>{const s=crypto.randomBytes(32).toString('hex');fs.writeFileSync(F.sec,s,{mode:0o600});return s})());
if(!Object.keys(users).length&&process.env.SUPERADMIN_USER&&process.env.SUPERADMIN_PASS){users[process.env.SUPERADMIN_USER.toLowerCase()]={hash:bcrypt.hashSync(process.env.SUPERADMIN_PASS,10),role:'superadmin',active:true};wr(F.us,users);console.log('Superadmin created')}
// ---- audit: append-only, hash-chained
let last='0';try{const L=fs.readFileSync(F.au,'utf8').trim().split('\n');last=JSON.parse(L[L.length-1]).h}catch(e){}
const sha=s=>crypto.createHash('sha256').update(s).digest('hex');
function audit(u,a){const e={ts:new Date().toISOString(),user:u.name,role:u.role,...a};e.h=sha(last+JSON.stringify(e));last=e.h;fs.appendFileSync(F.au,JSON.stringify(e)+'\n')}
const auditLines=()=>fs.existsSync(F.au)?fs.readFileSync(F.au,'utf8').trim().split('\n').filter(Boolean):[];
// ---- auth
const sign=s=>crypto.createHmac('sha256',SECRET).update(s).digest('hex');
const eq=(a,b)=>a.length===b.length&&crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b));
const tok=u=>{const p=Buffer.from(JSON.stringify({u,e:Date.now()+12*36e5})).toString('base64url');return p+'.'+sign(p)};
function auth(q,r,n){const c=(q.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('sid='));
if(c){const[p,s]=c.slice(4).split('.');if(p&&s&&eq(s,sign(p))){try{const d=JSON.parse(Buffer.from(p,'base64url')),us=users[d.u];if(d.e>Date.now()&&us&&us.active){q.u={name:d.u,role:us.role};return n()}}catch(e){}}}
r.status(401).json({error:'Not signed in'})}
const ADMIN=(q,r,n)=>['admin','superadmin'].includes(q.u.role)?n():r.status(403).json({error:'Admin or superadmin only'});
const SA=(q,r,n)=>q.u.role==='superadmin'?n():r.status(403).json({error:'Superadmin only'});
const app=express();app.set('trust proxy',1);app.use(express.json({limit:'5mb'}));
app.use((q,r,n)=>{r.setHeader('X-Content-Type-Options','nosniff');r.setHeader('X-Frame-Options','DENY');r.setHeader('Cache-Control','no-store');n()});
const fails={};
app.post('/api/login',(q,r)=>{const ip=q.ip,f=fails[ip]||{n:0,t:Date.now()};if(Date.now()-f.t>9e5){f.n=0;f.t=Date.now()}
if(f.n>=5)return r.status(429).json({error:'Too many attempts. Try again in 15 minutes.'});
const n=String(q.body.username||'').toLowerCase(),u=users[n];
if(!u||!u.active||!bcrypt.compareSync(String(q.body.password||''),u.hash)){f.n++;fails[ip]=f;audit({name:n||'?',role:'-'},{sheet:'auth',action:'login_failed'});return r.status(401).json({error:'Invalid username or password'})}
r.setHeader('Set-Cookie','sid='+tok(n)+'; HttpOnly; Path=/; SameSite=Lax; Max-Age=43200'+(q.headers['x-forwarded-proto']==='https'?'; Secure':''));
audit({name:n,role:u.role},{sheet:'auth',action:'login'});r.json({ok:1})});
app.post('/api/logout',(q,r)=>{r.setHeader('Set-Cookie','sid=; Max-Age=0; Path=/');r.json({ok:1})});
app.get('/api/me',auth,(q,r)=>r.json({username:q.u.name,role:q.u.role}));
app.get('/api/state',auth,(q,r)=>r.json(state?{state}:{empty:true}));
const clean=r=>{const o={};for(const k in r)if(!k.startsWith('_')&&r[k]!==''&&r[k]!=null)o[k]=r[k];return o};
const ref=r=>String(r.name||r.doc||r.id||r.outlet||r.emp||r.offer||r.pn||r.date||'');
app.post('/api/bootstrap',auth,SA,(q,r)=>{if(state)return r.status(409).json({error:'Already initialised'});const s={},now=new Date().toISOString();
for(const k of SHEETS)s[k]=((q.body.state||{})[k]||[]).map(x=>({...clean(x),_id:String(x._id),_st:'Approved',_ap:'system (initial setup)',_at:now,_by:'system'}));
state=s;wr(F.st,s);audit(q.u,{sheet:'system',action:'bootstrap'});r.json({state:s})});
// ---- data changes: every create/update/delete is audited; any change resets the record to Pending
app.post('/api/ops',auth,(q,r)=>{const u=q.u;if(u.role==='viewer')return r.status(403).json({error:'Read-only role'});if(!state)return r.status(409).json({error:'System not initialised'});
const meta=[],now=new Date().toISOString();let err=null;
try{for(const op of q.body.ops||[]){if(!SHEETS.includes(op.sheet))throw new Error('Invalid sheet');const arr=state[op.sheet]||(state[op.sheet]=[]);
if(op.op==='upsert'){const id=String(op.row&&op.row._id||'');if(!id)throw new Error('Missing record id');const nw=clean(op.row),i=arr.findIndex(x=>x._id===id);
if(i<0){const m={_st:'Pending',_by:u.name,_ua:now};arr.push({...nw,_id:id,...m});audit(u,{sheet:op.sheet,rid:id,ref:ref(nw),action:'create',new:JSON.stringify(nw)});meta.push({sheet:op.sheet,id,m})}
else{const old=arr[i],oc=clean(old),ch=[...new Set([...Object.keys(oc),...Object.keys(nw)])].filter(k=>String(oc[k]??'')!==String(nw[k]??''));if(!ch.length)continue;
const m={_st:'Pending',_by:u.name,_ua:now,_ap:'',_at:'',_rn:''};arr[i]={...nw,_id:id,...m};
ch.forEach(k=>audit(u,{sheet:op.sheet,rid:id,ref:ref(nw)||ref(oc),action:'update',field:k,old:String(oc[k]??''),new:String(nw[k]??''),prev_status:old._st}));meta.push({sheet:op.sheet,id,m})}}
else if(op.op==='delete'){const i=arr.findIndex(x=>x._id===op.id);if(i<0)continue;const old=arr[i];
if(old._st==='Approved'&&u.role==='entry')throw new Error('Approved records can be deleted by admin or superadmin only');
arr.splice(i,1);audit(u,{sheet:op.sheet,rid:old._id,ref:ref(old),action:'delete',old:JSON.stringify(clean(old)),prev_status:old._st})}}}catch(e){err=e.message}
wr(F.st,state);err?r.status(400).json({error:err,meta}):r.json({ok:1,meta})});
// ---- approval: admin / superadmin only
app.post('/api/approve',auth,ADMIN,(q,r)=>{const{sheet,id,action,note}=q.body;if(!SHEETS.includes(sheet)||!['approve','reject'].includes(action)||(id==='*'&&action!=='approve'))return r.status(400).json({error:'Invalid request'});
const now=new Date().toISOString(),st=action==='approve'?'Approved':'Rejected',m={_st:st,_ap:q.u.name,_at:now,_rn:note||''},rows=(state[sheet]||[]).filter(x=>id==='*'?x._st==='Pending':x._id===id);
rows.forEach(x=>{audit(q.u,{sheet,rid:x._id,ref:ref(x),action,prev_status:x._st,note:note||''});Object.assign(x,m)});wr(F.st,state);r.json({ok:1,count:rows.length,m})});
app.get('/api/audit',auth,ADMIN,(q,r)=>{const L=auditLines();r.json({total:L.length,rows:L.slice(-(+q.query.limit||1000)).reverse().map(x=>JSON.parse(x))})});
app.get('/api/audit/verify',auth,ADMIN,(q,r)=>{let p='0',bad=0;const L=auditLines();L.forEach((x,i)=>{const e=JSON.parse(x),h=e.h;delete e.h;if(!bad&&sha(p+JSON.stringify(e))!==h)bad=i+1;p=h});r.json({ok:!bad,total:L.length,brokenAt:bad})});
// ---- users (superadmin)
app.get('/api/users',auth,SA,(q,r)=>r.json(Object.entries(users).map(([n,u])=>({username:n,role:u.role,active:u.active}))));
app.post('/api/users/create',auth,SA,(q,r)=>{const n=String(q.body.username||'').trim().toLowerCase(),{password,role}=q.body;
if(!/^[a-z0-9._-]{3,30}$/.test(n)||users[n]||!ROLES.includes(role)||String(password||'').length<8)return r.status(400).json({error:'Invalid input: unique username (3-30 chars), valid role, password min 8 characters'});
users[n]={hash:bcrypt.hashSync(password,10),role,active:true};wr(F.us,users);audit(q.u,{sheet:'users',action:'user_create',ref:n,new:role});r.json({ok:1})});
app.post('/api/users/update',auth,SA,(q,r)=>{const n=q.body.username,u=users[n],b=q.body;if(!u)return r.status(404).json({error:'No such user'});
if(n===q.u.name&&((b.role&&b.role!==u.role)||b.active===false))return r.status(400).json({error:'You cannot change your own role or deactivate yourself'});
if(b.password&&String(b.password).length<8)return r.status(400).json({error:'Password min 8 characters'});
if(b.role&&ROLES.includes(b.role)&&b.role!==u.role){audit(q.u,{sheet:'users',action:'role_change',ref:n,old:u.role,new:b.role});u.role=b.role}
if(typeof b.active==='boolean'&&b.active!==u.active){audit(q.u,{sheet:'users',action:b.active?'user_activate':'user_deactivate',ref:n});u.active=b.active}
if(b.password){u.hash=bcrypt.hashSync(b.password,10);audit(q.u,{sheet:'users',action:'password_reset',ref:n})}
wr(F.us,users);r.json({ok:1})});
app.use(express.static(path.join(__dirname,'public')));
app.listen(PORT,()=>console.log('MIS listening on '+PORT));
