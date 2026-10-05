const cors={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"content-type, authorization","Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS"};
const enc=new TextEncoder();
const json=(v,s=200)=>Response.json(v,{status:s,headers: cors});
async function digest(v){return crypto.subtle.digest('SHA-256',enc.encode(v));}
function hex(b){return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');}
async function auth(request,env){
  const h=request.headers.get('authorization')||''; if(!h.startsWith('Bearer ')) return null;
  const hash=hex(await digest(h.slice(7)));
  return await env.DB.prepare("SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>datetime('now') AND u.active=1").bind(hash).first();
}
async function makeToken(){
  const bytes=crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
}
async function passwordOk(password, stored){
  const parts=stored.split('$'); if(parts.length!==4) return false;
  const salt=Uint8Array.from(atob(parts[2]),c=>c.charCodeAt(0));
  const key=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:Number(parts[1]),hash:'SHA-256'},key,256);
  return btoa(String.fromCharCode(...new Uint8Array(bits)))===parts[3];
}
export default {
  async fetch(request,env){
    if(request.method==='OPTIONS') return new Response(null,{headers:cors});
    const url=new URL(request.url);
    try{
      if(url.pathname==='/api/health') return json({ok:true,database:!!env.DB});
      if(!env.DB) return json({error:'Banco D1 não configurado'},503);
      if(url.pathname==='/api/auth/login'&&request.method==='POST'){
        const b=await request.json();
        const user=await env.DB.prepare('SELECT id,username,password_hash,role FROM users WHERE username=? AND active=1').bind(String(b.username||'').trim()).first();
        if(!user||!(await passwordOk(String(b.password||''),user.password_hash))) return json({error:'Usuário ou senha inválidos'},401);
        const raw=await makeToken();
        const hash=hex(await digest(raw));
        await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,datetime('now','+7 days'))").bind(hash,user.id).run();
        return json({token:raw,user:{id:user.id,username:user.username,role:user.role}});
      }
      const user=await auth(request,env);
      if(!user) return json({error:'Não autenticado'},401);
      if(url.pathname==='/api/auth/me') return json({user});
      if(url.pathname==='/api/dashboard'&&request.method==='GET'){
        const sales=await env.DB.prepare("SELECT COALESCE(SUM(total_cents),0) total,COUNT(*) orders FROM orders WHERE status!='cancelled'").first();
        const expenses=await env.DB.prepare('SELECT COALESCE(SUM(amount_cents),0) total FROM expenses').first();
        const low=await env.DB.prepare('SELECT COUNT(*) total FROM products WHERE active=1 AND stock<=min_stock').first();
        return json({sales_cents:sales.total,orders:sales.orders,expenses_cents:expenses.total,low_stock:low.total});
      }
      if(url.pathname==='/api/products'&&request.method==='GET') return json((await env.DB.prepare('SELECT * FROM products WHERE active=1 ORDER BY name').all()).results);
      if(url.pathname==='/api/customers'&&request.method==='GET') return json((await env.DB.prepare('SELECT * FROM customers ORDER BY name').all()).results);
      if(url.pathname==='/api/orders'&&request.method==='GET') return json((await env.DB.prepare('SELECT o.*,c.name customer_name FROM orders o LEFT JOIN customers c ON c.id=o.customer_id ORDER BY o.id DESC LIMIT 500').all()).results);
      if(url.pathname==='/api/expenses'&&request.method==='GET') return json((await env.DB.prepare('SELECT * FROM expenses ORDER BY paid_at DESC,id DESC LIMIT 500').all()).results);
      return json({error:'Rota não encontrada'},404);
    }catch(e){return json({error:'Erro interno',detail:e?.message||String(e)},500)}
  }
}