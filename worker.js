const cors={"Access-Control-Allow-Origin":"*","Access-Control-Allow-Headers":"content-type, authorization","Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS"};
const enc=new TextEncoder();
const out=(x,s=200)=>Response.json(x,{status:s,headers:cors});
const hash=async s=>{const b=await crypto.subtle.digest("SHA-256",enc.encode(s));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,"0")).join("")};
const money=v=>Math.round(Number(v||0)*100);
async function init(env){
 await env.DB.batch([
  env.DB.prepare("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'operator',active INTEGER NOT NULL DEFAULT 1)"),
  env.DB.prepare("CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,category TEXT,price_cents INTEGER DEFAULT 0,cost_cents INTEGER DEFAULT 0,stock REAL DEFAULT 0,min_stock REAL DEFAULT 0,active INTEGER DEFAULT 1)"),
  env.DB.prepare("CREATE TABLE IF NOT EXISTS customers(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,phone TEXT,address TEXT,notes TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)"),
  env.DB.prepare("CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT,customer_id INTEGER,status TEXT DEFAULT 'pending',payment_method TEXT,total_cents INTEGER DEFAULT 0,delivery_fee_cents INTEGER DEFAULT 0,notes TEXT,created_by INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP)"),
  env.DB.prepare("CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY AUTOINCREMENT,order_id INTEGER,product_id INTEGER,quantity REAL,unit_price_cents INTEGER,unit_cost_cents INTEGER)"),
  env.DB.prepare("CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY AUTOINCREMENT,description TEXT,amount_cents INTEGER,category TEXT,paid_at TEXT,notes TEXT,created_by INTEGER)"),
  env.DB.prepare("CREATE TABLE IF NOT EXISTS stock_movements(id INTEGER PRIMARY KEY AUTOINCREMENT,product_id INTEGER,quantity REAL,type TEXT,reason TEXT,reference_id INTEGER,created_by INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP)"),
  env.DB.prepare("CREATE TABLE IF NOT EXISTS cash_movements(id INTEGER PRIMARY KEY AUTOINCREMENT,type TEXT,description TEXT,amount_cents INTEGER,payment_method TEXT,created_by INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP)"),
  env.DB.prepare("CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER,expires_at TEXT)")
 ]);
 if(env.ADMIN_PASSWORD&&env.CAIXA_PASSWORD){
  const n=await env.DB.prepare("SELECT COUNT(*) n FROM users").first();
  if(!n.n){await env.DB.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").bind("admin",await hash(env.ADMIN_PASSWORD),"admin").run();await env.DB.prepare("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)").bind("caixa",await hash(env.CAIXA_PASSWORD),"operator").run()}
 }
}
async function user(req,env){
 const h=req.headers.get("authorization")||"";
 if(!h.startsWith("Bearer "))return null;
 const t=await hash(h.slice(7));
 return env.DB.prepare("SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND u.active=1 AND s.expires_at>datetime('now')").bind(t).first();
}
async function login(req,env){
 const b=await req.json();const u=await env.DB.prepare("SELECT * FROM users WHERE username=? AND active=1").bind(String(b.username||"").trim()).first();
 if(!u||await hash(String(b.password||""))!==u.password_hash)return out({error:"Usuário ou senha inválidos"},401);
 const token=btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/=/g,"");
 await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,datetime('now','+7 days'))").bind(await hash(token),u.id).run();
 return out({token,user:{id:u.id,username:u.username,role:u.role}});
}
export default {async fetch(req,env){
 if(req.method==="OPTIONS")return new Response(null,{headers:cors});
 const u=new URL(req.url);
 try{
  if(u.pathname==="/api/health")return out({ok:true,database:!!env.DB});
  if(!env.DB)return out({error:"D1 não configurado"},503);
  await init(env);
  if(u.pathname==="/api/auth/register"&&req.method==="POST"){const b=await req.json();const n=String(b.username||"").trim().toLowerCase();const p=String(b.password||"");if(n.length<3||p.length<4)return out({error:"Usuário ou senha inválidos"},400);const x=await env.DB.prepare("SELECT id FROM users WHERE username=?").bind(n).first();if(x)return out({error:"Usuário já cadastrado"},409);await env.DB.prepare("INSERT INTO users(username,password_hash,role,active) VALUES(?,?,?,1)").bind(n,await hash(p),"operator").run();return out({ok:true},201)}
  if(u.pathname==="/api/auth/login"&&req.method==="POST")return login(req,env);
  const me=await user(req,env);if(!me)return out({error:"Não autenticado"},401);
  if(u.pathname==="/api/auth/me")return out({user:me});
  if(u.pathname==="/api/auth/logout"){const h=req.headers.get("authorization")||"";if(h.startsWith("Bearer "))await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await hash(h.slice(7))).run();return out({ok:true})}
  if(u.pathname==="/api/dashboard"){
   const m=u.searchParams.get("month")||new Date().toISOString().slice(0,7);
   const s=await env.DB.prepare("SELECT COALESCE(SUM(total_cents),0) v,COUNT(*) n FROM orders WHERE status!='cancelled' AND substr(created_at,1,7)=?").bind(m).first();
   const e=await env.DB.prepare("SELECT COALESCE(SUM(amount_cents),0) v FROM expenses WHERE substr(paid_at,1,7)=?").bind(m).first();
   const low=await env.DB.prepare("SELECT COUNT(*) n FROM products WHERE active=1 AND stock<=min_stock").first();
   return out({sales_cents:s.v,orders:s.n,expenses_cents:e.v,profit_cents:Number(s.v)-Number(e.v),low_stock:low.n});
  }
  if(u.pathname==="/api/products"&&req.method==="GET")return out((await env.DB.prepare("SELECT * FROM products WHERE active=1 ORDER BY name").all()).results);
  if(u.pathname==="/api/products"&&req.method==="POST"){const b=await req.json();const r=await env.DB.prepare("INSERT INTO products(name,category,price_cents,cost_cents,stock,min_stock) VALUES(?,?,?,?,?,?)").bind(b.name,b.category||"",money(b.price),money(b.cost),Number(b.stock||0),Number(b.min_stock||0)).run();return out({id:r.meta.last_row_id},201)}
  if(u.pathname==="/api/customers"&&req.method==="GET")return out((await env.DB.prepare("SELECT * FROM customers ORDER BY name").all()).results);
  if(u.pathname==="/api/customers"&&req.method==="POST"){const b=await req.json();const r=await env.DB.prepare("INSERT INTO customers(name,phone,address,notes) VALUES(?,?,?,?)").bind(b.name,b.phone||"",b.address||"",b.notes||"").run();return out({id:r.meta.last_row_id},201)}
  if(u.pathname==="/api/orders"&&req.method==="GET")return out((await env.DB.prepare("SELECT o.*,c.name customer_name FROM orders o LEFT JOIN customers c ON c.id=o.customer_id ORDER BY o.id DESC").all()).results);
  if(u.pathname==="/api/orders"&&req.method==="POST"){
   const b=await req.json();if(!Array.isArray(b.items)||!b.items.length)return out({error:"Adicione itens ao pedido"},400);
   let total=money(b.delivery_fee);const items=[];
   for(const i of b.items){const p=await env.DB.prepare("SELECT * FROM products WHERE id=? AND active=1").bind(i.product_id).first();const q=Number(i.quantity);if(!p||q<=0)return out({error:"Produto inválido"},400);if(Number(p.stock)<q)return out({error:"Estoque insuficiente: "+p.name},400);total+=p.price_cents*q;items.push([p,q])}
   const o=await env.DB.prepare("INSERT INTO orders(customer_id,status,payment_method,total_cents,delivery_fee_cents,notes,created_by) VALUES(?,?,?,?,?,?,?)").bind(b.customer_id||null,b.status||"pending",b.payment_method||"pix",total,money(b.delivery_fee),b.notes||"",me.id).run();
   for(const [p,q] of items){await env.DB.prepare("INSERT INTO order_items(order_id,product_id,quantity,unit_price_cents,unit_cost_cents) VALUES(?,?,?,?,?)").bind(o.meta.last_row_id,p.id,q,p.price_cents,p.cost_cents).run();await env.DB.prepare("UPDATE products SET stock=stock-? WHERE id=?").bind(q,p.id).run();await env.DB.prepare("INSERT INTO stock_movements(product_id,quantity,type,reason,reference_id,created_by) VALUES(?,?,?,?,?,?)").bind(p.id,-q,"sale","Pedido #"+o.meta.last_row_id,o.meta.last_row_id,me.id).run()}
   await env.DB.prepare("INSERT INTO cash_movements(type,description,amount_cents,payment_method,created_by) VALUES(?,?,?,?,?)").bind("in","Pedido #"+o.meta.last_row_id,total,b.payment_method||"pix",me.id).run();
   return out({id:o.meta.last_row_id,total_cents:total},201);
  }
  if(u.pathname==="/api/expenses"&&req.method==="GET")return out((await env.DB.prepare("SELECT * FROM expenses ORDER BY id DESC").all()).results);
  if(u.pathname==="/api/expenses"&&req.method==="POST"){const b=await req.json(),a=money(b.amount);const r=await env.DB.prepare("INSERT INTO expenses(description,amount_cents,category,paid_at,notes,created_by) VALUES(?,?,?,?,?,?)").bind(b.description,a,b.category||"geral",b.paid_at||new Date().toISOString().slice(0,10),b.notes||"",me.id).run();await env.DB.prepare("INSERT INTO cash_movements(type,description,amount_cents,payment_method,created_by) VALUES(?,?,?,?,?)").bind("out",b.description,a,b.payment_method||"pix",me.id).run();return out({id:r.meta.last_row_id},201)}
  if(u.pathname==="/api/stock"&&req.method==="POST"){const b=await req.json();await env.DB.prepare("UPDATE products SET stock=stock+? WHERE id=?").bind(Number(b.quantity),b.product_id).run();await env.DB.prepare("INSERT INTO stock_movements(product_id,quantity,type,reason,created_by) VALUES(?,?,?,?,?)").bind(b.product_id,Number(b.quantity),"in",b.reason||"entrada",me.id).run();return out({ok:true},201)}
  if(u.pathname==="/api/cash"&&req.method==="GET")return out((await env.DB.prepare("SELECT * FROM cash_movements ORDER BY id DESC").all()).results);
  if(u.pathname==="/api/reports"){const a=u.searchParams.get("from")||"2000-01-01",b=u.searchParams.get("to")||"2999-12-31";const s=await env.DB.prepare("SELECT COALESCE(SUM(total_cents),0) v,COUNT(*) n FROM orders WHERE status!='cancelled' AND date(created_at) BETWEEN ? AND ?").bind(a,b).first();const e=await env.DB.prepare("SELECT COALESCE(SUM(amount_cents),0) v FROM expenses WHERE date(paid_at) BETWEEN ? AND ?").bind(a,b).first();return out({sales_cents:s.v,orders:s.n,expenses_cents:e.v,profit_cents:Number(s.v)-Number(e.v)})}
  return out({error:"Rota não encontrada"},404);
 }catch(e){return out({error:e.message||"Erro interno"},500)}
}}