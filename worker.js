export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, {headers:{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'content-type, authorization','Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS'}});
    if (url.pathname === '/api/health') return Response.json({ok:true,database:!!env.DB});
    if (!env.DB) return Response.json({error:'Banco D1 não configurado'}, {status:503});
    if (url.pathname === '/api/products' && request.method === 'GET') {
      const rows = await env.DB.prepare('SELECT * FROM products WHERE active=1 ORDER BY name').all();
      return Response.json(rows.results);
    }
    if (url.pathname === '/api/customers' && request.method === 'GET') {
      const rows = await env.DB.prepare('SELECT * FROM customers ORDER BY name').all();
      return Response.json(rows.results);
    }
    if (url.pathname === '/api/orders' && request.method === 'GET') {
      const rows = await env.DB.prepare('SELECT o.*, c.name customer_name FROM orders o LEFT JOIN customers c ON c.id=o.customer_id ORDER BY o.id DESC LIMIT 500').all();
      return Response.json(rows.results);
    }
    if (url.pathname === '/api/expenses' && request.method === 'GET') {
      const rows = await env.DB.prepare('SELECT * FROM expenses ORDER BY paid_at DESC, id DESC LIMIT 500').all();
      return Response.json(rows.results);
    }
    if (url.pathname === '/api/dashboard' && request.method === 'GET') {
      const sales = await env.DB.prepare("SELECT COALESCE(SUM(total_cents),0) total, COUNT(*) orders FROM orders WHERE status!='cancelled'").first();
      const expenses = await env.DB.prepare('SELECT COALESCE(SUM(amount_cents),0) total FROM expenses').first();
      const low = await env.DB.prepare('SELECT COUNT(*) total FROM products WHERE active=1 AND stock<=min_stock').first();
      return Response.json({sales_cents:sales.total,orders:sales.orders,expenses_cents:expenses.total,low_stock:low.total});
    }
    return Response.json({error:'Rota não encontrada'}, {status:404});
  }
};