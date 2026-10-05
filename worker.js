// Big 3 BBQ backend
export default {async fetch(){return new Response(JSON.stringify({ok:true,ready:true}),{headers:{'content-type':'application/json'}})}}
