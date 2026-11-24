// Encrypts a full HTML page into a password-gated page (PBKDF2-SHA256 250k + AES-256-GCM, decrypted in the browser).
// usage: node lock.mjs <in.html> <out.html> <password> "<title>"
import { readFileSync, writeFileSync } from "node:fs";
import { webcrypto as c } from "node:crypto";

const [inp, out, pass, title] = process.argv.slice(2);
const html = readFileSync(inp, "utf8");
const salt = c.getRandomValues(new Uint8Array(16)), iv = c.getRandomValues(new Uint8Array(12));
const base = await c.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
const key = await c.subtle.deriveKey({ name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" }, base,
  { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
const ct = new Uint8Array(await c.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(html)));
const b64 = (u) => Buffer.from(u).toString("base64");

writeFileSync(out, `<!doctype html>
<html lang="uk"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${title}</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600&family=Manrope:wght@400;600&display=swap">
<style>
:root{--ink:#0e0d0c;--slab:#171513;--line:#3b3326;--gold:#c9a54c;--text:#ece6d8;--muted:#9d9483;color-scheme:dark}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{background:var(--ink);color:var(--text);font-family:Manrope,Arial,sans-serif;display:grid;place-items:center;
 padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px));
 background-image:radial-gradient(900px 400px at 80% -10%,rgba(201,165,76,.12),transparent 60%)}
.box{width:100%;max-width:400px;border:1px solid var(--line);background:var(--slab);padding:34px 28px}
.brand{font-family:"Cormorant Garamond",Georgia,serif;letter-spacing:.32em;color:var(--gold);font-size:14px}
h1{font-family:"Cormorant Garamond",Georgia,serif;font-weight:600;font-size:30px;line-height:1.1;margin:18px 0 8px}
p{color:var(--muted);font-size:14px;margin:0 0 22px}
input{width:100%;background:var(--ink);border:1px solid var(--line);color:var(--text);font:16px Manrope,Arial,sans-serif;padding:13px 14px}
input:focus{outline:2px solid var(--gold);outline-offset:1px}
button{margin-top:12px;width:100%;background:var(--gold);color:#141210;border:0;font:600 14px Manrope,Arial,sans-serif;letter-spacing:.12em;padding:14px;cursor:pointer}
.err{color:#e08a7a;font-size:13px;min-height:20px;margin-top:10px}
</style></head><body>
<form class="box" id="f" autocomplete="off">
 <div class="brand">ASTRACORENOVA</div>
 <h1>${title}</h1>
 <p>Персональна пропозиція. Введіть пароль, який Вам надіслали.</p>
 <label for="pw" style="position:absolute;left:-9999px">Пароль</label>
 <input id="pw" type="password" placeholder="Пароль" autofocus>
 <button type="submit">ВІДКРИТИ</button>
 <div class="err" id="e"></div>
</form>
<script>
const D={s:"${b64(salt)}",i:"${b64(iv)}",c:"${b64(ct)}"};
const u=b=>Uint8Array.from(atob(b),ch=>ch.charCodeAt(0));
document.getElementById('f').addEventListener('submit',async ev=>{
 ev.preventDefault();const e=document.getElementById('e');e.textContent='';
 try{
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(document.getElementById('pw').value),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:u(D.s),iterations:250000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['decrypt']);
  const html=new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:u(D.i)},key,u(D.c)));
  document.open();document.write(html);document.close();
 }catch(_){e.textContent='Пароль не підходить. Перевірте, будь ласка, і спробуйте ще раз.';}
});
</script></body></html>`);
console.log("ok", out);
