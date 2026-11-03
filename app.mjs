const enc=new TextEncoder(),dec=new TextDecoder();
const form=document.getElementById('unlockForm'),password=document.getElementById('password'),button=document.getElementById('unlockButton'),message=document.getElementById('message'),lockButton=document.getElementById('lockButton');
let privateKey=null,currentFrame=null,keyBundle=null,publishedAt=null;
function bytes(s){if(typeof s!=='string'||!/^[-A-Za-z0-9+/=]+$/.test(s))throw new Error('Invalid encoding');return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
async function loadJson(name){const r=await fetch(new URL(name,import.meta.url),{cache:'no-store'});if(!r.ok)throw new Error('사이트 파일을 불러오지 못했습니다. 잠시 후 다시 시도해 주세요.');return r.json();}
async function unlockPrivate(pass,bundle){
  if(bundle.version!==1||bundle.kdf?.name!=='PBKDF2'||bundle.kdf?.hash!=='SHA-256'||bundle.kdf?.iterations!==600000||bundle.cipher!=='AES-256-GCM')throw new Error('지원하지 않는 암호 설정입니다.');
  const raw=enc.encode(pass);const base=await crypto.subtle.importKey('raw',raw,'PBKDF2',false,['deriveKey']);raw.fill(0);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',iterations:bundle.kdf.iterations,salt:bytes(bundle.kdf.salt)},base,{name:'AES-GCM',length:256},false,['decrypt']);
  let pkcs;try{pkcs=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(bundle.iv),additionalData:enc.encode('insight8:private:v1:'+bundle.keyId)},key,bytes(bundle.encryptedPrivateKey));}catch{throw new Error('암호가 일치하지 않습니다. 다시 입력해 주세요.');}
  try{return await crypto.subtle.importKey('pkcs8',pkcs,{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);}finally{new Uint8Array(pkcs).fill(0);}
}
async function showPayload(payload){
  if(!privateKey||payload.version!==1||payload.keyId!==keyBundle.keyId||payload.algorithm!=='RSA-OAEP-256+A256GCM')throw new Error('암호 설정과 자료 파일이 일치하지 않습니다.');
  const raw=await crypto.subtle.decrypt({name:'RSA-OAEP'},privateKey,bytes(payload.wrappedKey));
  const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['decrypt']);new Uint8Array(raw).fill(0);
  const html=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(payload.iv),additionalData:enc.encode('insight8:payload:v1:'+payload.keyId)},key,bytes(payload.ciphertext));
  const frame=document.createElement('iframe');frame.title='대리점 인사이트8';frame.setAttribute('sandbox','allow-scripts allow-same-origin allow-downloads');frame.srcdoc=dec.decode(html);new Uint8Array(html).fill(0);
  currentFrame?.remove();currentFrame=frame;document.body.append(frame);publishedAt=payload.publishedAt;document.body.classList.add('unlocked');lockButton.classList.remove('hidden');
}
function lock(){currentFrame?.remove();currentFrame=null;privateKey=null;keyBundle=null;publishedAt=null;password.value='';document.body.classList.remove('unlocked');lockButton.classList.add('hidden');message.textContent='화면을 잠갔습니다.';password.focus();}
form.addEventListener('submit',async event=>{event.preventDefault();if(!crypto?.subtle){message.textContent='보안 연결(HTTPS)에서 최신 브라우저로 열어 주세요.';return;}button.disabled=true;button.textContent='암호 확인 중…';message.textContent='';let pass=password.value;password.value='';try{keyBundle=await loadJson('./crypto-keys.json');privateKey=await unlockPrivate(pass,keyBundle);pass='';button.textContent='자료 여는 중…';await showPayload(await loadJson('./payload.json'));}catch(e){privateKey=null;message.textContent=e.name==='OperationError'?'자료를 확인할 수 없습니다. 암호 또는 게시 상태를 확인해 주세요.':e.message;}finally{pass='';button.disabled=false;button.textContent='인사이트8 열기';}});
lockButton.addEventListener('click',lock);
window.addEventListener('message',async event=>{if(!currentFrame||event.source!==currentFrame.contentWindow)return;if(event.data?.type==='insight8-lock'){lock();return;}if(event.data?.type==='insight8-refresh'){lockButton.disabled=true;try{await showPayload(await loadJson('./payload.json'));}catch{lock();message.textContent='최신 자료를 열지 못했습니다. 다시 접속해 주세요.';}finally{lockButton.disabled=false;}}});
document.addEventListener('visibilitychange',async()=>{if(document.hidden||!privateKey)return;try{const p=await loadJson('./payload.json');if(p.publishedAt!==publishedAt)currentFrame?.contentWindow?.postMessage({type:'insight8-new-data'},location.origin);}catch{}});
