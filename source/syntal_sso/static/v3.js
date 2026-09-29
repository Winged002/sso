(()=>{
  const body=document.body;
  const menu=document.querySelector('[data-mobile-menu]');
  const backdrop=document.querySelector('[data-mobile-backdrop]');
  const close=()=>body.classList.remove('nav-open');
  if(menu)menu.addEventListener('click',()=>body.classList.toggle('nav-open'));
  if(backdrop)backdrop.addEventListener('click',close);
  document.querySelectorAll('[data-dialog-open]').forEach(b=>b.addEventListener('click',()=>{const d=document.getElementById(b.dataset.dialogOpen);if(d)d.showModal()}));
  document.querySelectorAll('[data-dialog-close]').forEach(b=>b.addEventListener('click',()=>{const d=b.closest('dialog');if(d)d.close()}));
  document.querySelectorAll('.secondary-nav a,.primary-rail nav a').forEach(a=>a.addEventListener('click',()=>{if(innerWidth<=1180)close()}));

  const b64ToBytes=(value)=>{
    const normalized=String(value||'').replace(/-/g,'+').replace(/_/g,'/');
    const padded=normalized+'='.repeat((4-normalized.length%4)%4);
    const raw=atob(padded);
    return Uint8Array.from(raw,c=>c.charCodeAt(0));
  };
  const bytesToB64=(value)=>{
    if(value===null||value===undefined)return null;
    const bytes=new Uint8Array(value);
    let raw='';
    bytes.forEach(b=>raw+=String.fromCharCode(b));
    return btoa(raw).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  };
  const prepareRequestOptions=(options)=>{
    const out={...options};
    if(out.challenge)out.challenge=b64ToBytes(out.challenge);
    if(out.user&&out.user.id)out.user={...out.user,id:b64ToBytes(out.user.id)};
    if(Array.isArray(out.allowCredentials))out.allowCredentials=out.allowCredentials.map(x=>({...x,id:b64ToBytes(x.id)}));
    if(Array.isArray(out.excludeCredentials))out.excludeCredentials=out.excludeCredentials.map(x=>({...x,id:b64ToBytes(x.id)}));
    return out;
  };
  const serializeCredential=(credential)=>{
    const response=credential.response||{};
    const result={
      id:credential.id,
      rawId:bytesToB64(credential.rawId),
      type:credential.type,
      authenticatorAttachment:credential.authenticatorAttachment||null,
      response:{clientDataJSON:bytesToB64(response.clientDataJSON)}
    };
    if(response.authenticatorData)result.response.authenticatorData=bytesToB64(response.authenticatorData);
    if(response.signature)result.response.signature=bytesToB64(response.signature);
    if(response.userHandle)result.response.userHandle=bytesToB64(response.userHandle);
    if(response.attestationObject)result.response.attestationObject=bytesToB64(response.attestationObject);
    if(typeof response.getTransports==='function')result.response.transports=response.getTransports();
    if(typeof response.getAuthenticatorData==='function'&&!result.response.authenticatorData)result.response.authenticatorData=bytesToB64(response.getAuthenticatorData());
    if(typeof response.getPublicKeyAlgorithm==='function')result.response.publicKeyAlgorithm=response.getPublicKeyAlgorithm();
    return result;
  };
  const csrf=()=>document.querySelector('[data-csrf-token]')?.value||document.querySelector('input[name="csrf_token"]')?.value||'';
  const statusFor=(node)=>node?.closest('[data-passkey-surface]')?.querySelector('[data-passkey-status]')||document.querySelector('[data-passkey-status]');
  const showStatus=(node,message,isError=false)=>{const target=statusFor(node);if(!target)return;target.textContent=message||'';target.classList.toggle('error',!!isError)};
  const postJSON=async(url,payload)=>{
    const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf(),'Accept':'application/json'},body:JSON.stringify(payload||{})});
    let data={};try{data=await response.json()}catch(_){data={error:'The server returned an invalid response.'}}
    if(!response.ok||data.ok===false)throw new Error(data.error||`Request failed (${response.status})`);
    return data;
  };

  document.querySelectorAll('[data-passkey-login]').forEach(button=>button.addEventListener('click',async()=>{
    if(!window.PublicKeyCredential||!navigator.credentials){showStatus(button,'This browser does not support passkeys.',true);return;}
    const email=document.querySelector('[data-passkey-email]')?.value?.trim();
    if(!email){showStatus(button,'Enter your email address first.',true);document.querySelector('[data-passkey-email]')?.focus();return;}
    button.disabled=true;showStatus(button,'Waiting for your passkey…');
    try{
      const start=await postJSON('/passkeys/login/options',{email,next:button.dataset.next||''});
      const credential=await navigator.credentials.get({publicKey:prepareRequestOptions(start.publicKey)});
      const finish=await postJSON('/passkeys/login/verify',{credential:serializeCredential(credential),next:button.dataset.next||''});
      location.assign(finish.redirect||'/');
    }catch(error){showStatus(button,error?.message||'Passkey sign-in failed.',true);button.disabled=false;}
  }));

  document.querySelectorAll('[data-passkey-reauth]').forEach(button=>button.addEventListener('click',async()=>{
    if(!window.PublicKeyCredential||!navigator.credentials){showStatus(button,'This browser does not support passkeys.',true);return;}
    button.disabled=true;showStatus(button,'Waiting for your passkey…');
    try{
      const start=await postJSON('/passkeys/login/options',{mode:'reauth',next:button.dataset.next||''});
      const credential=await navigator.credentials.get({publicKey:prepareRequestOptions(start.publicKey)});
      const finish=await postJSON('/passkeys/login/verify',{credential:serializeCredential(credential),next:button.dataset.next||''});
      location.assign(finish.redirect||'/');
    }catch(error){showStatus(button,error?.message||'Passkey verification failed.',true);button.disabled=false;}
  }));

  document.querySelectorAll('[data-passkey-register]').forEach(button=>button.addEventListener('click',async()=>{
    if(!window.PublicKeyCredential||!navigator.credentials){showStatus(button,'This browser does not support passkeys.',true);return;}
    button.disabled=true;showStatus(button,'Create a passkey on this device…');
    try{
      const start=await postJSON('/account/passkeys/options',{});
      const credential=await navigator.credentials.create({publicKey:prepareRequestOptions(start.publicKey)});
      const name=document.querySelector('[data-passkey-name]')?.value?.trim()||'Passkey';
      await postJSON('/account/passkeys/verify',{credential:serializeCredential(credential),name});
      location.reload();
    }catch(error){showStatus(button,error?.message||'Passkey registration failed.',true);button.disabled=false;}
  }));
})();
