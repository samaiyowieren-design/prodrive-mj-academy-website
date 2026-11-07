import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// PRODRIVE account-deletion backend — controlled rollout.
// Account deletion is DISABLED by default until a schema audit and test-account
// run are complete. Never set mode=production before confirming data cleanup.
const originAllowlist = ["https://www.prodrivemjacademy.it","https://prodrivemjacademy.it"];
const url = Deno.env.get("SUPABASE_URL");
const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
if (!url || !serviceKey) throw new Error("Missing Supabase server configuration");
const db = createClient(url, serviceKey, {
  auth:{persistSession:false,autoRefreshToken:false},
});
const mode = Deno.env.get("PRODRIVE_ACCOUNT_DELETE_MODE") || "disabled";
// Only a dedicated test account may be deleted in test mode.
const testEmails = new Set(
  (Deno.env.get("PRODRIVE_DELETE_TEST_EMAILS") || "")
    .split(",").map(v => v.trim().toLowerCase()).filter(Boolean)
);
const protectedEmails = new Set([
  "samaiyowieren@gmail.com",
  "prodrivemjacademy@gmail.com",
]);
function res(data:unknown,status:number,origin:string){
  return new Response(JSON.stringify(data),{
    status,headers:{
      "Content-Type":"application/json; charset=utf-8",
      "Cache-Control":"no-store","Vary":"Origin",
      ...(originAllowlist.includes(origin)?{"Access-Control-Allow-Origin":origin}:{}),
      "Access-Control-Allow-Headers":"authorization,apikey,content-type",
      "Access-Control-Allow-Methods":"POST,OPTIONS",
    },
  });
}
serve(async req=>{
  const origin=req.headers.get("Origin") || "";
  if(req.method==="OPTIONS"){
    return new Response(null,{status:originAllowlist.includes(origin)?204:403,headers:{
      "Access-Control-Allow-Origin":originAllowlist.includes(origin)?origin:"",
      "Access-Control-Allow-Headers":"authorization,apikey,content-type",
      "Access-Control-Allow-Methods":"POST,OPTIONS",
    }});
  }
  if(req.method!=="POST")return res({error:"Method not allowed"},405,origin);
  if(origin&&!originAllowlist.includes(origin))return res({error:"Origin not allowed"},403,origin);
  const authorization=req.headers.get("Authorization") || "";
  if(!authorization.startsWith("Bearer "))return res({error:"Authentication required"},401,origin);
  const token=authorization.slice(7).trim();
  if(!token)return res({error:"Authentication required"},401,origin);
  try{
    const {data:{user},error:authError}=await db.auth.getUser(token);
    if(authError||!user)return res({error:"Invalid or expired session"},401,origin);
    const email=(user.email||"").toLowerCase();
    if(!email||protectedEmails.has(email))
      return res({error:"This account cannot be deleted by this endpoint"},403,origin);
    // A website administrator is never allowed to self-delete with this function.
    const {data:admin,error:adminError}=await db.from("website_admins")
      .select("user_id").eq("user_id",user.id).maybeSingle();
    if(adminError)throw new Error("Could not verify admin protection");
    if(admin)return res({error:"Administrator accounts are protected"},403,origin);
    const body=await req.json().catch(()=>null);
    if(!body||typeof body!=="object")return res({error:"Invalid request"},400,origin);
    const action=body.action;
    const permitted=mode==="production"||(mode==="test"&&testEmails.has(email));
    if(action==="preview"){
      return res({
        user_email:email,
        enabled:permitted,
        status:permitted?"available_for_testing":"not_enabled",
        explanation:"Deletion is irreversible. Account-linked data handling must be audited first.",
      },200,origin);
    }
    if(action!=="confirm")return res({error:"Unknown action"},400,origin);
    if(!permitted)return res({error:"Account deletion has not been activated yet"},503,origin);
    if(body.confirmation!=="DELETE MY ACCOUNT"||
       typeof body.email!=="string"||body.email.trim().toLowerCase()!==email)
      return res({error:"Explicit account and email confirmation required"},400,origin);
    // Deleting auth.users triggers configured FKs, including CASCADE and SET NULL.
    // A restrictive FK may block deletion. It must not be bypassed blindly.
    // Other unrelated user-data columns require a separate audit/cleanup plan.
    const {error:deleteError}=await db.auth.admin.deleteUser(user.id,false);
    if(deleteError){
      console.error("Account delete failed",deleteError.message);
      return res({error:"Deletion blocked by a data dependency. Contact support."},409,origin);
    }
    return res({success:true,message:"Account deletion completed"},200,origin);
  }catch(error){
    console.error("delete-account:",error);
    return res({error:"Deletion request could not be completed"},500,origin);
  }
});
