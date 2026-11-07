import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// Version 2 of PRODRIVE website-messages. Run the rate-limit SQL first.
// Never publish or paste SUPABASE_SERVICE_ROLE_KEY into website HTML.
const origins = ["https://www.prodrivemjacademy.it", "https://prodrivemjacademy.it"];
const url = Deno.env.get("SUPABASE_URL");
const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
if (!url || !key) throw new Error("Missing Supabase server environment");
const db = createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
function reply(data: unknown, status = 200, origin = "") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Vary": "Origin",
      ...(origins.includes(origin) ? { "Access-Control-Allow-Origin": origin } : {}),
      "Access-Control-Allow-Headers": "authorization, apikey, content-type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
    },
  });
}
async function hash(input: string) {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(raw), b => b.toString(16).padStart(2, "0")).join("");
}
function text(value: unknown, max: number) {
  return typeof value === "string" ? value.trim().slice(0, max + 1) : "";
}
function validId(id: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
}
async function quota(scope: string, keyMaterial: string, max: number, seconds: number) {
  const slot = Math.floor(Date.now() / (seconds * 1000));
  const bucketKey = scope + ":" + await hash(keyMaterial + "|" + key) + ":" + slot;
  const { data, error } = await db.rpc("website_take_message_quota", {
    p_key: bucketKey, p_limit: max, p_window_seconds: seconds,
  });
  if (error) {
    console.error("rate limit RPC failed", error.message);
    throw new Error("Rate limiting temporarily unavailable");
  }
  return data === true;
}
async function admin(req: Request) {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token) return false;
  const { data, error } = await db.auth.getUser(token);
  if (error || !data.user) return false;
  const { data: allowed, error: adminError } = await db.from("website_admins")
    .select("user_id").eq("user_id", data.user.id).maybeSingle();
  return !adminError && !!allowed;
}
async function visitor(id: string, token: string) {
  if (!validId(id) || token.length < 32 || token.length > 160) return false;
  const { data, error } = await db.from("website_conversations")
    .select("visitor_token_hash").eq("id", id).maybeSingle();
  if (error || !data) return false;
  return (await hash(token)) === data.visitor_token_hash;
}

// Resend credentials are read only from Supabase Edge Function secrets.
// This helper is intentionally best-effort: a mail outage must never lose a saved chat.
async function sendEmail(to: string, subject: string, message: string): Promise<boolean> {
  const apiKey = Deno.env.get("RESEND_API_KEY");
  if (!apiKey) {
    console.warn("RESEND_API_KEY is not configured; email notification skipped");
    return false;
  }
  try {
    const result = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: "PRODRIVE M&J ACADEMY <notifications@prodrivemjacademy.it>",
        to: [to],
        subject,
        text: message,
      }),
    });
    if (!result.ok) {
      console.error("Resend delivery failed", result.status, (await result.text()).slice(0, 300));
      return false;
    }
    return true;
  } catch (error) {
    console.error("Resend request failed", error);
    return false;
  }
}
const ADMIN_NOTIFICATION_EMAIL = "prodrivemjacademy@gmail.com";
const adminConversationUrl = (id: string) =>
  "https://www.prodrivemjacademy.it/admin-messages.html?conversation_id=" + encodeURIComponent(id);

serve(async (req) => {
  const origin = req.headers.get("Origin") || "";
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: origins.includes(origin) ? 204 : 403,
      headers: {
        "Access-Control-Allow-Origin": origins.includes(origin) ? origin : "",
        "Access-Control-Allow-Headers": "authorization, apikey, content-type",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Vary": "Origin",
      },
    });
  }
  if (req.method !== "POST") return reply({ error: "Method not allowed" }, 405, origin);
  if (origin && !origins.includes(origin)) return reply({ error: "Origin not allowed" }, 403, origin);
  const declaredLength = Number(req.headers.get("content-length") || "0");
  if (declaredLength > 12000) return reply({ error: "Request too large" }, 413, origin);

  try {
    const body = await req.json();
    if (!body || typeof body !== "object" || Array.isArray(body))
      return reply({ error: "Invalid request" }, 400, origin);
    const action = text(body.action, 40);
    // Defense in depth: IP quotas plus a global ceiling.
    // Browser Origin restrictions alone are not bot/spam protection.
    const ip = (req.headers.get("x-forwarded-for") || req.headers.get("cf-connecting-ip") || "unknown")
      .split(",")[0].trim().slice(0, 128);

    if (action === "create") {
      const name = text(body.name, 100);
      const email = text(body.email, 254).toLowerCase();
      const message = text(body.message, 2000);
      if (body.website || name.length < 1 || name.length > 100 ||
          email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
          message.length < 1 || message.length > 2000)
        return reply({ error: "Invalid contact details" }, 400, origin);
      if (!(await quota("contact", ip, 3, 900)) || !(await quota("contact-global", "all", 300, 900)))
        return reply({ error: "Too many requests. Please try again later." }, 429, origin);
      const token = crypto.randomUUID() + crypto.randomUUID();
      const { data: conversation, error: createError } = await db
        .from("website_conversations").insert({
          visitor_name: name, visitor_email: email, visitor_token_hash: await hash(token),
        }).select("id").single();
      if (createError || !conversation) throw new Error("Unable to create conversation");
      const { error: messageError } = await db.from("website_messages").insert({
        conversation_id: conversation.id, sender: "visitor", body: message,
      });
      if (messageError) {
        await db.from("website_conversations").delete().eq("id", conversation.id);
        throw new Error("Unable to save message");
      }
      await sendEmail(
        ADMIN_NOTIFICATION_EMAIL,
        "New PRODRIVE website message from " + name,
        "New student website message\n\nName: " + name
          + "\nEmail: " + email
          + "\n\nMessage:\n" + message
          + "\n\nOpen your private admin conversation:\n"
          + adminConversationUrl(conversation.id)
          + "\n\nYou must sign in as an approved administrator to read or reply."
      );
      return reply({
        success: true, message: "Message received",
        conversation_id: conversation.id, visitor_token: token,
      }, 200, origin);
    }

    if (action === "thread" || action === "visitor_reply") {
      const id = text(body.conversation_id, 36);
      const token = text(body.visitor_token, 160);
      if (!(await visitor(id, token))) return reply({ error: "Unauthorized" }, 401, origin);
      if (action === "visitor_reply") {
        const message = text(body.message, 2000);
        if (!message || message.length > 2000)
          return reply({ error: "Invalid message" }, 400, origin);
        if (!(await quota("visitor-reply", id, 30, 3600)))
          return reply({ error: "Please try again later" }, 429, origin);
        const { error } = await db.from("website_messages").insert({
          conversation_id: id, sender: "visitor", body: message,
        });
        if (error) throw new Error("Unable to save reply");
        await db.from("website_conversations")
          .update({ updated_at: new Date().toISOString() }).eq("id", id);
        await sendEmail(
          ADMIN_NOTIFICATION_EMAIL,
          "PRODRIVE student replied on your website",
          "A student sent another message:\n\n" + message
            + "\n\nOpen the private conversation:\n" + adminConversationUrl(id)
        );
        return reply({ success: true }, 200, origin);
      }
      const { data, error } = await db.from("website_messages")
        .select("id,sender,body,created_at")
        .eq("conversation_id", id).order("created_at", { ascending: true }).limit(200);
      if (error) throw new Error("Unable to load messages");
      return reply({ messages: data }, 200, origin);
    }

    if (action.startsWith("admin_")) {
      if (!(await admin(req))) return reply({ error: "Admin access required" }, 403, origin);
      if (action === "admin_list") {
        const { data, error } = await db.from("website_conversations")
          .select("id,visitor_name,visitor_email,status,created_at,updated_at")
          .order("updated_at", { ascending: false }).limit(100);
        if (error) throw new Error("Unable to load inbox");
        return reply({ conversations: data }, 200, origin);
      }
      const id = text(body.conversation_id, 36);
      if (!validId(id)) return reply({ error: "Invalid conversation ID" }, 400, origin);
      if (action === "admin_thread") {
        const { data, error } = await db.from("website_messages")
          .select("id,sender,body,created_at")
          .eq("conversation_id", id).order("created_at", { ascending: true }).limit(200);
        if (error) throw new Error("Unable to load conversation");
        return reply({ messages: data }, 200, origin);
      }
      if (action === "admin_reply") {
        const message = text(body.message, 2000);
        if (!message || message.length > 2000)
          return reply({ error: "Invalid reply" }, 400, origin);
        const { data: conversation } = await db.from("website_conversations")
          .select("id,visitor_name,visitor_email").eq("id", id).maybeSingle();
        if (!conversation) return reply({ error: "Conversation not found" }, 404, origin);
        const { error } = await db.from("website_messages").insert({
          conversation_id: id, sender: "admin", body: message,
        });
        if (error) throw new Error("Unable to save reply");
        await db.from("website_conversations")
          .update({ updated_at: new Date().toISOString() }).eq("id", id);
        await sendEmail(
          conversation.visitor_email,
          "PRODRIVE M&J ACADEMY replied to your message",
          "Hello " + conversation.visitor_name
            + ",\n\nPRODRIVE M&J ACADEMY has replied:\n\n"
            + message
            + "\n\nTo continue chatting, open https://www.prodrivemjacademy.it/#contact"
            + " on the same browser and device where you originally sent your message."
            + "\n\nYou can also contact PRODRIVE on WhatsApp from our website."
        );
        return reply({ success: true }, 200, origin);
      }
    }
    return reply({ error: "Unknown action" }, 400, origin);
  } catch (error) {
    console.error("website-messages", error);
    return reply({ error: "Request could not be completed" }, 500, origin);
  }
});
