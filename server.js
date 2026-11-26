"use strict";
require("dotenv").config();
const express=require("express"), helmet=require("helmet"), cookieParser=require("cookie-parser");
const bcrypt=require("bcryptjs"), jwt=require("jsonwebtoken"), {Pool}=require("pg");
const {rateLimit}=require("express-rate-limit"), fs=require("fs"), path=require("path");
const app=express(), PORT=Number(process.env.PORT||3000), prod=process.env.NODE_ENV==="production";
if(!process.env.DATABASE_URL) throw new Error("DATABASE_URL is missing");
if(!process.env.JWT_SECRET||process.env.JWT_SECRET.length<32) throw new Error("JWT_SECRET must be at least 32 characters");
if(!process.env.COOKIE_SECRET||process.env.COOKIE_SECRET.length<32) throw new Error("COOKIE_SECRET must be at least 32 characters");
app.disable("x-powered-by"); app.set("trust proxy",1);
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:prod?{rejectUnauthorized:false}:false,max:10,idleTimeoutMillis:30000,connectionTimeoutMillis:10000});
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'","data:"],connectSrc:["'self'"],objectSrc:["'none'"],frameAncestors:["'none'"],upgradeInsecureRequests:prod?[]:null}}}));
app.use(express.json({limit:"20kb"})); app.use(cookieParser(process.env.COOKIE_SECRET));
const COOKIE="scrollchat_session", COOKIE_OPTIONS={httpOnly:true,secure:prod,sameSite:"strict",path:"/",maxAge:7*86400000};
const limiter=rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:"draft-7",legacyHeaders:false,message:{error:"تعداد تلاش‌ها زیاد است. ۱۵ دقیقه دیگر دوباره امتحان کن."}});
const norm=v=>String(v||"").trim().toLowerCase(), validUser=u=>/^[a-z0-9_]{3,24}$/.test(u);
function session(user){return jwt.sign({sub:String(user.id),username:user.username},process.env.JWT_SECRET,{expiresIn:"7d",issuer:"scroll-chat"});}
async function auth(req,res,next){try{const token=req.cookies[COOKIE];if(!token)return res.status(401).json({error:"ابتدا وارد حساب شو."});
const p=jwt.verify(token,process.env.JWT_SECRET,{issuer:"scroll-chat"}),r=await pool.query("SELECT id,username,created_at FROM users WHERE id=$1",[p.sub]);
if(!r.rowCount){res.clearCookie(COOKIE,COOKIE_OPTIONS);return res.status(401).json({error:"حساب کاربری پیدا نشد."});}req.user=r.rows[0];next();
}catch(e){res.clearCookie(COOKIE,COOKIE_OPTIONS);return res.status(401).json({error:"نشست ورود معتبر نیست؛ دوباره وارد شو."});}}
app.get("/",(q,s)=>s.sendFile(path.join(__dirname,"index.html")));
app.get("/style.css",(q,s)=>s.type("text/css").sendFile(path.join(__dirname,"style.css")));
app.get("/app.js",(q,s)=>s.type("application/javascript").sendFile(path.join(__dirname,"app.js")));
app.get("/api/health",async(q,s)=>{try{await pool.query("SELECT 1");s.json({ok:true,service:"scroll-chat",version:"1.0.0"});}catch(e){s.status(503).json({ok:false,error:"Database unavailable"});}});
app.post("/api/auth/register",limiter,async(q,s)=>{const username=norm(q.body.username),password=q.body.password;
if(!validUser(username))return s.status(400).json({error:"نام کاربری باید ۳ تا ۲۴ کاراکتر و فقط شامل حروف انگلیسی کوچک، عدد یا _ باشد."});
if(typeof password!=="string"||password.length<10||password.length>72)return s.status(400).json({error:"رمز عبور باید حداقل ۱۰ و حداکثر ۷۲ کاراکتر باشد."});
try{const hash=await bcrypt.hash(password,12),r=await pool.query("INSERT INTO users(username,password_hash) VALUES($1,$2) RETURNING id,username,created_at",[username,hash]);
const user=r.rows[0];s.cookie(COOKIE,session(user),COOKIE_OPTIONS);s.status(201).json({ok:true,user});}
catch(e){if(e.code==="23505")return s.status(409).json({error:"این نام کاربری قبلاً ثبت شده است."});console.error("Register:",e.message);s.status(500).json({error:"ثبت‌نام انجام نشد. دوباره تلاش کن."});}});
app.post("/api/auth/login",limiter,async(q,s)=>{const username=norm(q.body.username),password=q.body.password;
if(!validUser(username)||typeof password!=="string"||!password.length)return s.status(400).json({error:"نام کاربری یا رمز عبور نامعتبر است."});
try{const r=await pool.query("SELECT id,username,password_hash,created_at FROM users WHERE username=$1",[username]);
if(!r.rowCount)return s.status(401).json({error:"نام کاربری یا رمز عبور اشتباه است."});
const u=r.rows[0];if(!await bcrypt.compare(password,u.password_hash))return s.status(401).json({error:"نام کاربری یا رمز عبور اشتباه است."});
await pool.query("UPDATE users SET last_login_at=NOW() WHERE id=$1",[u.id]);s.cookie(COOKIE,session(u),COOKIE_OPTIONS);
s.json({ok:true,user:{id:u.id,username:u.username,created_at:u.created_at}});}
catch(e){console.error("Login:",e.message);s.status(500).json({error:"ورود انجام نشد. دوباره تلاش کن."});}});
app.post("/api/auth/logout",(q,s)=>{s.clearCookie(COOKIE,COOKIE_OPTIONS);s.json({ok:true});});
app.get("/api/auth/me",auth,(q,s)=>s.json({ok:true,user:q.user}));
app.use("/api",(q,s)=>s.status(404).json({error:"مسیر API پیدا نشد."}));
app.use((e,q,s,n)=>{console.error("Unhandled:",e.message);s.status(500).json({error:"خطای داخلی سرور."});});
async function start(){try{const schema=fs.readFileSync(path.join(__dirname,"schema.sql"),"utf8");await pool.query(schema);console.log("Database schema ready");app.listen(PORT,"0.0.0.0",()=>console.log("Scroll Chat on",PORT));}catch(e){console.error("Startup failed:",e);process.exit(1);}}
process.on("SIGTERM",async()=>{await pool.end();process.exit(0);});start();
