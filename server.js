import express from 'express';
import helmet from 'helmet';
import cookieSession from 'cookie-session';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import crypto from 'node:crypto';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express();
const port=Number(process.env.PORT||3000);
const secret=process.env.SESSION_SECRET||crypto.randomBytes(32).toString('hex');
const db=new Database(path.join(__dirname,'data','conquer.db'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS applications(id INTEGER PRIMARY KEY AUTOINCREMENT,nick TEXT NOT NULL,cls TEXT,power TEXT,hours TEXT,intro TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,status TEXT NOT NULL DEFAULT 'PENDING');
CREATE TABLE IF NOT EXISTS members(id INTEGER PRIMARY KEY AUTOINCREMENT,nick TEXT NOT NULL UNIQUE,cls TEXT,power TEXT,joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,body TEXT NOT NULL,author TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`);

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'200kb'}));
app.use(express.urlencoded({extended:false}));
app.use(cookieSession({name:'conquer_session',keys:[secret],httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:1000*60*60*8}));
app.use(express.static(path.join(__dirname,'public')));
const admin=(req,res,next)=>req.session?.admin?next():res.status(401).json({error:'UNAUTHORIZED'});

app.post('/api/applications',(req,res)=>{
 const {nick,cls,power,hours,intro}=req.body||{};
 if(!nick?.trim()) return res.status(400).json({error:'닉네임은 필수입니다.'});
 const stmt=db.prepare('INSERT INTO applications(nick,cls,power,hours,intro) VALUES(?,?,?,?,?)');
 const info=stmt.run(nick.trim(),cls||'',power||'',hours||'',intro||'');
 res.status(201).json({id:info.lastInsertRowid,message:'가입 신청이 접수되었습니다.'});
});
app.get('/api/applications',admin,(req,res)=>res.json(db.prepare('SELECT * FROM applications ORDER BY id DESC').all()));
app.post('/api/applications/:id/decision',admin,(req,res)=>{
 const id=Number(req.params.id), status=req.body?.status;
 if(!['APPROVED','REJECTED'].includes(status)) return res.status(400).json({error:'잘못된 상태입니다.'});
 const row=db.prepare('SELECT * FROM applications WHERE id=?').get(id);
 if(!row)return res.status(404).json({error:'신청을 찾을 수 없습니다.'});
 db.prepare('UPDATE applications SET status=? WHERE id=?').run(status,id);
 if(status==='APPROVED'){
  db.prepare('INSERT OR IGNORE INTO members(nick,cls,power) VALUES(?,?,?)').run(row.nick,row.cls,row.power);
 }
 res.json({ok:true});
});
app.get('/api/members',(req,res)=>res.json(db.prepare('SELECT * FROM members ORDER BY joined_at DESC').all()));
app.delete('/api/members/:id',admin,(req,res)=>{db.prepare('DELETE FROM members WHERE id=?').run(Number(req.params.id));res.json({ok:true})});
app.get('/api/posts',(req,res)=>res.json(db.prepare('SELECT * FROM posts ORDER BY id DESC').all()));
app.post('/api/posts',admin,(req,res)=>{const {title,body,author}=req.body||{};if(!title||!body)return res.status(400).json({error:'제목과 내용이 필요합니다.'});const i=db.prepare('INSERT INTO posts(title,body,author) VALUES(?,?,?)').run(title,body,author||'관리자');res.status(201).json({id:i.lastInsertRowid})});
app.delete('/api/posts/:id',admin,(req,res)=>{db.prepare('DELETE FROM posts WHERE id=?').run(Number(req.params.id));res.json({ok:true})});
app.post('/api/admin/login',(req,res)=>{const id=req.body?.id,password=req.body?.password;const adminId=process.env.ADMIN_ID||'admin',adminPw=process.env.ADMIN_PASSWORD||'change-me';if(id===adminId&&password===adminPw){req.session.admin=true;return res.json({ok:true})}res.status(401).json({error:'로그인 정보가 올바르지 않습니다.'})});
app.post('/api/admin/logout',(req,res)=>{req.session=null;res.json({ok:true})});
app.get('/api/admin/me',(req,res)=>res.json({authenticated:!!req.session?.admin}));

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(port,()=>console.log(`CONQUER running on http://localhost:${port}`));
