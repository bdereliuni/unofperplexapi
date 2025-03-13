import re
import ssl
import json
import socket
import random
import asyncio
import mimetypes
from uuid import uuid4
from threading import Thread
from curl_cffi import requests, CurlMime
from websocket import WebSocketApp

# FastAPI için gerekli kütüphaneler
from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, Depends
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from typing import List, Dict, Optional, Any
from pydantic import BaseModel
import base64
import os

# Veritabanı için eklemeler
from sqlalchemy import create_engine, Column, String, JSON, Integer, Text, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.sql import func
from contextlib import contextmanager
import datetime

try:
    from .emailnator import Emailnator
except ImportError:
    # Doğrudan çalıştırılırken import hatası olmaması için
    class Emailnator:
        pass

# Veritabanı bağlantısını yapılandırma
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./chats.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Veritabanı modelleri
class Chat(Base):
    __tablename__ = "chats"
    
    id = Column(String, primary_key=True, index=True)
    backend_uuid = Column(String, index=True, nullable=True)
    context_uuid = Column(String, index=True, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    
    messages = relationship("Message", back_populates="chat", cascade="all, delete-orphan")

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(String, ForeignKey("chats.id"))
    role = Column(String, index=True)  # "user" veya "assistant"
    content = Column(Text)
    files = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    
    chat = relationship("Chat", back_populates="messages")

# Veritabanı tabloları oluştur
Base.metadata.create_all(bind=engine)

# Veritabanı bağlantı yöneticisi
@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class AsyncMixin:
    def __init__(self, *args, **kwargs):
        self.__storedargs = args, kwargs
        self.async_initialized = False
        
    async def __ainit__(self, *args, **kwargs):
        pass
    
    async def __initobj(self):
        assert not self.async_initialized
        self.async_initialized = True
        
        # pass the parameters to __ainit__ that passed to __init__
        await self.__ainit__(*self.__storedargs[0], **self.__storedargs[1])
        return self
    
    def __await__(self):
        return self.__initobj().__await__()

class Client(AsyncMixin):
    '''
    A client for interacting with the Perplexity AI API.
    '''
    async def __ainit__(self, cookies={}, headers=None):
        default_headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'max-age=0',
            'dnt': '1',
            'priority': 'u=0, i',
            'sec-ch-ua': '"Not;A=Brand";v="24", "Chromium";v="128"',
            'sec-ch-ua-arch': '"x86"',
            'sec-ch-ua-bitness': '"64"',
            'sec-ch-ua-full-version': '"128.0.6613.120"',
            'sec-ch-ua-full-version-list': '"Not;A=Brand";v="24.0.0.0", "Chromium";v="128.0.6613.120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-model': '""',
            'sec-ch-ua-platform': '"Windows"',
            'sec-ch-ua-platform-version': '"19.0.0"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
        }
        
        # Eğer özel headers verilmişse, varsayılan başlıkları güncelle
        if headers:
            default_headers.update(headers)
            
        self.session = requests.AsyncSession(headers=default_headers, cookies=cookies, impersonate='chrome')
        self.own = bool(cookies)
        self.copilot = float('inf') if self.own else 0
        self.file_upload = float('inf') if self.own else 0
        self.message_counter = 1
        self.signin_regex = re.compile(r'"(https://www\.perplexity\.ai/api/auth/callback/email\?callbackUrl=.*?)"')
        self.last_file_upload_info = None
        self.timestamp = format(random.getrandbits(32), '08x')
        self.sid = json.loads((await self.session.get(f'https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.timestamp}')).text[1:])['sid']
        
        assert (await self.session.post(f'https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.timestamp}&sid={self.sid}', data='40{"jwt":"anonymous-ask-user"}')).text == 'OK'
        await self.session.get('https://www.perplexity.ai/api/auth/session')
        
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.sock = context.wrap_socket(socket.create_connection(('www.perplexity.ai', 443)), server_hostname='www.perplexity.ai')
        
        self.ws = WebSocketApp(
            url=f'wss://www.perplexity.ai/socket.io/?EIO=4&transport=websocket&sid={self.sid}',
            header={'User-Agent': self.session.headers['User-Agent']},
            cookie='; '.join([f'{key}={value}' for key, value in self.session.cookies.get_dict().items()]),
            on_open=lambda ws: (ws.send('2probe'), ws.send('5')),
            on_message=self._on_message,
            on_error=lambda ws, error: print(f'Websocket Error: {error}'),
            socket=self.sock
        )
        
        Thread(target=self.ws.run_forever, daemon=True).start()
        
        while not (self.ws.sock and self.ws.sock.connected):
            await asyncio.sleep(0.01)
    
    async def create_account(self, cookies):
        '''
        Function to create a new account
        '''
        while True:
            try:
                emailnator_cli = await Emailnator(cookies)
                
                resp = await self.session.post('https://www.perplexity.ai/api/auth/signin/email', data={
                    'email': emailnator_cli.email,
                    'csrfToken': self.session.cookies.get_dict()['next-auth.csrf-token'].split('%')[0],
                    'callbackUrl': 'https://www.perplexity.ai/',
                    'json': 'true'
                })
                
                if resp.ok:
                    new_msgs = await emailnator_cli.reload(wait_for=lambda x: x['subject'] == 'Sign in to Perplexity', timeout=20)
                    
                    if new_msgs:
                        break
                else:
                    print('Perplexity account creating error:', resp)
            
            except Exception:
                pass
        
        msg = emailnator_cli.get(func=lambda x: x['subject'] == 'Sign in to Perplexity')
        new_account_link = self.signin_regex.search(await emailnator_cli.open(msg['messageID'])).group(1)
        
        await self.session.get(new_account_link)
        
        self.copilot = 5
        self.file_upload = 10
        
        self.ws.close()
        del self.sock
        
        self.sid = json.loads((await self.session.get(f'https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.timestamp}')).text[1:])['sid']
        
        assert (await self.session.post(f'https://www.perplexity.ai/socket.io/?EIO=4&transport=polling&t={self.timestamp}&sid={self.sid}', data='40{"jwt":"anonymous-ask-user"}')).text == 'OK'
        
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.sock = context.wrap_socket(socket.create_connection(('www.perplexity.ai', 443)), server_hostname='www.perplexity.ai')
        
        self.ws = WebSocketApp(
            url=f'wss://www.perplexity.ai/socket.io/?EIO=4&transport=websocket&sid={self.sid}',
            header={'User-Agent': self.session.headers['User-Agent']},
            cookie='; '.join([f'{key}={value}' for key, value in self.session.cookies.get_dict().items()]),
            on_open=lambda ws: (ws.send('2probe'), ws.send('5')),
            on_message=self._on_message,
            on_error=lambda ws, error: print(f'Websocket Error: {error}'),
            socket=self.sock
        )
        
        Thread(target=self.ws.run_forever).start()
        
        while not (self.ws.sock and self.ws.sock.connected):
            await asyncio.sleep(0.01)
        
        return True
    
    def _on_message(self, ws, message):
        '''
        Websocket message handler
        '''
        if message == '2':
            ws.send('3')
        
        elif message.startswith(str(self.message_counter + 430)):
            response = json.loads(message[len(str(self.message_counter + 430)):])[0]
            
            if 'fields' in response:
                self.last_file_upload_info = response
    
    async def search(self, query, mode='auto', model=None, sources=['web'], files={}, stream=False, language='en-US', follow_up=None, incognito=False):
        '''
        Query function
        '''
        assert mode in ['auto', 'pro', 'reasoning', 'deep research'], 'Search modes -> ["auto", "pro", "reasoning", "deep research"]'
        assert model in {
            'auto': [None],
            'pro': ['sonar', 'gpt-4.5', 'gpt-4o', 'claude 3.7 sonnet', 'gemini 2.0 flash', 'grok-2'],
            'reasoning': ['r1', 'o3-mini', 'claude 3.7 sonnet'],
            'deep research': [None]
        }[mode] if self.own else True, '''Models for modes -> {
    'auto': [None],
    'pro': ['sonar', 'gpt-4.5', 'gpt-4o', 'claude 3.7 sonnet', 'gemini 2.0 flash', 'grok-2'],
    'reasoning': ['r1', 'o3-mini', 'claude 3.7 sonnet'],
    'deep research': [None]
}'''
        assert all([source in ('web', 'scholar', 'social') for source in sources]), 'Sources -> ["web", "scholar", "social"]'
        
        # Pro hesap olduğu için limit kontrollerini kaldırdık
        self.last_file_upload_info = None
        
        uploaded_files = []
        
        for filename, file in files.items():
            self.message_counter += 1
            self.ws.send(f'{self.message_counter + 420}' + json.dumps([
                'get_upload_url',
                {
                    'content_type': mimetypes.guess_type(filename)[0],
                    'filename': filename,
                    'source': 'default',
                    'version': '2.18'
                }
            ]))
            
            while not self.last_file_upload_info:
                await asyncio.sleep(0.01)
            
            if not self.last_file_upload_info['success']:
                raise Exception('File upload error', self.last_file_upload_info)
            
            mp = CurlMime()
            
            for key, value in self.last_file_upload_info['fields'].items():
                mp.addpart(name=key, data=value)
            
            mp.addpart(name='file', content_type=mimetypes.guess_type(filename)[0], filename=filename, data=file)
            
            upload_resp = await self.session.post(self.last_file_upload_info['url'], multipart=mp)
            
            if not upload_resp.ok:
                raise Exception('File upload error', upload_resp)
            
            uploaded_files.append(self.last_file_upload_info['url'] + self.last_file_upload_info['fields']['key'].replace('${filename}', filename))
        
        json_data = {
            'query_str': query,
            'params':
                {
                    'attachments': uploaded_files + follow_up['attachments'] if follow_up else uploaded_files,
                    'frontend_context_uuid': str(uuid4()),
                    'frontend_uuid': str(uuid4()),
                    'is_incognito': incognito,
                    'language': language,
                    'last_backend_uuid': follow_up['backend_uuid'] if follow_up else None,
                    'mode': 'concise' if mode == 'auto' else 'copilot',
                    'model_preference': {
                        'auto': 'turbo',
                        'pro': 'pplx_pro',
                        'reasoning': 'pplx_reasoning',
                        'deep research': 'pplx_alpha'
                    }[mode] if not self.own else {
                        'auto': {
                            None: 'turbo'
                        },
                        'pro': {
                            'sonar': 'experimental',
                            'gpt-4.5': 'gpt45',
                            'gpt-4o': 'gpt4o',
                            'claude 3.7 sonnet': 'claude2',
                            'gemini 2.0 flash': 'gemini2flash',
                            'grok-2': 'grok'
                        },
                        'reasoning': {
                            'r1': 'r1',
                            'o3-mini': 'o3mini',
                            'claude 3.7 sonnet': 'claude37sonnetthinking'
                        },
                        'deep research': {
                            None: 'pplx_alpha'
                        }
                    }[mode][model],
                    'source': 'default',
                    'sources': sources,
                    'version': '2.18'
                }
            }
        
        resp = await self.session.post('https://www.perplexity.ai/rest/sse/perplexity_ask', json=json_data, stream=True)
        chunks = []
        
        async def stream_response(resp):
            async for chunk in resp.aiter_lines(delimiter=b'\r\n\r\n'):
                content = chunk.decode('utf-8')
                
                if content.startswith('event: message\r\n'):
                    content_json = json.loads(content[len('event: message\r\ndata: '):])
                    content_json['text'] = json.loads(content_json['text'])
                    
                    chunks.append(content_json)
                    yield chunks[-1]
                
                elif content.startswith('event: end_of_stream\r\n'):
                    return
        
        if stream:
            return stream_response(resp)
        
        async for chunk in resp.aiter_lines(delimiter=b'\r\n\r\n'):
            content = chunk.decode('utf-8')
            
            if content.startswith('event: message\r\n'):
                content_json = json.loads(content[len('event: message\r\ndata: '):])
                content_json['text'] = json.loads(content_json['text'])
                
                chunks.append(content_json)
            
            elif content.startswith('event: end_of_stream\r\n'):
                return chunks[-1]


# Veritabanı işlemleri için yardımcı fonksiyonlar
def get_chat_by_id(db: Session, chat_id: str):
    return db.query(Chat).filter(Chat.id == chat_id).first()

def create_chat(db: Session, chat_id: str, backend_uuid: str = None, context_uuid: str = None):
    chat = Chat(id=chat_id, backend_uuid=backend_uuid, context_uuid=context_uuid)
    db.add(chat)
    db.commit()
    db.refresh(chat)
    return chat

def add_message(db: Session, chat_id: str, role: str, content: str, files=None):
    message = Message(chat_id=chat_id, role=role, content=content, files=files)
    db.add(message)
    db.commit()
    db.refresh(message)
    return message

def update_chat(db: Session, chat_id: str, backend_uuid: str = None, context_uuid: str = None):
    chat = get_chat_by_id(db, chat_id)
    if chat:
        if backend_uuid:
            chat.backend_uuid = backend_uuid
        if context_uuid:
            chat.context_uuid = context_uuid
        chat.updated_at = datetime.datetime.now()
        db.commit()
        db.refresh(chat)
    return chat

def delete_chat_by_id(db: Session, chat_id: str):
    chat = get_chat_by_id(db, chat_id)
    if chat:
        db.delete(chat)
        db.commit()
        return True
    return False

def get_all_chats(db: Session, skip: int = 0, limit: int = 100):
    return db.query(Chat).offset(skip).limit(limit).all()

def get_chat_messages(db: Session, chat_id: str):
    return db.query(Message).filter(Message.chat_id == chat_id).order_by(Message.created_at).all()

# FastAPI modelleri
class QueryRequest(BaseModel):
    query: str
    mode: str = "auto"
    model: Optional[str] = None
    sources: List[str] = ["web"]
    language: str = "en-US"
    incognito: bool = False
    stream: bool = False
    cookies: Dict[str, str] = {}
    headers: Dict[str, str] = {}
    chat_id: Optional[str] = None  # Chat ID ekledik

class FileData(BaseModel):
    filename: str
    content: str  # Base64 kodlu dosya içeriği

class QueryRequestWithFiles(QueryRequest):
    files: List[FileData] = []

# Varsayılan cookie ve header bilgileri
DEFAULT_COOKIES = {
    'pplx.welcome-back-gate-impressions': '4',
    'pplx.visitor-id': '0c977904-17cd-4dd5-a592-c4e3524a62ea',
    '__cflb': '02DiuDyvFMmK5p9jVbVnMNSKYZhUL9aGmrcqeXMScWv1z',
    '__podscribe_perplexityai_referrer': 'https://accounts.google.com/',
    '__podscribe_perplexityai_landing_url': 'https://www.perplexity.ai/?login-source=signupButton&login-new=true',
    '_fbp': 'fb.1.1741860500363.754976730684619743',
    'intercom-device-id-l2wyozh0': '54d474e4-ab32-48aa-aec4-df76de9a2197',
    'pplx.trackingAllowed': 'true',
    '_gcl_au': '1.1.383922571.1741860520',
    'pplx.unified-engine-tooltip-shown': 'true',
    'pplx.deep-research-tooltip-impressions': '3',
    'IndrX2c1OFdjNG9oXzgxd1JocUVVWGFadkNMVEZaYlkzeGRCUlRlR1JldWhCX2Fub255bW91c1VzZXJJZCI%3D': 'ImFjODM1NGI3LTkzNTUtNDBlZC1hNDQ4LTM3YTk3NmVhNzkwYSI=',
    'pplx.search-models': '{%22pro%22:%22claude2%22}',
    'pplx.session-id': 'ba020254-5dbe-4ae2-871b-8a53c6f36f9b',
    'next-auth.csrf-token': '66938a2453456767a04f1e361302f61c43325a0b620af716692d17d680e9b737%7Cf7952ba6e42096b95d7512a9281b24deb409e74a3de7980f1ce0988188e7a9ea',
    'pplx.is-enterprise-ad-dismissed': 'true',
    'next-auth.callback-url': 'https%3A%2F%2Fwww.perplexity.ai%2Fapi%2Fauth%2Fsignin-callback%3Fredirect%3Dhttps%253A%252F%252Fwww.perplexity.ai',
    'cf_clearance': 'NQlbg9t1j3jgppoPVJmHsS.8AyF2h94Zsj4tltnI6XI-1741886951-1.2.1.1-chx1naofSgda6caNatjNJW1RsXGNaEofek9o.BGNNqwQzmyzD8DS1orCV9e.tPz9gLASUvWje.7JtXq3JYL1ajnkAY_60BMcUXVuaxv1ThbTAz316IdFLOz.utWmfrZwqEfXfrCJhNF3KdmDY4JuNDkm5ktqiNBsjarBG56bMIHpCg4kZB.4pRm0hjOepP7kvR8hb_Od3QcHVwb8mVKBJuSMt1pQP.UlvGSPo8wVSHZA31mboxHJczMWkzaWPH.HHW4Tw9m6Hants8NRn2XDy9Z7PsiejqrvRgFPWKbjOWHYAvLQZQhD0qYlPsE.gidMez2SXJQB3tTHwMt1bTgz8qgp7aGFXv.3T_AWuBGoAMY',
    'pplx.search-mode': 'pro',
    'pplx.metadata': '{%22qc%22:10%2C%22qcu%22:5%2C%22qcm%22:0%2C%22qcc%22:4%2C%22qcr%22:0%2C%22qcdr%22:0%2C%22qcd%22:0%2C%22hli%22:true%2C%22hcga%22:true%2C%22hcds%22:false%2C%22hso%22:true%2C%22hfo%22:true}',
    '_rdt_uuid': '1741860500402.008516c9-6373-466b-8759-0df7ed2582ed',
    '__cf_bm': '9Hps3a91Pgya8br3OK.R8BJAPoDiSr7QHj9.7CAjWLs-1741887435-1.0.1.1-Q5eqSh9xQ4ACtbdi1E5wmGommKwqtfeyDO6JYjZum1okOdMBNweWerHkG3MsobpHNtLwXLATvLyiYcpP61xdIrcyyGhWGcEukdCbnh3oV_U',
    'AWSALB': 'Ji0/h0sAivREUvDnmrSBhviCuoQPtahXXceL9cZ+gTKQL6VJkDifUee7Jo2OOQvfbyXk0FtodZtspQ1BBpRWrX8mO04Va/qa5C6OE8Y2v9dpDwBQ+R8ES1Xq4PZ+DFmX2LnX4T1mYR57ZRwttVU47QC0GsbaYhTyfzjeZIn2qo/Rh3edtLGB2Mbcou0lEw==',
    'AWSALBCORS': 'Ji0/h0sAivREUvDnmrSBhviCuoQPtahXXceL9cZ+gTKQL6VJkDifUee7Jo2OOQvfbyXk0FtodZtspQ1BBpRWrX8mO04Va/qa5C6OE8Y2v9dpDwBQ+R8ES1Xq4PZ+DFmX2LnX4T1mYR57ZRwttVU47QC0GsbaYhTyfzjeZIn2qo/Rh3edtLGB2Mbcou0lEw==',
    '__Secure-next-auth.session-token': 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..vXbL4smoTiAG9YIa.uPeGNUtQ0FFP2m4wISg804Abb71RvJvBcQpfQ9KuQgm86LAX1JsPrc74edW4flOnZMBPAiNBx_bXhLD-yKFSlkyt2EudYRr2fUOJnXjPI7w8irbTwzT6EZsGKAENLe-0Cl6LNSJ0I64pMxVSTJyzWeV8mq0AGzuY6narvyZiGeQqKMgXdaR36760BMBUBSTltY3P4iNG4-ASj7c97CnSKDJlTPf-25Xs7LsUX72BqCsz_eAGWKwuqsa4hubOUf7zYTtemHsht_wSBTJtbEZSuMx9lIHQkpku693znMRkuohycpiR5DiVpSTt0pygcriYfZtbqX4GmHtzc0xGuocr-JKdv5nxiTNa448svvm68WmbUq7uLpvzhYrGxabGFiPrPSo.qwig2Y-hMqU_jKKM2l0SGg',
    '_dd_s': 'aid=0ed0bd48-7abb-42da-b8a2-229a11a1cf4c&rum=2&id=259aad17-663e-448f-8f96-a6f55ac2e407&created=1741884620482&expire=1741888430872&logs=1',
}

DEFAULT_HEADERS = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'accept-language': 'tr,en-US;q=0.9,en;q=0.8,zh-CN;q=0.7,zh;q=0.6',
    'cache-control': 'max-age=0',
    'priority': 'u=0, i',
    'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
    'sec-ch-ua-arch': '"x86"',
    'sec-ch-ua-bitness': '"64"',
    'sec-ch-ua-full-version': '"134.0.6998.89"',
    'sec-ch-ua-full-version-list': '"Chromium";v="134.0.6998.89", "Not:A-Brand";v="24.0.0.0", "Google Chrome";v="134.0.6998.89"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-model': '""',
    'sec-ch-ua-platform': '"Windows"',
    'sec-ch-ua-platform-version': '"10.0.0"',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-user': '?1',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
}

# FastAPI uygulaması
app = FastAPI(title="Perplexity API Server", description="Perplexity AI API'sine erişim sağlayan API sunucusu")

# CORS ayarları
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ana sayfa route'u
@app.get("/")
async def root():
    return {
        "message": "Perplexity API Sunucusu çalışıyor",
        "endpoints": [
            {
                "path": "/query",
                "method": "POST",
                "description": "Perplexity'ye sorgu gönder"
            },
            {
                "path": "/query_with_files",
                "method": "POST",
                "description": "Dosyalarla birlikte Perplexity'ye sorgu gönder"
            },
            {
                "path": "/chats",
                "method": "GET",
                "description": "Mevcut sohbetleri listele"
            }
        ]
    }

# Normal sorgu endpoint'i (dosya olmadan)
@app.post("/query")
async def query(request: QueryRequest):
    try:
        # İstek için özel cookie ve header bilgileri
        cookies_to_use = request.cookies if request.cookies else DEFAULT_COOKIES
        headers_to_use = request.headers if request.headers else DEFAULT_HEADERS
        
        # Her istek için yeni bir client oluştur
        client = await Client(cookies=cookies_to_use, headers=headers_to_use)
        
        # Chat ID kontrolü ve follow-up hazırlama
        follow_up = None
        
        with get_db() as db:
            # Eğer chat_id verilmişse
            if request.chat_id:
                # Veritabanından chat'i kontrol et
                chat = get_chat_by_id(db, request.chat_id)
                
                if chat:
                    # Var olan sohbeti devam ettir
                    follow_up = {
                        "backend_uuid": chat.backend_uuid,
                        "attachments": []
                    }
        
        result = await client.search(
            query=request.query,
            mode=request.mode,
            model=request.model,
            sources=request.sources,
            language=request.language,
            incognito=request.incognito,
            stream=request.stream,
            follow_up=follow_up
        )
        
        # İşlem bittikten sonra websocket bağlantısını kapat
        if hasattr(client, 'ws') and client.ws:
            client.ws.close()
        
        # Sonucu veritabanına kaydet
        if request.chat_id and not request.stream:
            with get_db() as db:
                chat = get_chat_by_id(db, request.chat_id)
                
                if not chat:
                    # Yeni sohbet oluştur
                    chat = create_chat(
                        db, 
                        request.chat_id, 
                        result.get("backend_uuid", None), 
                        result.get("context_uuid", None)
                    )
                    # Kullanıcı mesajını ekle
                    add_message(db, request.chat_id, "user", request.query)
                    # Asistan mesajını ekle
                    add_message(
                        db, 
                        request.chat_id, 
                        "assistant", 
                        result["text"]["answer"] if "text" in result and "answer" in result["text"] else ""
                    )
                else:
                    # Mevcut sohbeti güncelle
                    update_chat(
                        db, 
                        request.chat_id, 
                        result.get("backend_uuid", None), 
                        result.get("context_uuid", None)
                    )
                    # Kullanıcı mesajını ekle
                    add_message(db, request.chat_id, "user", request.query)
                    # Asistan mesajını ekle
                    add_message(
                        db, 
                        request.chat_id, 
                        "assistant", 
                        result["text"]["answer"] if "text" in result and "answer" in result["text"] else ""
                    )
        
        if request.stream:
            # Streaming yanıt için
            async def generate():
                last_chunk = None
                async for chunk in result:
                    last_chunk = chunk
                    yield json.dumps(chunk) + "\n"
                
                # Stream'in sonunda veritabanını güncelle
                if request.chat_id and last_chunk:
                    with get_db() as db:
                        chat = get_chat_by_id(db, request.chat_id)
                        
                        if not chat:
                            # Yeni sohbet oluştur
                            chat = create_chat(
                                db, 
                                request.chat_id, 
                                last_chunk.get("backend_uuid", None), 
                                last_chunk.get("context_uuid", None)
                            )
                            # Kullanıcı mesajını ekle
                            add_message(db, request.chat_id, "user", request.query)
                            # Asistan mesajını ekle
                            add_message(
                                db, 
                                request.chat_id, 
                                "assistant", 
                                last_chunk["text"]["answer"] if "text" in last_chunk and "answer" in last_chunk["text"] else ""
                            )
                        else:
                            # Mevcut sohbeti güncelle
                            update_chat(
                                db, 
                                request.chat_id, 
                                last_chunk.get("backend_uuid", None), 
                                last_chunk.get("context_uuid", None)
                            )
                            # Kullanıcı mesajını ekle
                            add_message(db, request.chat_id, "user", request.query)
                            # Asistan mesajını ekle
                            add_message(
                                db, 
                                request.chat_id, 
                                "assistant", 
                                last_chunk["text"]["answer"] if "text" in last_chunk and "answer" in last_chunk["text"] else ""
                            )
            
            return StreamingResponse(generate(), media_type="application/x-ndjson")
        else:
            # Normal yanıt için
            return JSONResponse(content=result)
    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e), "type": str(type(e))})

# Dosya içeren sorgu endpoint'i
@app.post("/query_with_files")
async def query_with_files(request: QueryRequestWithFiles):
    try:
        # İstek için özel cookie ve header bilgileri
        cookies_to_use = request.cookies if request.cookies else DEFAULT_COOKIES
        headers_to_use = request.headers if request.headers else DEFAULT_HEADERS
        
        # Her istek için yeni bir client oluştur
        client = await Client(cookies=cookies_to_use, headers=headers_to_use)
        
        files = {}
        
        # Base64 kodlu dosyaları çöz
        for file_data in request.files:
            file_content = base64.b64decode(file_data.content)
            files[file_data.filename] = file_content
        
        # Chat ID kontrolü ve follow-up hazırlama
        follow_up = None
        
        with get_db() as db:
            # Eğer chat_id verilmişse
            if request.chat_id:
                # Veritabanından chat'i kontrol et
                chat = get_chat_by_id(db, request.chat_id)
                
                if chat:
                    # Var olan sohbeti devam ettir
                    follow_up = {
                        "backend_uuid": chat.backend_uuid,
                        "attachments": []
                    }
        
        result = await client.search(
            query=request.query,
            mode=request.mode,
            model=request.model,
            sources=request.sources,
            language=request.language,
            incognito=request.incognito,
            stream=request.stream,
            files=files,
            follow_up=follow_up
        )
        
        # İşlem bittikten sonra websocket bağlantısını kapat
        if hasattr(client, 'ws') and client.ws:
            client.ws.close()
        
        # Dosya adlarını JSON formatına dönüştür
        file_names = [f.filename for f in request.files]
        
        # Sonucu veritabanına kaydet
        if request.chat_id and not request.stream:
            with get_db() as db:
                chat = get_chat_by_id(db, request.chat_id)
                
                if not chat:
                    # Yeni sohbet oluştur
                    chat = create_chat(
                        db, 
                        request.chat_id, 
                        result.get("backend_uuid", None), 
                        result.get("context_uuid", None)
                    )
                    # Kullanıcı mesajını ekle
                    add_message(db, request.chat_id, "user", request.query, file_names)
                    # Asistan mesajını ekle
                    add_message(
                        db, 
                        request.chat_id, 
                        "assistant", 
                        result["text"]["answer"] if "text" in result and "answer" in result["text"] else ""
                    )
                else:
                    # Mevcut sohbeti güncelle
                    update_chat(
                        db, 
                        request.chat_id, 
                        result.get("backend_uuid", None), 
                        result.get("context_uuid", None)
                    )
                    # Kullanıcı mesajını ekle
                    add_message(db, request.chat_id, "user", request.query, file_names)
                    # Asistan mesajını ekle
                    add_message(
                        db, 
                        request.chat_id, 
                        "assistant", 
                        result["text"]["answer"] if "text" in result and "answer" in result["text"] else ""
                    )
        
        if request.stream:
            # Streaming yanıt için
            async def generate():
                last_chunk = None
                async for chunk in result:
                    last_chunk = chunk
                    yield json.dumps(chunk) + "\n"
                
                # Stream'in sonunda veritabanını güncelle
                if request.chat_id and last_chunk:
                    with get_db() as db:
                        chat = get_chat_by_id(db, request.chat_id)
                        
                        if not chat:
                            # Yeni sohbet oluştur
                            chat = create_chat(
                                db, 
                                request.chat_id, 
                                last_chunk.get("backend_uuid", None), 
                                last_chunk.get("context_uuid", None)
                            )
                            # Kullanıcı mesajını ekle
                            add_message(db, request.chat_id, "user", request.query, file_names)
                            # Asistan mesajını ekle
                            add_message(
                                db, 
                                request.chat_id, 
                                "assistant", 
                                last_chunk["text"]["answer"] if "text" in last_chunk and "answer" in last_chunk["text"] else ""
                            )
                        else:
                            # Mevcut sohbeti güncelle
                            update_chat(
                                db, 
                                request.chat_id, 
                                last_chunk.get("backend_uuid", None), 
                                last_chunk.get("context_uuid", None)
                            )
                            # Kullanıcı mesajını ekle
                            add_message(db, request.chat_id, "user", request.query, file_names)
                            # Asistan mesajını ekle
                            add_message(
                                db, 
                                request.chat_id, 
                                "assistant", 
                                last_chunk["text"]["answer"] if "text" in last_chunk and "answer" in last_chunk["text"] else ""
                            )
            
            return StreamingResponse(generate(), media_type="application/x-ndjson")
        else:
            # Normal yanıt için
            return JSONResponse(content=result)
    
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e), "type": str(type(e))})

# Mevcut sohbetleri listele
@app.get("/chats")
async def list_chats(skip: int = 0, limit: int = 100):
    with get_db() as db:
        chats = get_all_chats(db, skip, limit)
        result = {}
        
        for chat in chats:
            messages = get_chat_messages(db, chat.id)
            result[chat.id] = {
                "message_count": len(messages),
                "messages": [{"role": msg.role, "content": msg.content, "files": msg.files} for msg in messages],
                "backend_uuid": chat.backend_uuid,
                "context_uuid": chat.context_uuid,
                "created_at": chat.created_at.isoformat(),
                "updated_at": chat.updated_at.isoformat()
            }
        
        return JSONResponse(content=result)

# Belirli bir sohbeti görüntüle
@app.get("/chats/{chat_id}")
async def get_chat(chat_id: str):
    with get_db() as db:
        chat = get_chat_by_id(db, chat_id)
        
        if chat:
            messages = get_chat_messages(db, chat_id)
            result = {
                "id": chat.id,
                "messages": [{"role": msg.role, "content": msg.content, "files": msg.files} for msg in messages],
                "backend_uuid": chat.backend_uuid,
                "context_uuid": chat.context_uuid,
                "created_at": chat.created_at.isoformat(),
                "updated_at": chat.updated_at.isoformat()
            }
            return JSONResponse(content=result)
        
        return JSONResponse(status_code=404, content={"error": "Chat not found"})

# Belirli bir sohbeti sil
@app.delete("/chats/{chat_id}")
async def delete_chat(chat_id: str):
    with get_db() as db:
        success = delete_chat_by_id(db, chat_id)
        
        if success:
            return JSONResponse(content={"message": f"Chat {chat_id} deleted successfully"})
        
        return JSONResponse(status_code=404, content={"error": "Chat not found"})

# Doğrudan çalıştırma için
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("client:app", host="0.0.0.0", port=port, reload=True)