from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime, timedelta, timezone
import jwt
from typing import List
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Response
from fpdf import FPDF

# --- 1. CONFIGURAÇÕES DE SEGURANÇA E BASE DE DADOS ---
SECRET_KEY = "chave_super_secreta_da_mixx_internet"
ALGORITHM = "HS256"
TEMPO_EXPIRACAO_MINUTOS = 30

SQLALCHEMY_DATABASE_URL = "sqlite:///./mixx_internet.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# O esquema de segurança diz ao FastAPI onde o cliente deve ir buscar o token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# --- 2. MODELOS DE BASE DE DADOS (SQLite) ---
class DBCliente(Base):
    __tablename__ = "clientes"
    cpf = Column(String, primary_key=True, index=True)
    senha = Column(String)
    plano = relationship("DBPlano", back_populates="cliente", uselist=False)
    faturas = relationship("DBFatura", back_populates="cliente")

class DBPlano(Base):
    __tablename__ = "planos"
    id = Column(Integer, primary_key=True, index=True)
    cliente_cpf = Column(String, ForeignKey("clientes.cpf"))
    nome_plano = Column(String)
    tecnologia = Column(String)
    valor_mensalidade = Column(Float)
    status_conexao = Column(String)
    cliente = relationship("DBCliente", back_populates="plano")

class DBFatura(Base):
    __tablename__ = "faturas"
    id_fatura = Column(Integer, primary_key=True, index=True)
    cliente_cpf = Column(String, ForeignKey("clientes.cpf"))
    vencimento = Column(String)
    valor = Column(Float)
    status = Column(String)
    linha_digitavel_boleto = Column(String)
    cliente = relationship("DBCliente", back_populates="faturas")

Base.metadata.create_all(bind=engine)

# --- 3. MODELOS DE RESPOSTA (Pydantic) ---
class Fatura(BaseModel):
    id_fatura: int
    vencimento: str
    valor: float
    status: str
    linha_digitavel_boleto: str
    model_config = ConfigDict(from_attributes=True)

class DadosPlano(BaseModel):
    nome_plano: str
    tecnologia: str
    valor_mensalidade: float
    status_conexao: str
    model_config = ConfigDict(from_attributes=True)

# --- 4. FUNÇÕES DE SEGURANÇA E BANCO DE DADOS ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def criar_token(dados: dict):
    copia_dados = dados.copy()
    expira = datetime.now(timezone.utc) + timedelta(minutes=TEMPO_EXPIRACAO_MINUTOS)
    copia_dados.update({"exp": expira})
    return jwt.encode(copia_dados, SECRET_KEY, algorithm=ALGORITHM)

# Esta função intercepta as requisições protegidas, verifica o token e descobre quem é o cliente
def obter_cliente_logado(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        cpf: str = payload.get("sub")
        if cpf is None:
            raise HTTPException(status_code=401, detail="Token inválido.")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="A sua sessão expirou.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token de segurança inválido.")
    
    cliente = db.query(DBCliente).filter(DBCliente.cpf == cpf).first()
    if not cliente:
        raise HTTPException(status_code=401, detail="Cliente não encontrado.")
    return cliente

# --- 5. INICIALIZAÇÃO DA API E ROTAS ---
app = FastAPI(title="API Mixx Internet - Segura com JWT")

# Adicione este bloco para permitir que o Front-end converse com a API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Em produção, colocaríamos o domínio da Mixx Internet aqui
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/auth/login")
def realizar_login(dados: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # O OAuth2 usa os nomes padrão 'username' (onde vamos pedir o CPF) e 'password'
    cliente = db.query(DBCliente).filter(DBCliente.cpf == dados.username).first()
    
    if not cliente or cliente.senha != dados.password:
        raise HTTPException(status_code=401, detail="CPF ou senha incorretos.")
    
    # Gera o Token e envia para o cliente guardar
    token_jwt = criar_token({"sub": cliente.cpf})
    return {"access_token": token_jwt, "token_type": "bearer"}

# Repare que agora NÃO pedimos o CPF na URL. O token já carrega essa informação!
@app.get("/api/cliente/plano", response_model=DadosPlano)
def consultar_plano(cliente_logado: DBCliente = Depends(obter_cliente_logado)):
    if not cliente_logado.plano:
        raise HTTPException(status_code=404, detail="Plano não encontrado.")
    return cliente_logado.plano

@app.get("/api/cliente/faturas", response_model=List[Fatura])
def listar_faturas(cliente_logado: DBCliente = Depends(obter_cliente_logado)):
    if not cliente_logado.faturas:
        raise HTTPException(status_code=404, detail="Nenhuma fatura encontrada.")
    return cliente_logado.faturas

# --- 6. ROTAS ADMINISTRATIVAS (Painel do Provedor) ---

class AdminNovoCliente(BaseModel):
    cpf: str
    senha: str
    nome_plano: str
    tecnologia: str
    valor_mensalidade: float

class AdminNovaFatura(BaseModel):
    cliente_cpf: str
    vencimento: str
    valor: float
    linha_digitavel_boleto: str

class AdminAtualizarStatus(BaseModel):
    status_conexao: str # Ex: "Ativa", "Bloqueada", "Reduzida"

@app.post("/api/admin/clientes", tags=["Administração"])
def admin_cadastrar_cliente(dados: AdminNovoCliente, db: Session = Depends(get_db)):
    if db.query(DBCliente).filter(DBCliente.cpf == dados.cpf).first():
        raise HTTPException(status_code=400, detail="CPF já registado.")
    
    # Cria o cliente e o plano associado na base de dados
    novo_cliente = DBCliente(cpf=dados.cpf, senha=dados.senha)
    novo_plano = DBPlano(
        cliente_cpf=dados.cpf, 
        nome_plano=dados.nome_plano, 
        tecnologia=dados.tecnologia, 
        valor_mensalidade=dados.valor_mensalidade, 
        status_conexao="Ativa" # Por padrão, um cliente novo entra como Ativo
    )
    
    db.add(novo_cliente)
    db.add(novo_plano)
    db.commit()
    return {"mensagem": "Cliente e plano registados com sucesso na Mixx Internet."}

@app.post("/api/admin/faturas", tags=["Administração"])
def admin_gerar_fatura(dados: AdminNovaFatura, db: Session = Depends(get_db)):
    if not db.query(DBCliente).filter(DBCliente.cpf == dados.cliente_cpf).first():
        raise HTTPException(status_code=404, detail="Cliente não encontrado.")
        
    nova_fatura = DBFatura(
        cliente_cpf=dados.cliente_cpf,
        vencimento=dados.vencimento,
        valor=dados.valor,
        status="Aberta", # Faturas novas nascem sempre em aberto
        linha_digitavel_boleto=dados.linha_digitavel_boleto
    )
    db.add(nova_fatura)
    db.commit()
    return {"mensagem": "Fatura gerada com sucesso."}

@app.put("/api/admin/clientes/{cpf}/status", tags=["Administração"])
def admin_alterar_status(cpf: str, dados: AdminAtualizarStatus, db: Session = Depends(get_db)):
    plano = db.query(DBPlano).filter(DBPlano.cliente_cpf == cpf).first()
    if not plano:
        raise HTTPException(status_code=404, detail="Plano não encontrado.")
        
    plano.status_conexao = dados.status_conexao
    db.commit() # Atualiza a tabela no SQLite
    return {"mensagem": f"Estado da ligação alterado para {dados.status_conexao}."}

# --- 7. AUTOMAÇÃO E GERAÇÃO DE ARQUIVOS ---

@app.get("/api/cliente/faturas/{id_fatura}/pdf", tags=["Cliente"])
def baixar_pdf_fatura(id_fatura: int, cliente_logado: DBCliente = Depends(obter_cliente_logado), db: Session = Depends(get_db)):
    # 1. Verifica se a fatura existe e se pertence mesmo a este cliente (Segurança)
    fatura = db.query(DBFatura).filter(DBFatura.id_fatura == id_fatura, DBFatura.cliente_cpf == cliente_logado.cpf).first()
    
    if not fatura:
        raise HTTPException(status_code=404, detail="Fatura não encontrada ou não autorizada.")

    # 2. Desenha o PDF em memória
    pdf = FPDF()
    pdf.add_page()
    
    # Cabeçalho
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "Mixx Internet - Fatura do Assinante", ln=True, align="C")
    pdf.ln(10)
    
    # Dados da Fatura
    pdf.set_font("helvetica", "", 12)
    pdf.cell(0, 10, f"CPF do Titular: {cliente_logado.cpf}", ln=True)
    pdf.cell(0, 10, f"Plano: {cliente_logado.plano.nome_plano if cliente_logado.plano else 'Não definido'}", ln=True)
    pdf.cell(0, 10, f"Data de Vencimento: {fatura.vencimento}", ln=True)
    pdf.cell(0, 10, f"Valor da Mensalidade: R$ {fatura.valor:.2f}", ln=True)
    pdf.cell(0, 10, f"Estado Atual: {fatura.status.upper()}", ln=True)
    
    pdf.ln(10)
    
    # Bloco de Pagamento (Apenas se a fatura estiver aberta)
    if fatura.status == "Aberta":
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 10, "Linha Digitável para Pagamento no Multibanco / App:", ln=True)
        pdf.set_font("helvetica", "", 12)
        pdf.cell(0, 10, fatura.linha_digitavel_boleto, ln=True)
    else:
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(0, 128, 0) # Cor verde
        pdf.cell(0, 10, "FATURA LIQUIDADA. Obrigado pela sua preferência!", ln=True)

    # 3. Transforma o PDF em bytes (para envio pela rede)
    pdf_bytes = bytes(pdf.output())

    # 4. Devolve como um ficheiro descarregável
    nome_arquivo = f"Fatura_Mixx_{fatura.vencimento}.pdf"
    return Response(
        content=pdf_bytes, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename={nome_arquivo}"}
    )