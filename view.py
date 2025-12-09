from main import app, con
from flask_bcrypt import generate_password_hash, check_password_hash
import config
import datetime
from flask import jsonify, request
from flask_jwt_extended import create_access_token, get_jwt, verify_jwt_in_request, get_jwt_identity

# Funções globais
# Funções de token
senha_secreta = app.config['SECRET_KEY']


# gera token com expiração de 3 horas
def generate_token(user_id):
    expires = datetime.timedelta(hours=3)
    additional_claims = {"id_usuario": str(user_id)}
    token = create_access_token(identity=user_id, additional_claims=additional_claims, expires_delta=expires)
    return token


def formatar_telefone(tel):
    # 5518123451234
    # +55 (18) 12345-1234
    tel = str(tel)
    tel = ''.join(filter(str.isdigit, tel))  # Remove caracteres não numéricos
    if len(tel) == 11:
        ddd = tel[:2]
        primeira_parte = tel[2:7]
        segunda_parte = tel[7:]
        return f"({ddd}) {primeira_parte}-{segunda_parte}"
    elif len(tel) == 13:
        pais = tel[:2]
        ddd = tel[2:4]
        primeira_parte = tel[4:9]
        segunda_parte = tel[9:]
        return f"+{pais} ({ddd}) {primeira_parte}-{segunda_parte}"


# helper igual
def remover_bearer(token):
    if token and token.startswith("Bearer "):
        return token[len("Bearer "):]
    return token


# verificar_user refatorado para usar flask-jwt-extended
def verificar_user(tipo, trazer_pl):
    cur = con.cursor()
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return 1  # Token de autenticação necessário

        token = remover_bearer(auth_header)

        # Use verify_jwt_in_request para validar token; se inválido, lança exceções do JWT ext.
        try:
            # verifica e popula contexto do request com JWT
            verify_jwt_in_request()
        except Exception as e:
            # mapear erros para seus códigos
            msg = getattr(e, 'args', [None])[0]
            # expirado -> flask_jwt_extended lança jwt_exceptions.ExpiredSignatureError por baixo
            from flask_jwt_extended.exceptions import NoAuthorizationError, RevokedTokenError
            from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
            if isinstance(e, NoAuthorizationError):
                return 1
            # tentativa simples: checar texto da exceção
            text = str(e).lower()
            print(text)
            if 'expired' in text:
                return 2
            if 'invalid' in text or 'decode' in text:
                return 3
            return 3

        # pega identity e claims
        id_logado = get_jwt_identity()
        claims = get_jwt()  # dicionário com additional_claims

        # Se você precisa do payload completo (similar ao antigo), construa-o:
        payload = dict(claims)
        payload['id_usuario'] = id_logado

        # checagens de permissão usando seu banco
        if tipo == 2:
            cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO = ? AND (TIPO = 2 OR TIPO = 3)", (id_logado,))
            biblio = cur.fetchone()
            if not biblio:
                return 4  # Nível Personal trainer requerido

        elif tipo == 3:
            cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO = ? AND TIPO = 3", (id_logado,))
            admin = cur.fetchone()
            if not admin:
                return 5  # Nível Administrador requerido

        if trazer_pl:
            return payload
        return 0  # sucesso sem payload
    except Exception:
        print("Erro em verificar_user")
        raise
    finally:
        cur.close()


def informar_verificacao(tipo=0, trazer_pl=False):
    verificacao = verificar_user(tipo, trazer_pl)
    if verificacao == 1:
        return jsonify({'message': 'Token de autenticação necessário.', "verificacao": verificacao, "error": True}), 401
    elif verificacao == 2:
        return jsonify({'message': 'Token expirado.', "verificacao": verificacao, "error": True}), 401
    elif verificacao == 3:
        return jsonify({'message': 'Token inválido.', "verificacao": verificacao, "error": True}), 401
    elif verificacao == 4:
        return jsonify({'message': 'Nível Personal Trainer requerido.', "verificacao": verificacao, "error": True}), 401
    elif verificacao == 5:
        return jsonify({'message': 'Nível Administrador requerido.', "verificacao": verificacao, "error": True}), 401
    elif verificacao == 6:
        return jsonify({'message': 'Acesso negado.', "verificacao": verificacao, "error": True}), 401
    else:
        if trazer_pl:
            return verificacao
        return None


global_contagem_erros = {}


@app.route('/login', methods=["POST"])
def logar():
    data = request.get_json()
    email = data.get("email")
    email = email.lower()
    senha = data.get("senha")

    cur = con.cursor()
    try:
        # Checando se a senha está correta
        cur.execute("SELECT senha, id_usuario FROM usuarios WHERE email = ?", (email,))
        resultado = cur.fetchone()

        if resultado:
            senha_hash = resultado[0]
            id_user = resultado[1]
            ativo = cur.execute("SELECT ATIVO FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
            ativo = ativo.fetchone()[0]
            if not ativo:
                return jsonify(
                    {
                        "message": "Este usuário está inativado.",
                        "id_user": id_user,
                        "error": True
                    }
                ), 401

            if check_password_hash(senha_hash, senha):
                tipo = cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
                tipo = tipo.fetchone()[0]

                nome = cur.execute("SELECT NOME FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
                nome = nome.fetchone()[0]

                token = generate_token(id_user)

                # limpar global_contagem_erros e etc...

                token = remover_bearer(token)

                tipo = cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
                tipo = tipo.fetchone()[0]
                # Excluir as tentativas que deram errado
                id_user_str = f"usuario-{id_user}"
                if id_user_str in global_contagem_erros:
                    del global_contagem_erros[id_user_str]

                return jsonify({"message": "Login realizado com sucesso!",
                                "token": token,
                                "nome": nome,
                                "tipo": tipo,
                                "email": email,
                                "error": False}), 200
            else:
                # Ignorar isso tudo se o usuário for administrador ou personal trainer
                tipo = cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_user,))
                tipo = tipo.fetchone()[0]

                if tipo != 3:
                    id_user_str = f"usuario-{id_user}"
                    if id_user_str not in global_contagem_erros:
                        global_contagem_erros[id_user_str] = 1
                    else:
                        global_contagem_erros[id_user_str] += 1

                        if global_contagem_erros[id_user_str] == 3:
                            cur.execute("UPDATE USUARIOS SET ATIVO = FALSE WHERE ID_USUARIO = ?", (id_user,))
                            con.commit()

                            return jsonify({"message": "Tentativas excedidas, usuário inativado.", "error": True}), 401
                        elif global_contagem_erros[id_user_str] > 3:
                            global_contagem_erros[id_user_str] = 1
                            # Em teoria é para ser impossível a execução chegar aqui

                return jsonify({"message": "Credenciais inválidas.", "error": True}), 401
        else:
            return jsonify({"message": "Usuário não encontrado.", "error": True}), 404
    except Exception:
        print("Erro em logar")
        raise

    finally:
        cur.close()


@app.route('/cadastrarusuario/<int:tipo>', methods=["POST"])
def cadastrar_usuario(tipo=1):
    if tipo > 1:
        verificacao = informar_verificacao(2)
        if verificacao:
            return verificacao

    data = request.get_json()
    nome = data.get('nome')
    senha1 = data.get('senha')
    cpf = data.get('cpf')
    tel = data.get('tel')
    email = data.get('email')
    email = email.lower()

    if not all([nome, senha1, cpf, tel, email]):
        return jsonify({"message": "Todos os campos são obrigatórios"}), 400

    cpf1 = str(cpf)
    tel1 = str(tel)

    # Verificações de senha
    if len(senha1) < 8:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
            uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401

    tem_maiuscula = False
    tem_minuscula = False
    tem_numero = False
    tem_caract_especial = False
    caracteres_especiais = "!@#$%^&*(),-.?\":{}|<>"

    # Verifica cada caractere da senha
    for char in senha1:
        if char.isupper():
            tem_maiuscula = True
        elif char.islower():
            tem_minuscula = True
        elif char.isdigit():
            tem_numero = True
        elif char in caracteres_especiais:
            tem_caract_especial = True

    # Verifica se todos os critérios foram atendidos
    if not tem_maiuscula:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
            uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
    if not tem_minuscula:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
            uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
    if not tem_numero:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
            uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401
    if not tem_caract_especial:
        return jsonify({"message": """Sua senha deve conter pelo menos oito caracteres, 
            uma letra maiúscula e minúscula e um símbolo de seu teclado.""", "error": True}), 401

    cur = con.cursor()
    try:
        cur.execute("SELECT CPF FROM USUARIOS WHERE CPF = ?", (cpf1,))
        # Verificações a partir do banco de dados
        # Verificações de duplicatas
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == cpf1:
                return jsonify({"message": "CPF já cadastrado", "error": True}), 401

        cur.execute("SELECT EMAIL FROM USUARIOS WHERE EMAIL = ?", (email,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == email:
                return jsonify({"message": "Email já cadastrado", "error": True}), 401

        cur.execute("SELECT TELEFONE FROM USUARIOS WHERE TELEFONE = ?", (formatar_telefone(tel1),))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == formatar_telefone(tel1):
                return jsonify({"message": "Telefone já cadastrado", "error": True}), 401

        senha2 = generate_password_hash(senha1).decode('utf-8')

        cur.execute("""INSERT INTO USUARIOS (NOME, SENHA, TIPO, CPF, EMAIL, TELEFONE)
         VALUES (?, ?, ?, ?, ?, ?)""", (nome, senha2, tipo, cpf1, email, formatar_telefone(tel1),))

        con.commit()

        return jsonify({"message": "Usuário cadastrado com sucesso"}), 200

    except Exception as e:
        print(f"Erro em cadastrarusuario, {e}")
        raise
    finally:
        cur.close()
