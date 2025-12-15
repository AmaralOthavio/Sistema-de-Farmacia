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
    token = create_access_token(identity=str(user_id), additional_claims=additional_claims, expires_delta=expires)
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
        id_logado = int(get_jwt_identity())
        claims = get_jwt()  # dicionário com additional_claims

        # Se você precisa do payload completo (similar ao antigo), construa-o:
        payload = dict(claims)
        payload['id_usuario'] = id_logado

        # checagens de permissão usando seu banco
        if tipo == 2:
            cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO = ? AND (TIPO = 2 OR TIPO = 3)", (id_logado,))
            biblio = cur.fetchone()
            if not biblio:
                return 4  # Nível 2

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
        return jsonify({'message': 'Nível Farmacêutico requerido.', "verificacao": verificacao, "error": True}), 401
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

    if nome:
        if len(nome) > 895:
            return jsonify({"message": "Nome grande demais, o limite é 895 caracteres", "error": True}), 401
    if cpf:
        if len(cpf1) != 11:
            return jsonify({"message": "O CPF precisa ter 11 dígitos", "error": True}), 401
    if tel:
        if len(tel1) != 13:
            return jsonify({"message": """O telefone precisa ser enviado em 13 dígitos exemplo: +55 (18) 12345-1234 = 5518123451234""", "error": True}), 401
    if '@' not in email:
        return jsonify({"message": "E-mail inválido", "error": True}), 401

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


@app.route("/usuarios/editar", methods=["PUT"])
def editar_perfil():
    verificacao = informar_verificacao()
    if verificacao:
        return verificacao
    id_usuario = informar_verificacao(trazer_pl=True)
    id_usuario = id_usuario['id_usuario']

    data = request.get_json()
    nome = data.get("nome")
    senha1 = data.get("senha")
    cpf = data.get("cpf")
    email = data.get("email")
    email = email.lower()
    tel = data.get("tel")

    # Verificações de comprimento e formatação de dados
    cpf1 = str(cpf)
    tel1 = str(tel)

    if nome:
        if len(nome) > 895:
            return jsonify({"message": "Nome grande demais, o limite é 895 caracteres", "error": True}), 401
    if cpf:
        if len(cpf1) != 11:
            return jsonify({"message": "O CPF precisa ter 11 dígitos", "error": True}), 401
    if tel:
        if len(tel1) != 13:
            return jsonify({"message": """O telefone precisa ser enviado em 13 dígitos exemplo: +55 (18) 12345-1234 = 5518123451234""", "error": True}), 401
    if '@' not in email:
        return jsonify({"message": "E-mail inválido", "error": True}), 401

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
        # Verificações de duplicatas
        cur.execute("SELECT CPF FROM USUARIOS WHERE CPF = ? AND ID_USUARIO <> ?", (cpf1, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == cpf1:
                return jsonify({"message": "CPF já cadastrado", "error": True}), 401

        cur.execute("SELECT EMAIL FROM USUARIOS WHERE EMAIL = ? AND ID_USUARIO <> ?", (email, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == email:
                return jsonify({"message": "Email já cadastrado", "error": True}), 401

        cur.execute("SELECT TELEFONE FROM USUARIOS WHERE TELEFONE = ? AND ID_USUARIO <> ?", (formatar_telefone(tel1), id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == formatar_telefone(tel1):
                return jsonify({"message": "Telefone já cadastrado", "error": True}), 401

        # Pegando valores padrões
        cur.execute("""SELECT NOME, SENHA, CPF, EMAIL, TELEFONE FROM USUARIOS WHERE ID_USUARIO = ?""", (id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            # Trocando os valores não recebidos pelos existentes no banco
            nome = resposta[0] if not nome else nome
            senha_hash = resposta[1]
            cpf1 = str(resposta[2]) if not cpf else cpf1
            email = resposta[3] if not email else email
            tel = resposta[4] if not tel else tel

        if senha1:
            senha_hash = generate_password_hash(senha1).decode('utf-8')

        cur.execute("""UPDATE USUARIOS SET NOME = ?, SENHA = ?, CPF = ?, EMAIL = ?, TELEFONE = ?, 
         WHERE ID_USUARIO = ?""", (nome, senha_hash, cpf1, email, formatar_telefone(tel),
                                                    id_usuario,))

        con.commit()

        return jsonify({"message": "Usuário editado com sucesso!", "error": "False"}), 200

    except Exception:
        print("Erro em /usuarios/editar")
        raise
    finally:
        cur.close()


# Entrega os campos de dados já existentes para o usuário se editar
@app.route('/usuarios/info', methods=["GET"])
def trazer_campos_editar_a_si_mesmo():
    verificacao = informar_verificacao()
    if verificacao:
        return verificacao

    id_logado = informar_verificacao(trazer_pl=True)
    id_logado = id_logado["id_usuario"]

    cur = con.cursor()
    try:
        cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_logado, ))
        dicionario = {}
        subtitulos = []

        tipo = cur.fetchone()
        if tipo:
            cur.execute(f"""SELECT NOME, EMAIL, TELEFONE, CPF, ATIVO
                            FROM USUARIOS WHERE ID_USUARIO = ?""", (id_logado,))
            subtitulos = ["nome", "email", "telefone", "cpf", "data_nascimento", "ativo"]
            dados = cur.fetchone()
            x = 0
            for dado in dados:
                try:
                    dicionario[subtitulos[x]] = dado
                except IndexError:
                    return jsonify({"message": "Erro ao recuperar campos de dado do usuário", "error": True}), 500
                x += 1
            # dados_json = dict(zip(subtitulos, dados))

            return jsonify({"dados": dicionario, "error": False}), 200

    except Exception:
        print("Erro em /usuarios/info")
        raise
    finally:
        cur.close()


@app.route("/usuarios/<int:tipo_logado>/<int:pagina>/<int:tipo_listar>", methods=["GET"])
def listar_usuarios(tipo_logado, pagina=1, tipo_listar=1):  # Se a página for 0, retornar o total de páginas disponíveis
    # Lista todos os usuários e suas informações conforme as permissões de quem está logado
    if tipo_logado > 2:
        verificacao = informar_verificacao(3)
        if verificacao:
            return verificacao
    else:
        verificacao = informar_verificacao(2)
        if verificacao:
            return verificacao

    tipo_listar = 3 if tipo_listar > 3 else tipo_listar
    tipo_listar = 1 if tipo_listar < 1 else tipo_listar
    cur = con.cursor()
    try:
        if pagina == 0:
            cur.execute("SELECT COUNT(ID_USUARIO) FROM USUARIOS WHERE TIPO = ?", (tipo_listar, ))
            qtd_paginas = cur.fetchone()
            qtd_paginas = qtd_paginas[0]
            # print(qtd_paginas, qtd_paginas/8, qtd_paginas % 8 != 0, qtd_paginas // 8 + 1)
            if qtd_paginas % 8 != 0:  # Se tem resto adiciona um
                qtd_paginas = (qtd_paginas // 8) + 1
            else:
                qtd_paginas = qtd_paginas / 8

            return jsonify({"paginas": int(qtd_paginas)})
        inicial = pagina * 8 - 7 if pagina == 1 else pagina * 8 - 7
        final = pagina * 8
        if tipo_listar == 3:
            if tipo_logado < 3:
                return jsonify({"message": "Você não tem permissão para ver esse tipo de usuário.", "error": True}), 401

        cur.execute(f"""SELECT ID_USUARIO, NOME, EMAIL, TELEFONE, ATIVO FROM USUARIOS 
                        WHERE TIPO = ? ORDER BY ID_USUARIO DESC ROWS {inicial} TO {final}""", (tipo_listar, ))
        usuarios = cur.fetchall()
        # [inicial - 1:final]
        return jsonify({"usuarios": usuarios, "error": False}), 200
    except Exception:
        print("Erro em /usuarios/admin/<int:pagina>/<int:tipo>")
        raise
    finally:
        cur.close()


@app.route("/usuarios/info/<int:id_usuario>/<int:tipo_logado>", methods=["GET"])
def trazer_campos_editar_outro(id_usuario, tipo_logado):
    if tipo_logado > 2:
        verificacao = informar_verificacao(3)
        if verificacao:
            return verificacao
    else:
        verificacao = informar_verificacao(2)
        if verificacao:
            return verificacao

    cur = con.cursor()
    try:
        cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
        resposta = cur.fetchone()
        subtitulos = []
        dicionario = {}
        if resposta:
            tipo = resposta[0]
            if tipo == 2:
                if tipo_logado < 3:
                    return jsonify({"message": "Você não tem permissão de ver os dados desse usuário",
                                    "error": True}), 401

            cur.execute("""SELECT NOME, ATIVO, CPF, EMAIL, TELEFONE
             FROM USUARIOS WHERE ID_USUARIO = ?""", (id_usuario,))
            subtitulos = ["nome", "ativo", "cpf", "email", "telefone"]
        else:
            return jsonify({"message": "Usuário não encontrado", "error": True}), 404

        dados = cur.fetchone()
        x = 0
        for dado in dados:
            try:
                dicionario[subtitulos[x]] = dado
            except IndexError:
                return jsonify({"message": "Erro ao recuperar campos de dado do usuário", "error": True}), 500
            x += 1
        # dados_json = dict(zip(subtitulos, dados))

        return jsonify({"dados": dicionario, "error": False}), 200
    except Exception:
        print("Erro em /usuarios/info/<int:id_usuario>/<int:tipo_logado>")
        raise
    finally:
        cur.close()


@app.route("/usuarios/<int:id_usuario>/editar/<int:tipo_logado>", methods=["PUT"])
def editar_outro_usuario(id_usuario, tipo_logado):
    if tipo_logado > 2:
        verificacao = informar_verificacao(3)
        if verificacao:
            return verificacao
    else:
        verificacao = informar_verificacao(2)
        if verificacao:
            return verificacao

    data = request.get_json()
    nome = data.get("nome")
    senha1 = data.get("senha")
    cpf = data.get("cpf")
    email = data.get("email")
    if email:
        email = email.lower()
    tel = data.get("telefone")

    # Verificações de comprimento e formatação de dados
    cpf1 = str(cpf) if cpf else None
    tel1 = str(tel) if tel else None

    if nome:
        if len(nome) > 895:
            return jsonify({"message": "Nome grande demais, o limite é 895 caracteres", "error": True}), 401
    if cpf:
        if len(cpf1) != 11:
            return jsonify({"message": "O CPF precisa ter 11 dígitos", "error": True}), 401
    if tel:
        if len(tel1) != 13:
            return jsonify({"message": """O telefone precisa ser enviado em 13 dígitos exemplo: +55 (18) 12345-1234 = 5518123451234""", "error": True}), 401
    if email:
        if '@' not in email:
            return jsonify({"message": "E-mail inválido", "error": True}), 401

    # Verificações de senha, se houver senha
    if senha1:
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
        # Verificações de duplicatas
        cur.execute("SELECT CPF FROM USUARIOS WHERE CPF = ? AND ID_USUARIO <> ?", (cpf1, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == cpf1:
                return jsonify({"message": "CPF já cadastrado", "error": True}), 401

        cur.execute("SELECT EMAIL FROM USUARIOS WHERE EMAIL = ? AND ID_USUARIO <> ?", (email, id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == email:
                return jsonify({"message": "Email já cadastrado", "error": True}), 401

        cur.execute("SELECT TELEFONE FROM USUARIOS WHERE TELEFONE = ? AND ID_USUARIO <> ?", (formatar_telefone(tel1), id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            if resposta[0] == formatar_telefone(tel1):
                return jsonify({"message": "Telefone já cadastrado", "error": True}), 401

        # Pegando valores padrões
        cur.execute("""SELECT NOME, SENHA, CPF, EMAIL, TELEFONE, TIPO FROM USUARIOS WHERE ID_USUARIO = ?""", (id_usuario,))
        resposta = cur.fetchone()
        if resposta:
            # Trocando os valores não recebidos pelos existentes no banco
            nome = resposta[0] if not nome else nome
            senha_hash = resposta[1]
            cpf1 = str(resposta[2]) if not cpf else cpf1
            email = resposta[3] if not email else email
            tel1 = str(resposta[4]) if not tel else tel1

        if senha1:
            senha_hash = generate_password_hash(senha1).decode('utf-8')

        cur.execute("""UPDATE USUARIOS SET NOME = ?, SENHA = ?, CPF = ?, EMAIL = ?, TELEFONE = ? 
         WHERE ID_USUARIO = ?""",
                    (nome, senha_hash, cpf1, email, formatar_telefone(tel1), id_usuario,))

        con.commit()

        return jsonify({"message": "Usuário editado com sucesso!", "error": "False"}), 200

    except Exception:
        print("Erro em /usuarios/<int:id_usuario>/editar/<int:tipo_logado>")
        raise
    finally:
        cur.close()


@app.route("/usuarios/<int:id_usuario>/alternar-ativo", methods=["GET"])
def alternar_ativo_de_usuario(id_usuario):

    cur = con.cursor()
    try:
        # Verificar o id_usuario
        cur.execute("SELECT TIPO, ATIVO FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario, ))
        resultado = cur.fetchone()
        if not resultado:
            return jsonify({"message": "Usuário não encontrado", "error": True}), 404
        if resultado[0] > 1:
            verificacao = informar_verificacao(3)
            if verificacao:
                return verificacao
            if resultado[0] == 3:
                return jsonify({"message": "Esse usuário não pode ser inativado"})
        else:
            verificacao = informar_verificacao(2)
            if verificacao:
                return verificacao

        if resultado[1]:  # Se ativo == True
            cur.execute("UPDATE USUARIOS SET ATIVO = FALSE WHERE ID_USUARIO = ?", (id_usuario, ))
            con.commit()
            return jsonify({"message": "Usuário inativado com sucesso!", "error": False})
        else:  # Se resultado != True
            cur.execute("UPDATE USUARIOS SET ATIVO = TRUE WHERE ID_USUARIO = ?", (id_usuario,))
            con.commit()
            return jsonify({"message": "Usuário reativado com sucesso!", "error": False})
    except Exception:
        print("erro em /usuarios/<int:id_usuario>/alternar-ativo")
        raise
    finally:
        cur.close()


@app.route("/produtos/cadastrar", methods=["POST"])
def cadastrar_produto():
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    data = request.get_json()
    nome = data.get("nome")
    cod_bar = data.get("codigo")
    qtd = data.get("qtd")
    preco = data.get("preco")

    if not all([nome, cod_bar, qtd, preco]):
        return jsonify({"message": "Todos os campos são obrigatórios."})

    cod_bar1 = str(cod_bar)

    preco = float(preco)
    if preco < 0 or preco > 99999999:
        return jsonify({"message": "Preço inválido"})
    if qtd < 0:
        return jsonify({"message": "Quantidade de estoque inválida"})
    if len(cod_bar1) != 13:
        return jsonify({"message": "Codigo de barras inválido"})

    cur = con.cursor()
    try:
        cur.execute("SELECT 1 FROM PRODUTOS WHERE CODIGO_BARRAS = ?", (cod_bar1, ))
        resposta = cur.fetchone()
        if resposta:
            return jsonify({"message": "Já existe um produto cadastrado com esse código de barras"}), 401

        cur.execute("INSERT INTO PRODUTOS (NOME, CODIGO_BARRAS, QUANTIDADE, PRECO) VALUES (?,?,?,?)",
                    (nome, cod_bar1, qtd, preco,))

        con.commit()

        return jsonify({"message": "Produto cadastrado com sucesso!"}), 200

    except Exception as e:
        print("erro ao cadastrar produto", e)
        raise
    finally:
        cur.close()


@app.route("/produtos/editar/<int:id_produto>", methods=["PUT"])
def editar_produto(id_produto):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    data = request.get_json()
    nome = data.get("nome")
    codigo = data.get("codigo")
    qtd = data.get("qtd")
    preco = data.get("preco")
    codigo = str(codigo) if codigo else None

    if codigo:
        if len(codigo) != 13:
            return jsonify({"message": """Código de barras inválido""", "error": True}), 401

    cur = con.cursor()
    try:
        # Verificações de duplicatas
        cur.execute("SELECT 1 FROM PRODUTOS WHERE CODIGO_BARRAS = ? AND ID_PRODUTO <> ?", (codigo, id_produto,))
        resposta = cur.fetchone()
        if resposta:
            return jsonify({"message": "Um outro produto já está usando esse código de barras", "error": True}), 401

        # Pegando valores padrões
        cur.execute("""SELECT NOME, CODIGO_BARRAS, QUANTIDADE, PRECO FROM PRODUTOS WHERE ID_PRODUTO = ?""", (id_produto,))
        resposta = cur.fetchone()
        if resposta:
            # Trocando os valores não recebidos pelos existentes no banco
            nome = resposta[0] if not nome else nome
            codigo = resposta[1] if not codigo else codigo
            qtd = resposta[2] if not qtd else qtd
            preco = resposta[3] if not preco else preco

        cur.execute("""UPDATE PRODUTOS SET NOME = ?, CODIGO_BARRAS = ?, QUANTIDADE = ?, PRECO = ? 
         WHERE ID_PRODUTO = ?""",
                    (nome, codigo, qtd, preco, id_produto, ))

        con.commit()

        return jsonify({"message": "Produto editado com sucesso!", "error": "False"}), 200

    except Exception as e:
        print("Erro ao editar produto", e)
        raise
    finally:
        cur.close()


@app.route("/produtos/excluir/<int:id_produto>", methods=["DELETE"])
def excluir_produto(id_produto):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    cur = con.cursor()
    try:
        cur.execute("SELECT 1 FROM PRODUTOS WHERE ID_PRODUTO = ?", (id_produto,))
        resposta = cur.fetchone()
        if not resposta:
            return jsonify({"message": "Produto não encontrado"}), 404

        cur.execute("DELETE FROM PRODUTOS WHERE ID_PRODUTO = ?", (id_produto,))
        con.commit()
        return jsonify({"message": "Produto excluído com sucesso!"}), 200
    except Exception as e:
        print("Erro ao excluir produto")
        raise
    finally:
        cur.close()


@app.route("/produtos/<int:pagina>", methods=["GET"])
def trazer_produtos(pagina):
    verificacao = informar_verificacao()
    if verificacao:
        return verificacao

    cur = con.cursor()
    try:
        if pagina == 0:
            cur.execute("SELECT COUNT(ID_PRODUTO) FROM PRODUTOS")
            qtd_paginas = cur.fetchone()
            qtd_paginas = qtd_paginas[0]
            # print(qtd_paginas, qtd_paginas/8, qtd_paginas % 8 != 0, qtd_paginas // 8 + 1)
            if qtd_paginas % 8 != 0:  # Se tem resto adiciona um
                qtd_paginas = (qtd_paginas // 8) + 1
            else:
                qtd_paginas = qtd_paginas / 8

            return jsonify({"paginas": int(qtd_paginas)})
        inicial = pagina * 8 - 7 if pagina == 1 else pagina * 8 - 7
        final = pagina * 8

        cur.execute(f"SELECT * FROM PRODUTOS ROWS {inicial} to {final}")
        produtos = cur.fetchall()
        return jsonify({"produtos": produtos})

    except Exception as e:
        print("erro ao listar produtos")
        raise
    finally:
        cur.close()


#@app.route("/produtos/<int:id_produto>")


@app.route("/movimentacoes/criar/<int:id_usuario>", methods=["POST"])
def criar_movimentacoes(id_usuario):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao
    data = request.get_json()
    ids_produtos = data.get("produtos")

    cur = con.cursor()
    try:
        # Verificar se o produto e o usuário existem
        cur.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario, ))
        resposta = cur.fetchone()
        if not resposta:
            return jsonify({"message": "Usuário não encontrado"}), 404

        estoques = {} # Estoque novo
        # estoques_banco = {}
        for id_prod in ids_produtos:
            cur.execute("SELECT QUANTIDADE FROM PRODUTOS WHERE ID_PRODUTO = ?", (id_prod, ))
            resposta = cur.fetchone()
            if not resposta:
                return jsonify({"message": f"Produto não encontrado (ID {id_prod})"}), 404
            else:
                if str(id_prod) in estoques:
                    estoques[str(id_prod)] -= 1
                else:
                    estoques[str(id_prod)] = resposta[0] - 1
                # estoques_banco[str(id_prod)] = resposta[0]

        cur.execute("INSERT INTO MOVIMENTACOES (ID_USUARIO) VALUES (?) RETURNING ID_MOVIMENTACAO",(id_usuario, ))
        id_mov = cur.fetchone()
        id_mov = id_mov[0]

        for id_prod, estoque in estoques.items():
            nova_qtd = estoque
            if nova_qtd < 0:
                return jsonify({"message": "Um dos produtos escolhidos possui estoque insuficiente"}), 401

            # Alterar o estoque de cada produto
            cur.execute("UPDATE PRODUTOS SET QUANTIDADE = ? WHERE ID_PRODUTO = ?", (nova_qtd, int(id_prod),))

        for id_prod in ids_produtos:
            # Adiciona cada ID_PRODUTO à movimentação por GRUPO_PRODUTOS
            cur.execute("INSERT INTO GRUPOS_PRODUTOS (ID_MOVIMENTACAO, ID_PRODUTO) VALUES (?,?)",
                        (id_mov, id_prod))

        con.commit()
        return jsonify({"message": "Movimentação registrada com sucesso!"})

    except Exception as e:
        print("Erro ao criar movimentação")
        raise
    finally:
        cur.close()

@app.route("/movimentacoes/<int:pagina>", methods=["GET"])
def trazer_movimentacoes(pagina):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    cur = con.cursor()
    try:
        if pagina == 0:
            cur.execute("SELECT COUNT(ID_MOVIMENTACAO) FROM MOVIMENTACOES")
            qtd_paginas = cur.fetchone()
            qtd_paginas = qtd_paginas[0]
            # print(qtd_paginas, qtd_paginas/8, qtd_paginas % 8 != 0, qtd_paginas // 8 + 1)
            if qtd_paginas % 8 != 0:  # Se tem resto adiciona um
                qtd_paginas = (qtd_paginas // 8) + 1
            else:
                qtd_paginas = qtd_paginas / 8

            return jsonify({"paginas": int(qtd_paginas)})
        inicial = pagina * 8 - 7 if pagina == 1 else pagina * 8 - 7
        final = pagina * 8

        cur.execute(f"""SELECT ID_MOVIMENTACAO, ID_USUARIO, DATA_MOVIMENTACAO FROM MOVIMENTACOES
        ORDER BY DATA_MOVIMENTACAO DESC
         ROWS {inicial} to {final}""")
        colunas = ["id_mob", "id_user", "data_mov"]
        linhas = cur.fetchall()

        dicionario = [dict(zip(colunas, linha)) for linha in linhas]

        return jsonify({"movimentacoes": dicionario})
    except Exception:
        print("Erro ao trazer movimentações")
        raise
    finally:
        cur.close()


@app.route("/movimentacoes/excluir/<int:id_movimentacao>", methods=["DELETE"])
def excluir_movimentacao(id_movimentacao):
    verificacao = informar_verificacao(2)
    if verificacao:
        return verificacao

    cur = con.cursor()
    try:
        cur.execute("SELECT 1 FROM MOVIMENTACOES WHERE ID_MOVIMENTACAO = ?", (id_movimentacao,))
        resposta = cur.fetchone()
        if not resposta:
            return jsonify({"message": "Movimentação não encontrada"}), 404

        cur.execute("DELETE FROM GRUPOS_PRODUTOS WHERE ID_MOVIMENTACAO = ?", (id_movimentacao, ))
        cur.execute("DELETE FROM MOVIMENTACOES WHERE ID_MOVIMENTACAO = ?", (id_movimentacao,))
        con.commit()

        return jsonify({"message": "Movimentação excluída com sucesso"}), 200

    except Exception:
        print("erro ao excluir movimentação")
    finally:
        cur.close()


#@app.route("/movimentacoes/editar/<int:id_usuario>", methods=["PUT"])
#def editar_movimentacao
