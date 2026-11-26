/*
 * Download protegido do instalador do Gerenciador de disparos.
 *
 * O instalador fica publicado cifrado (AES-256-GCM). A chave sai da senha
 * do gerenciador, do mesmo jeito que o gerenciador a confere:
 *   resumo = PBKDF2-SHA256(senha, sal, iteracoes)
 *   chave  = SHA-256("chatfast-download|" + resumo em hexadecimal)
 * Tudo acontece neste navegador: a senha nao vai para lugar nenhum.
 * Com a senha errada o arquivo nao abre (o verificador falha antes de
 * baixar os 45 MB).
 */
(function (raiz) {
  'use strict';

  const ROTULO = 'chatfast-download|';
  const MAGICA = 'CFD1';

  function hex(bytes) {
    return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
  }

  function deHex(texto) {
    const bytes = new Uint8Array(texto.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(texto.substr(i * 2, 2), 16);
    return bytes;
  }

  async function chaveDaSenha(cripto, senha, sal, iteracoes) {
    const base = await cripto.importKey('raw', new TextEncoder().encode(senha), 'PBKDF2', false, ['deriveBits']);
    const resumo = await cripto.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: deHex(sal), iterations: iteracoes }, base, 256);
    const material = await cripto.digest('SHA-256', new TextEncoder().encode(ROTULO + hex(resumo)));
    return cripto.importKey('raw', material, 'AES-GCM', false, ['decrypt']);
  }

  async function abrir(cripto, chave, bruto) {
    const dados = new Uint8Array(bruto);
    if (new TextDecoder().decode(dados.slice(0, 4)) !== MAGICA) throw new Error('formato');
    return cripto.decrypt({ name: 'AES-GCM', iv: dados.slice(4, 16) }, chave, dados.slice(16));
  }

  raiz.ChatFastDownload = { chaveDaSenha, abrir, hex };

  if (typeof document === 'undefined') return;   // usado nos testes (Node)

  /* ---------------------------------------------------------------- tela */

  const $ = (id) => document.getElementById(id);
  const cripto = crypto.subtle;
  let info = null;

  function situacao(texto, fracao) {
    $('andamento').hidden = false;
    $('situacao').textContent = texto;
    $('preenchido').style.width = Math.round((fracao || 0) * 100) + '%';
  }

  async function lerInfo() {
    const resposta = await fetch('versao.json?t=' + Date.now(), { cache: 'no-store' });
    if (!resposta.ok) throw new Error('Ainda não há instalador publicado.');
    return resposta.json();
  }

  async function baixarComProgresso(endereco) {
    const resposta = await fetch(endereco + '?v=' + encodeURIComponent(info.versao), { cache: 'no-store' });
    if (!resposta.ok || !resposta.body) throw new Error('Não foi possível baixar o instalador. Tente de novo.');

    const total = Number(resposta.headers.get('content-length')) || info.tamanho_cifrado || 0;
    const leitor = resposta.body.getReader();
    const partes = [];
    let recebido = 0;

    for (;;) {
      const { done, value } = await leitor.read();
      if (done) break;
      partes.push(value);
      recebido += value.length;
      situacao(`Baixando... ${Math.round(recebido / 1048576)} de ${Math.round(total / 1048576)} MB`, total ? recebido / total * 0.9 : 0.5);
    }

    const tudo = new Uint8Array(recebido);
    let posicao = 0;
    for (const parte of partes) {
      tudo.set(parte, posicao);
      posicao += parte.length;
    }
    return tudo.buffer;
  }

  function salvar(conteudo) {
    const link = document.createElement('a');
    link.href = URL.createObjectURL(new Blob([conteudo], { type: 'application/zip' }));
    link.download = 'Gerenciador de disparos.zip';
    document.body.appendChild(link);
    link.click();
    setTimeout(() => {
      URL.revokeObjectURL(link.href);
      link.remove();
    }, 4000);
  }

  $('formulario').addEventListener('submit', async (evento) => {
    evento.preventDefault();
    $('erro').textContent = '';
    $('baixar').disabled = true;

    try {
      info = info || (await lerInfo());
      situacao('Conferindo a senha...', 0.02);

      const chave = await chaveDaSenha(cripto, $('senha').value, info.sal, info.iteracoes);
      const verificador = await (await fetch('verificador.bin?v=' + encodeURIComponent(info.versao), { cache: 'no-store' })).arrayBuffer();

      try {
        await abrir(cripto, chave, verificador);
      } catch (e) {
        $('andamento').hidden = true;
        $('erro').textContent = 'Senha incorreta. Use a mesma senha do gerenciador de disparos.';
        $('senha').select();
        return;
      }

      const cifrado = await baixarComProgresso('instalador.bin');
      situacao('Abrindo o arquivo protegido...', 0.93);
      const aberto = await abrir(cripto, chave, cifrado);

      if (info.sha256 && hex(await cripto.digest('SHA-256', aberto)) !== info.sha256) {
        throw new Error('O arquivo chegou diferente do publicado. Tente de novo.');
      }

      salvar(aberto);
      situacao('Pronto! O instalador foi salvo em Downloads. Siga os passos abaixo.', 1);
      $('senha').value = '';
    } catch (erro) {
      $('andamento').hidden = true;
      $('erro').textContent = erro.message || 'Não foi possível baixar. Tente de novo.';
    } finally {
      $('baixar').disabled = false;
    }
  });

  lerInfo()
    .then((dados) => {
      info = dados;
      $('versao').textContent = `Versão ${dados.versao} · ${Math.round(dados.tamanho / 1048576)} MB · Windows 10 ou mais novo.`;
    })
    .catch(() => {});
})(typeof window !== 'undefined' ? window : globalThis);
