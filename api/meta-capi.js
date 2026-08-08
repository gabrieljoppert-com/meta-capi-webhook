/**
 * Webhook: Shopify "orders/paid" -> Meta Conversions API (evento Purchase)
 * ---------------------------------------------------------------------
 * Contexto: no checkout da Lívia Ribeiro, pedidos pagos via "Parcelamento"
 * ficam com status "pagamento pendente" até alguém marcar como pago
 * manualmente no admin da Shopify (depois da confirmação via Cielo).
 * O canal nativo Shopify->Meta só dispara o Purchase no momento do
 * checkout, e SÓ para pedidos que já nascem pagos (ex: PIX). Confirmado
 * por teste real: marcar um pedido como pago depois não gera o evento.
 *
 * Este webhook resolve isso: toda vez que um pedido é marcado como pago
 * (endpoint "orders/paid" da Shopify, dispara tanto na compra via PIX
 * quanto no "Marcar como pago" manual do Parcelamento), este script
 * envia o evento Purchase para a Meta via API de Conversões — cobrindo
 * o gap.
 *
 * IMPORTANTE — DUPLICAÇÃO EM PEDIDOS PIX:
 * "orders/paid" dispara para QUALQUER pedido que fica pago, inclusive PIX
 * — que JÁ é rastreado nativamente (pixel dispara na página de confirmação
 * do checkout). Confirmado via API: nesta loja só existem 2 gateways,
 * "PIX" e "Parcelamento" (payment_gateway_names). Por isso este webhook
 * IGNORA pedidos com gateway "PIX" (já cobertos pelo canal nativo) e só
 * envia para a Meta os que não passaram pela tela de confirmação da
 * Shopify — hoje, isso é "Parcelamento". Ver SKIP_GATEWAYS abaixo.
 *
 * DEPLOY (qualquer opção serve, é só uma function HTTP):
 *   - Vercel: crie um projeto, coloque este arquivo em /api/meta-capi.js,
 *     "vercel deploy". A URL fica algo como
 *     https://seu-projeto.vercel.app/api/meta-capi
 *   - Cloudflare Workers: adaptar para o formato de Workers (fetch handler)
 *   - Qualquer Node host com Express: app.post('/webhook', handler)
 *
 * CONFIGURAÇÃO NA SHOPIFY (depois de ter a URL pública):
 *   Admin > Configurações > Notificações > Webhooks > Criar webhook
 *   Evento: "Pedido pago" (orders/paid)
 *   Formato: JSON
 *   URL: <sua URL de deploy>
 *   Isso te dá também o "Signing secret" (SHOPIFY_WEBHOOK_SECRET abaixo).
 *
 * VARIÁVEIS DE AMBIENTE NECESSÁRIAS:
 *   META_PIXEL_ID              = 828033213432275   (já confirmado)
 *   META_CAPI_ACCESS_TOKEN     = gerar em Events Manager > Pixel > Configurações
 *                                 > API de Conversões > "Configurar integração
 *                                 direta" > "Gerar token de acesso"
 *   SHOPIFY_WEBHOOK_SECRET     = fornecido pela Shopify ao criar o webhook
 *                                 (usado para validar a assinatura HMAC)
 *   META_TEST_EVENT_CODE       = opcional, só para testar em
 *                                 Events Manager > Eventos de teste antes
 *                                 de ativar em produção (remover depois)
 *
 * IMPORTANTE (Vercel): para validar a assinatura HMAC da Shopify é
 * necessário o corpo RAW exato, byte a byte, tal como a Shopify o
 * assinou. A Vercel, por padrão, faz parse automático do JSON e não
 * expõe req.rawBody nas funções Node.js "puras" (sem framework) — por
 * isso desativamos o bodyParser via "config.api.bodyParser = false" e
 * lemos o corpo manualmente do stream, ANTES de qualquer JSON.parse.
 */

const crypto = require('crypto');

// ---- Config (via variáveis de ambiente) ----
const PIXEL_ID = process.env.META_PIXEL_ID;
const ACCESS_TOKEN = process.env.META_CAPI_ACCESS_TOKEN;
const WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;
const TEST_EVENT_CODE = process.env.META_TEST_EVENT_CODE; // opcional
const GRAPH_VERSION = 'v21.0';

// Gateways já rastreados pelo canal nativo Shopify->Meta (pixel dispara na
// página de confirmação do checkout) — pedidos com esses gateways são
// ignorados aqui para não duplicar o Purchase na Meta.
const SKIP_GATEWAYS = ['pix'];

// Desativa o parse automático de body da Vercel — precisamos do raw exato
// para validar a assinatura HMAC da Shopify corretamente.
module.exports.config = {
  api: {
    bodyParser: false,
  },
};

// Lê o corpo cru da requisição a partir do stream, antes de qualquer parse.
function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sha256(value) {
  if (!value) return undefined;
  return crypto
    .createHash('sha256')
    .update(String(value).trim().toLowerCase())
    .digest('hex');
}

// Normaliza telefone para E.164 antes de hashear (Meta exige isso para bater)
function normalizePhone(raw, defaultCountryCode = '55') {
  if (!raw) return undefined;
  const digits = String(raw).replace(/\D/g, '');
  if (!digits) return undefined;
  // Se já vier com código do país (ex: 55...), usa direto; senão prefixa.
  const withCountry = digits.startsWith(defaultCountryCode)
    ? digits
    : `${defaultCountryCode}${digits}`;
  return withCountry;
}

function verifyShopifyHmac(rawBodyBuffer, hmacHeader) {
  if (!WEBHOOK_SECRET) return true; // sem secret configurado, pula validação (não recomendado em produção)
  if (!hmacHeader) return false;
  const digest = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBodyBuffer)
    .digest('base64');
  const digestBuf = Buffer.from(digest);
  const headerBuf = Buffer.from(hmacHeader);
  if (digestBuf.length !== headerBuf.length) return false;
  return crypto.timingSafeEqual(digestBuf, headerBuf);
}

function buildPurchaseEvent(order) {
  const email = order?.email || order?.contact_email;
  const phone = order?.phone || order?.shipping_address?.phone || order?.customer?.phone;
  const firstName = order?.customer?.first_name || order?.shipping_address?.first_name;
  const lastName = order?.customer?.last_name || order?.shipping_address?.last_name;
  const city = order?.shipping_address?.city;
  const state = order?.shipping_address?.province_code;
  const zip = order?.shipping_address?.zip;
  const country = order?.shipping_address?.country_code;

  // external_id ajuda a deduplicar/casar com outros eventos do mesmo cliente
  const externalId = order?.customer?.id ? String(order.customer.id) : undefined;

  const userData = {
    em: sha256(email),
    ph: sha256(normalizePhone(phone)),
    fn: sha256(firstName),
    ln: sha256(lastName),
    ct: sha256(city),
    st: sha256(state),
    zp: sha256(zip),
    country: sha256(country),
    external_id: sha256(externalId),
  };

  // fbc/fbp: capturados no tema (layout/theme.liquid) e propagados como
  // note_attributes do pedido — ver nota no final do arquivo.
  const fbp = order?.note_attributes?.find((a) => a.name === '_fbp')?.value;
  const fbc = order?.note_attributes?.find((a) => a.name === '_fbc')?.value;
  if (fbp) userData.fbp = fbp;
  if (fbc) userData.fbc = fbc;

  const contents = (order?.line_items || []).map((item) => ({
    id: String(item.product_id || item.variant_id || item.sku || ''),
    quantity: item.quantity,
    item_price: Number(item.price),
  }));

  const event = {
    event_name: 'Purchase',
    event_time: Math.floor(new Date(order.processed_at || order.created_at).getTime() / 1000),
    action_source: 'website',
    event_source_url: order?.order_status_url || 'https://liviaribeiro.com/',
    user_data: userData,
    custom_data: {
      currency: order?.currency || 'BRL',
      value: Number(order?.total_price || order?.current_total_price || 0),
      contents,
      content_type: 'product',
      order_id: String(order?.id || order?.order_number || ''),
    },
    // Evita duplicar caso o mesmo pedido gere dois webhooks (ex: paid + edited)
    event_id: `shopify_order_paid_${order?.id}`,
  };

  return event;
}

async function sendToMetaCapi(event) {
  const body = {
    data: [event],
  };
  if (TEST_EVENT_CODE) {
    body.test_event_code = TEST_EVENT_CODE;
  }

  const url = `https://graph.facebook.com/${GRAPH_VERSION}/${PIXEL_ID}/events?access_token=${ACCESS_TOKEN}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  const json = await res.json();
  if (!res.ok) {
    throw new Error(`Meta CAPI error: ${JSON.stringify(json)}`);
  }
  return json;
}

// ---- Handler HTTP (formato Vercel/Node genérico) ----
module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.status(405).send('Method not allowed');
    return;
  }

  try {
    // Corpo RAW exato (bodyParser desativado acima via module.exports.config),
    // necessário para validar o HMAC corretamente.
    const rawBodyBuffer = await getRawBody(req);
    const hmacHeader = req.headers['x-shopify-hmac-sha256'];

    if (!verifyShopifyHmac(rawBodyBuffer, hmacHeader)) {
      res.status(401).send('Assinatura inválida');
      return;
    }

    const order = JSON.parse(rawBodyBuffer.toString('utf8'));

    // Só processa se o pedido de fato está pago (financial_status == paid)
    if (order.financial_status !== 'paid') {
      res.status(200).send('Ignorado: pedido não está pago');
      return;
    }

    // Evita duplicar Purchase para gateways já cobertos pelo canal nativo
    // Shopify->Meta (ex: PIX). Ver nota no topo do arquivo.
    const gateways = (order.payment_gateway_names || []).map((g) => String(g).toLowerCase());
    if (gateways.some((g) => SKIP_GATEWAYS.includes(g))) {
      res.status(200).send('Ignorado: gateway já rastreado pelo canal nativo (' + gateways.join(', ') + ')');
      return;
    }

    const event = buildPurchaseEvent(order);
    const result = await sendToMetaCapi(event);

    console.log('Purchase enviado para Meta CAPI:', order.id, result);
    res.status(200).json({ ok: true, result });
  } catch (err) {
    console.error('Erro ao processar webhook:', err);
    res.status(500).json({ ok: false, error: err.message });
  }
};

/**
 * CAPTURA DE _fbp/_fbc: implementada em 08/08/2026 via script em
 * layout/theme.liquid, que salva os cookies _fbp/_fbc como atributos do
 * carrinho (propagam para note_attributes do pedido automaticamente).
 * Esta função já lê esses valores acima (user_data.fbp / user_data.fbc).
 *
 * TESTE ANTES DE ATIVAR EM PRODUÇÃO:
 * 1. Gere um Test Event Code em Events Manager > Pixel > Eventos de teste.
 * 2. Configure META_TEST_EVENT_CODE temporariamente.
 * 3. Marque um pedido de teste como pago e confira se o evento aparece
 *    na aba "Eventos de teste" do Events Manager, com os campos certos.
 * 4. Remova META_TEST_EVENT_CODE antes de ir para produção.
 */
